%% Common Test coverage for distribution over the encrypted carrier.
-module(bouncer_dist_SUITE).
-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").

-export([all/0, init_per_suite/1, end_per_suite/1,
         init_per_testcase/2, end_per_testcase/2]).
-export([distribution_roundtrip/1, large_transfer_and_full_duplex/1,
         unauthorized_and_name_binding/1, supported_suites/1, rekey/1,
         idle_disconnect_reconnect_and_revocation/1, max_pending/1,
         wrong_distribution_protocol/1, logs_do_not_contain_secret_key/1,
         config_restart/1, isolated_settings/1,
         invalid_settings_start/1, no_key_start/1,
         get_value/1, captured_logs/0, ct_data_owner/1]).
-export([echo_loop/0, echo_sender/3, send_many/4,
         echo_sender_generated/3,
         watch_node/2, kill_dist_socket/1,
         adding_handler/1, removing_handler/1, log/2]).

all() ->
    [distribution_roundtrip, large_transfer_and_full_duplex,
     unauthorized_and_name_binding, supported_suites, rekey,
     idle_disconnect_reconnect_and_revocation, max_pending,
     wrong_distribution_protocol, logs_do_not_contain_secret_key,
     config_restart, isolated_settings,
     invalid_settings_start, no_key_start].

init_per_suite(Config) ->
    _ = os:cmd("epmd -daemon"),
    Root = temp_dir("bouncer_dist_suite"),
    ok = filelib:ensure_dir(filename:join(Root, "marker")),
    [{suite_root, Root} | Config].

end_per_suite(Config) ->
    file:del_dir_r(?config(suite_root, Config)),
    ok.

init_per_testcase(Case, Config) ->
    Root = temp_dir("bouncer_dist_" ++ atom_to_list(Case)),
    InitiatorOpts = case Case of
                        rekey -> [{"rekey_after", "frames:50"}];
                        isolated_settings ->
                            [{"suite", "chachapoly_blake2b"},
                             {"accept_suites",
                              "chachapoly_blake2b,aesgcm_sha256,aesgcm_sha512,aesgcm_blake2b"}];
                        _ -> []
                    end,
    ResponderOpts = case Case of
                        max_pending -> [{"max_pending", "2"}];
                        rekey -> [{"rekey_after", "frames:50"}];
                        isolated_settings ->
                            [{"suite", "aesgcm_sha256"},
                             {"accept_suites",
                              "chachapoly_blake2b,aesgcm_sha256,aesgcm_sha512,aesgcm_blake2b"}];
                        _ -> []
                    end,
    {PeerA, NodeA, NameA, DirA, AuthA, KeyA} =
        start_node(Root, "a", InitiatorOpts),
    {PeerB, NodeB, NameB, DirB, AuthB, KeyB} =
        start_node(Root, "b", ResponderOpts),
    AuthFileA = authorize(NameA, KeyA, AuthB),
    AuthFileB = authorize(NameB, KeyB, AuthA),
    ok = install_log_capture(PeerA),
    ok = install_log_capture(PeerB),
    [{case_root, Root}, {peer_a, PeerA}, {node_a, NodeA}, {name_a, NameA},
     {dir_a, DirA}, {auth_a, AuthA}, {key_a, KeyA},
     {peer_b, PeerB}, {node_b, NodeB}, {name_b, NameB},
     {dir_b, DirB}, {auth_b, AuthB}, {key_b, KeyB},
     {auth_file_a, AuthFileA}, {auth_file_b, AuthFileB} | Config].

end_per_testcase(_Case, Config) ->
    stop_peer(?config(peer_a, Config)),
    stop_peer(?config(peer_b, Config)),
    file:del_dir_r(?config(case_root, Config)),
    ok.

distribution_roundtrip(Config) ->
    PeerA = ?config(peer_a, Config),
    PeerB = ?config(peer_b, Config),
    NodeA = ?config(node_a, Config),
    NodeB = ?config(node_b, Config),
    ?assertEqual(pong, peer:call(PeerA, net_adm, ping, [NodeB])),
    ?assertEqual(<<"roundtrip">>,
                 peer:call(PeerA, rpc, call,
                           [NodeB, erlang, list_to_binary, ["roundtrip"]])),
    ?assert(lists:member(NodeB, peer:call(PeerA, erlang, nodes, []))),
    ?assert(lists:member(NodeA, peer:call(PeerB, erlang, nodes, []))),
    setup_echo(PeerA),
    setup_echo(PeerB),
    Ref = make_ref(),
    Payload = crypto:strong_rand_bytes(64 * 1024),
    _ = peer:call(PeerA, erlang, spawn,
                  [?MODULE, echo_sender, [{bouncer_echo, NodeB}, Ref, Payload]]),
    ?assertEqual({byte_size(Payload), crypto:hash(sha256, Payload)},
                 await_result(PeerA, {result, Ref}, 10000)),
    ok.

large_transfer_and_full_duplex(Config) ->
    PeerA = ?config(peer_a, Config),
    PeerB = ?config(peer_b, Config),
    NodeA = ?config(node_a, Config),
    NodeB = ?config(node_b, Config),
    ?assertEqual(pong, peer:call(PeerA, net_adm, ping, [NodeB])),
    setup_echo(PeerA),
    setup_echo(PeerB),
    lists:foreach(
      fun(Size) ->
              Ref = make_ref(),
              _ = peer:call(PeerA, erlang, spawn,
                            [?MODULE, echo_sender_generated,
                             [{bouncer_echo, NodeB}, Ref, Size]]),
              Expected = await_result(PeerA, {expected, Ref}, 60000),
              ?assertEqual({Size, Expected},
                           await_result(PeerA, {result, Ref}, 60000))
      end, [5 * 1024 * 1024]),
    BigRef = make_ref(),
    Start = erlang:monotonic_time(millisecond),
    _ = peer:call(PeerA, erlang, spawn,
                  [?MODULE, echo_sender_generated,
                   [{bouncer_echo, NodeB}, BigRef, 50 * 1024 * 1024]]),
    SmallRef = make_ref(),
    Small = <<"reverse-direction-during-large-transfer">>,
    _ = peer:call(PeerB, erlang, spawn,
                  [?MODULE, echo_sender, [{bouncer_echo, NodeA}, SmallRef, Small]]),
    ?assertEqual({byte_size(Small), crypto:hash(sha256, Small)},
                 await_result(PeerB, {result, SmallRef}, 30000)),
    BigHash = await_result(PeerA, {expected, BigRef}, 120000),
    ?assertEqual({50 * 1024 * 1024, BigHash},
                 await_result(PeerA, {result, BigRef}, 120000)),
    ct:pal("50 MB full-duplex transfer and small reverse message latency: ~p ms",
           [erlang:monotonic_time(millisecond) - Start]),
    ok.

unauthorized_and_name_binding(Config) ->
    PeerA = ?config(peer_a, Config),
    NodeA = ?config(node_a, Config),
    Root = ?config(case_root, Config),
    {PeerC, NodeC, NameC, _DirC, AuthC, KeyC} =
        start_node(Root, "untrusted", []),
    ok = install_log_capture(PeerC),
    {ok, TempAuthorization} =
        bouncer_keys:add_peer(NameC, bouncer_keys:public(KeyC),
                              #{authorized_dirs => ?config(auth_a, Config),
                                node_name => ?config(name_a, Config)}),
    ?assertEqual(pang, peer:call(PeerA, net_adm, ping, [NodeC])),
    ?assert(log_contains(PeerC, "Add to the authorized directory")),
    ?assert(log_contains(PeerA, "probably not authorized there")),
    ok = file:delete(TempAuthorization),
    {ok, _} = bouncer_keys:add_peer(?config(name_a, Config),
                                    bouncer_keys:public(?config(key_a, Config)),
                                    #{authorized_dirs => AuthC,
                                      node_name => NameC}),
    ?assertEqual(pang, peer:call(PeerC, net_adm, ping, [NodeA])),
    ?assert(log_contains(PeerA, "Add to the authorized directory")),
    stop_peer(PeerC),

    WrongName = <<"not-the-node@127.0.0.1">>,
    PeerB = ?config(peer_b, Config),
    AuthB = ?config(auth_b, Config),
    KeyA = ?config(key_a, Config),
    ok = file:delete(?config(auth_file_a, Config)),
    {ok, _} = bouncer_keys:add_peer(WrongName, bouncer_keys:public(KeyA),
                                    #{authorized_dirs => AuthB,
                                      node_name => ?config(name_b, Config)}),
    ?assertEqual(pang, peer:call(PeerA, net_adm, ping,
                                 [?config(node_b, Config)])),
    ?assert(log_contains(PeerB, "peer authorization failed")),
    ok.

supported_suites(Config) ->
    Root = ?config(case_root, Config),
    Suites = ["chachapoly_blake2b", "aesgcm_sha512", "aesgcm_sha256",
              "aesgcm_blake2b"],
    lists:foreach(
      fun(Suite) ->
              Pair = start_pair(Root, "suite_" ++ Suite,
                                [{"suite", Suite}],
                                [{"accept_suites",
                                  "chachapoly_blake2b,aesgcm_sha512,aesgcm_sha256,aesgcm_blake2b"}]),
              {PeerA, _NodeA, _PeerB, NodeB} = Pair,
              ?assertEqual(pong, peer:call(PeerA, net_adm, ping, [NodeB])),
              stop_pair(Pair)
      end, Suites),
    DefaultOnly = start_pair(Root, "suite_reject",
                             [{"suite", "chachapoly_blake2b"}], []),
    {PeerA1, _NodeA1, _PeerB1, NodeB1} = DefaultOnly,
    ?assertEqual(pang, peer:call(PeerA1, net_adm, ping, [NodeB1])),
    stop_pair(DefaultOnly),
    ok.

rekey(Config) ->
    PeerA = ?config(peer_a, Config),
    PeerB = ?config(peer_b, Config),
    NodeB = ?config(node_b, Config),
    ?assertEqual(pong, peer:call(PeerA, net_adm, ping, [NodeB])),
    setup_echo(PeerA),
    setup_echo(PeerB),
    Ref = make_ref(),
    _ = peer:call(PeerA, erlang, spawn,
                  [?MODULE, send_many,
                   [{bouncer_echo, NodeB}, Ref, 10000, 20 * 1024 * 1024]]),
    ?assertEqual(ok, await_result(PeerB, {batch, Ref}, 120000)),
    ?assertEqual(4, await_result(PeerB, {batch, Ref, 10000}, 120000)),
    LargeHash = await_result(PeerA, {expected, Ref}, 120000),
    ?assertEqual({20 * 1024 * 1024, LargeHash},
                 await_result(PeerB, {large, Ref}, 120000)),
    ok.

idle_disconnect_reconnect_and_revocation(Config) ->
    PeerA = ?config(peer_a, Config),
    PeerB = ?config(peer_b, Config),
    NodeB = ?config(node_b, Config),
    ?assertEqual(pong, peer:call(PeerA, net_adm, ping, [NodeB])),
    timer:sleep(3 * 8 * 1000),
    ?assertEqual(pong, peer:call(PeerA, net_adm, ping, [NodeB])),

    NodeA = ?config(node_a, Config),
    SocketDownRef = make_ref(),
    _ = peer:call(PeerB, erlang, spawn,
                  [?MODULE, watch_node, [NodeA, SocketDownRef]]),
    ?assertEqual(ok, peer:call(PeerA, ?MODULE, kill_dist_socket,
                               [node_port(NodeB)])),
    ?assertEqual(ok, await_result(PeerB, {nodedown, SocketDownRef}, 10000)),
    ?assertEqual(pong, peer:call(PeerA, net_adm, ping, [NodeB])),

    RevocationRef = make_ref(),
    _ = peer:call(PeerB, erlang, spawn,
                  [?MODULE, watch_node, [NodeA, RevocationRef]]),
    AuthFile = ?config(auth_file_b, Config),
    ok = file:delete(AuthFile),
    %% Authorization is checked on new handshakes, not on live connections.
    ?assertEqual(pong, peer:call(PeerA, net_adm, ping, [NodeB])),
    ?assertEqual(true, peer:call(PeerB, erlang, disconnect_node, [NodeA])),
    ?assertEqual(ok, await_result(PeerB, {nodedown, RevocationRef}, 10000)),
    ?assertEqual(pang, peer:call(PeerB, net_adm, ping, [NodeA])),
    {ok, _} = bouncer_keys:add_peer(?config(name_b, Config),
                                    bouncer_keys:public(?config(key_b, Config)),
                                    #{authorized_dirs => ?config(auth_a, Config),
                                      node_name => ?config(name_a, Config)}),
    ?assertEqual(pong, peer:call(PeerB, net_adm, ping, [NodeA])),
    ok.

max_pending(Config) ->
    PeerA = ?config(peer_a, Config),
    NodeB = ?config(node_b, Config),
    NameB = ?config(name_b, Config),
    [ShortName | _] = binary:split(NameB, <<"@">>),
    {port, Port, _Version} =
        erl_epmd:port_please(binary_to_list(ShortName), {127, 0, 0, 1}),
    {ok, S1} = gen_tcp:connect({127, 0, 0, 1}, Port,
                              [binary, {active, false}], 3000),
    {ok, S2} = gen_tcp:connect({127, 0, 0, 1}, Port,
                              [binary, {active, false}], 3000),
    timer:sleep(250),
    {ok, S3} = gen_tcp:connect({127, 0, 0, 1}, Port,
                              [binary, {active, false}], 3000),
    ?assertEqual({error, closed}, gen_tcp:recv(S3, 0, 3000)),
    gen_tcp:close(S1),
    gen_tcp:close(S2),
    ?assertEqual(pong, peer:call(PeerA, net_adm, ping, [NodeB])),
    ok.

wrong_distribution_protocol(Config) ->
    Root = ?config(case_root, Config),
    {PeerPlain, _NodePlain} = start_plain_node(Root),
    ?assertEqual(pang,
                 peer:call(PeerPlain, net_adm, ping, [?config(node_b, Config)])),
    ?assertEqual(?config(node_b, Config),
                 peer:call(?config(peer_b, Config), erlang, node, [])),
    stop_peer(PeerPlain),
    ok.

logs_do_not_contain_secret_key(Config) ->
    ?assertEqual(pong, peer:call(?config(peer_a, Config), net_adm, ping,
                                 [?config(node_b, Config)])),
    lists:foreach(
      fun({Peer, Key}) ->
              Events = peer:call(Peer, ?MODULE, captured_logs, []),
              Encoded = term_to_binary(Events),
              Secret = bouncer_keys:secret(Key),
              ?assertEqual(nomatch, binary:match(Encoded, Secret)),
              ?assertEqual(nomatch,
                           binary:match(Encoded, base64:encode(Secret))),
              PersistentTerms = peer:call(Peer, persistent_term, get, []),
              PersistentKeys = [Key0 || {Key0, _Value} <- PersistentTerms],
              ?assertEqual([], [Key0 || Key0 <- PersistentKeys,
                                        bouncer_key(Key0)]),
              PersistentData = term_to_binary(PersistentTerms),
              ?assertEqual(nomatch, binary:match(PersistentData, Secret)),
              ?assertEqual(nomatch,
                           binary:match(PersistentData, base64:encode(Secret))),
              ?assertEqual(nomatch,
                           binary:match(PersistentData,
                                        bouncer_keys:public(Key))),
              ?assertEqual(nomatch,
                           binary:match(PersistentData,
                                        bouncer_keys:fingerprint(Key)))
      end, [{?config(peer_a, Config), ?config(key_a, Config)},
            {?config(peer_b, Config), ?config(key_b, Config)}]),
    ok.

config_restart(Config) ->
    PeerA = ?config(peer_a, Config),
    NodeB = ?config(node_b, Config),
    {ok, OldSettings} =
        peer:call(PeerA, bouncer_dist_config, connection_settings, []),
    OldGeneration = maps:get(config_generation, OldSettings),
    OldPid = peer:call(PeerA, erlang, whereis, [bouncer_dist_config]),
    ?assert(is_pid(OldPid)),
    _ = peer:call(PeerA, erlang, exit, [OldPid, kill]),
    NewPid = await_config_restart(PeerA, OldPid,
                                  erlang:monotonic_time(millisecond) + 10000),
    ?assert(is_pid(NewPid)),
    ?assertNotEqual(OldPid, NewPid),
    {ok, NewSettings} =
        peer:call(PeerA, bouncer_dist_config, connection_settings, []),
    ?assertNotEqual(OldGeneration, maps:get(config_generation, NewSettings)),
    ?assertEqual({error, stale_configuration},
                 peer:call(PeerA, bouncer_dist_config, key_info,
                           [OldGeneration])),
    _ = peer:call(PeerA, erlang, disconnect_node, [NodeB]),
    ?assertEqual(pong, peer:call(PeerA, net_adm, ping, [NodeB], 30000)),
    ok.

isolated_settings(Config) ->
    PeerA = ?config(peer_a, Config),
    PeerB = ?config(peer_b, Config),
    NodeA = ?config(node_a, Config),
    NodeB = ?config(node_b, Config),
    {ok, SuiteA} = peer:call(PeerA, bouncer_dist_config, get, [suite]),
    {ok, SuiteB} = peer:call(PeerB, bouncer_dist_config, get, [suite]),
    {ok, DirA} = peer:call(PeerA, bouncer_dist_config, get, [dir]),
    {ok, DirB} = peer:call(PeerB, bouncer_dist_config, get, [dir]),
    {ok, SettingsA} =
        peer:call(PeerA, bouncer_dist_config, connection_settings, []),
    ?assertEqual([],
                 peer:call(PeerA, ets, lookup,
                           [bouncer_dist_config, connection_settings])),
    ?assertEqual(atom_to_binary(NodeA, utf8), maps:get(node_name, SettingsA)),
    ?assertEqual(SuiteA, maps:get(suite, maps:get(hs_opts, SettingsA))),
    SendTimeout = maps:get(send_timeout_ms, SettingsA),
    try
        true = peer:call(PeerA, ets, insert,
                         [bouncer_dist_config, {send_timeout_ms, 1234}]),
        {ok, ChangedSettings} =
            peer:call(PeerA, bouncer_dist_config, connection_settings, []),
        ?assertEqual(1234, maps:get(send_timeout_ms, ChangedSettings)),
        ?assertEqual(1234, maps:get(send_timeout_ms,
                                    maps:get(hs_opts, ChangedSettings)))
    after
        true = peer:call(PeerA, ets, insert,
                         [bouncer_dist_config,
                          {send_timeout_ms, SendTimeout}])
    end,
    ?assertMatch({ok, _},
                 peer:call(PeerA, bouncer_dist_config, key_info,
                           [maps:get(config_generation, SettingsA)])),
    ?assertEqual({error, not_ready},
                 peer:call(PeerA, bouncer_dist_config, get, [settings])),
    ?assertEqual(chachapoly_blake2b, SuiteA),
    ?assertEqual(aesgcm_sha256, SuiteB),
    ?assertNotEqual(DirA, DirB),
    ?assertEqual(pong, peer:call(PeerA, net_adm, ping, [NodeB], 30000)),
    ?assertEqual(pong, peer:call(PeerB, net_adm, ping, [NodeA], 30000)),
    ok.

invalid_settings_start(Config) ->
    Root = ?config(case_root, Config),
    Result = start_bouncer_with_args(
               Root, "invalid_suite",
               ["-bouncer", "suite", "foo",
                "-bouncer", "dir", filename:join(Root, "invalid_suite_dir")]),
    assert_startup_failure_contains(Result, "suite"),
    assert_startup_failure_contains(Result, "chachapoly_blake2b").

no_key_start(Config) ->
    Root = ?config(case_root, Config),
    Dir = filename:join(Root, "no_key_dir"),
    ok = filelib:ensure_dir(filename:join(Dir, "marker")),
    Result = start_bouncer_with_args(
               Root, "no_key",
               ["-bouncer", "dir", Dir,
                "-bouncer", "generate", "false"]),
    assert_startup_failure_contains(Result, "no_key").

start_bouncer_with_args(_Root, Suffix, ExtraArgs) ->
    Name = list_to_atom("bouncer_start_" ++ Suffix ++ "_" ++
                        integer_to_list(erlang:unique_integer([positive]))),
    Erl = os:find_executable("erl"),
    Args = ["-noshell", "-noinput", "+S", "2:2", "-proto_dist", "bouncer",
            "-name", atom_to_list(Name) ++ "@127.0.0.1"] ++
        ExtraArgs ++ ["-pa" | code:get_path()],
    Port = open_port({spawn_executable, Erl},
                     [binary, exit_status, stderr_to_stdout, {args, Args}]),
    collect_startup_output(Port, <<>>).

assert_startup_failure_contains(Failure, Text) ->
    {Status, Output} = Failure,
    ?assert(Status =/= 0),
    ?assertNotEqual(nomatch, binary:match(Output, list_to_binary(Text))).

collect_startup_output(Port, Acc) ->
    receive
        {Port, {data, Data}} ->
            collect_startup_output(Port, <<Acc/binary, Data/binary>>);
        {Port, {exit_status, Status}} ->
            {Status, Acc}
    after 20000 ->
        _ = port_close(Port),
        ct:fail(distribution_startup_did_not_exit)
    end.

await_config_restart(Peer, OldPid, Deadline) ->
    case peer:call(Peer, erlang, whereis, [bouncer_dist_config]) of
        Pid when is_pid(Pid), Pid =/= OldPid ->
            Pid;
        _ ->
            case erlang:monotonic_time(millisecond) < Deadline of
                true ->
                    timer:sleep(25),
                    await_config_restart(Peer, OldPid, Deadline);
                false ->
                    ct:fail(config_process_did_not_restart)
            end
    end.

get_value(Key) ->
    case ets:lookup(bouncer_dist_ct_data, {value, Key}) of
        [{{value, Key}, Value}] -> Value;
        [] -> undefined
    end.

captured_logs() ->
    [Event || {{log, _Id}, Event} <- ets:tab2list(bouncer_dist_ct_data)].

bouncer_key(bouncer) -> true;
bouncer_key(Key) when is_atom(Key) ->
    lists:prefix("bouncer", atom_to_list(Key));
bouncer_key(<<"bouncer", _/binary>>) ->
    true;
bouncer_key(Key) when is_tuple(Key), tuple_size(Key) > 0 ->
    bouncer_key(element(1, Key));
bouncer_key(_) ->
    false.

setup_echo(Peer) ->
    Pid = peer:call(Peer, erlang, spawn, [?MODULE, echo_loop, []]),
    true = peer:call(Peer, erlang, register, [bouncer_echo, Pid]),
    ok.

echo_loop() ->
    receive
        {echo, Ref, From, Payload} ->
            Size = byte_size(Payload),
            Hash = crypto:hash(sha256, Payload),
            put_value({result, Ref}, {Size, Hash}),
            From ! {Ref, Size, Hash},
            echo_loop();
        {batch, Ref, Seq, Payload} ->
            case Seq of
                10000 ->
                    put_value({batch, Ref, Seq}, byte_size(Payload)),
                    put_value({batch, Ref}, ok);
                _ -> ok
            end,
            echo_loop();
        {large, Ref, Payload} ->
            put_value({large, Ref},
                      {byte_size(Payload), crypto:hash(sha256, Payload)}),
            echo_loop();
        stop ->
            ok
    end.

echo_sender(Destination, Ref, Payload) ->
    Destination ! {echo, Ref, self(), Payload},
    receive
        {Ref, Size, Hash} ->
            put_value({result, Ref}, {Size, Hash})
    after 120000 ->
        exit(echo_timeout)
    end.

echo_sender_generated(Destination, Ref, Size) ->
    Payload = crypto:strong_rand_bytes(Size),
    put_value({expected, Ref}, crypto:hash(sha256, Payload)),
    echo_sender(Destination, Ref, Payload).

send_many(Destination, Ref, Count, LargeSize) ->
    lists:foreach(fun(Seq) -> Destination ! {batch, Ref, Seq, <<Seq:32>>} end,
                  lists:seq(1, Count)),
    Large = crypto:strong_rand_bytes(LargeSize),
    put_value({expected, Ref}, crypto:hash(sha256, Large)),
    Destination ! {large, Ref, Large}.

watch_node(Node, Ref) ->
    true = erlang:monitor_node(Node, true),
    receive
        {nodedown, Node} ->
            put_value({nodedown, Ref}, ok)
    after 30000 ->
        exit(nodedown_timeout)
    end.

kill_dist_socket(RemotePort) ->
    Sockets = [Socket || Socket <- erlang:ports(),
                         socket_peer_port(Socket) =:= RemotePort],
    case Sockets of
        [Socket] ->
            gen_tcp:close(Socket);
        _ ->
            {error, {expected_one_distribution_socket, length(Sockets)}}
    end.

socket_peer_port(Socket) ->
    try inet:peername(Socket) of
        {ok, {{127, 0, 0, 1}, Port}} -> Port;
        _ -> undefined
    catch
        _:_ -> undefined
    end.

node_port(Node) ->
    [ShortName | _] = string:split(atom_to_list(Node), "@", all),
    {port, Port, _Version} = erl_epmd:port_please(ShortName, {127, 0, 0, 1}),
    Port.

await_result(Peer, Key, Timeout) ->
    Deadline = erlang:monotonic_time(millisecond) + Timeout,
    await_result_loop(Peer, Key, Deadline).

await_result_loop(Peer, Key, Deadline) ->
    case peer:call(Peer, ?MODULE, get_value, [Key]) of
        undefined ->
            case erlang:monotonic_time(millisecond) < Deadline of
                true ->
                    timer:sleep(25),
                    await_result_loop(Peer, Key, Deadline);
                false ->
                    ct:fail({timeout_waiting_for, Key})
            end;
        Value -> Value
    end.

start_pair(Root, Tag, OptA, OptB) ->
    PairRoot = filename:join(Root, Tag),
    ok = filelib:ensure_dir(filename:join(PairRoot, "marker")),
    {PeerA, NodeA, NameA, _DirA, AuthA, KeyA} = start_node(PairRoot, "a", OptA),
    {PeerB, NodeB, NameB, _DirB, AuthB, KeyB} = start_node(PairRoot, "b", OptB),
    _ = authorize(NameA, KeyA, AuthB),
    _ = authorize(NameB, KeyB, AuthA),
    {PeerA, NodeA, PeerB, NodeB}.

stop_pair({PeerA, _NodeA, PeerB, _NodeB}) ->
    stop_peer(PeerA),
    stop_peer(PeerB),
    ok.

start_node(Root, Suffix, ExtraSettings) ->
    Unique = integer_to_list(erlang:unique_integer([positive])),
    Name = list_to_atom("bouncer_" ++ Suffix ++ "_" ++ Unique),
    NodeName = <<(atom_to_binary(Name, utf8))/binary, "@127.0.0.1">>,
    Dir = filename:join(Root, atom_to_list(Name)),
    AuthDir = filename:join(Dir, "authorized.d"),
    ok = filelib:ensure_dir(filename:join(AuthDir, "marker")),
    {ok, Keys} = bouncer_keys:load_or_generate(
                   NodeName, #{dir => Dir, generate => true}),
    Pa = code:get_path(),
    BouncerArgs =
        lists:append([["-bouncer", Key, Value] ||
                         {Key, Value} <-
                             [{"dir", Dir}, {"authorized_dirs", AuthDir},
                              {"generate", "false"} | ExtraSettings]]),
    Args = ["+S", "2:2",
            "+SDio", "1",
            "+SDcpu", "1:1",
            "-proto_dist", "bouncer",
            "-kernel", "net_ticktime", "8",
            "inet_dist_use_interface", "{127,0,0,1}"] ++ BouncerArgs ++
        ["-pa" | Pa],
    {ok, Peer, Node} = peer:start_link(
                         #{name => Name, host => "127.0.0.1",
                           longnames => true,
                           connection => standard_io, args => Args}),
    {Peer, Node, NodeName, Dir, AuthDir, Keys}.

start_plain_node(Root) ->
    Name = list_to_atom("bouncer_plain_" ++
                        integer_to_list(erlang:unique_integer([positive]))),
    Args = ["+S", "2:2",
            "+SDio", "1",
            "+SDcpu", "1:1",
            "-proto_dist", "inet_tcp",
            "-kernel", "net_ticktime", "8",
            "-pa" | code:get_path()],
    {ok, Peer, Node} = peer:start_link(
                         #{name => Name, host => "127.0.0.1",
                           longnames => true,
                           connection => standard_io, args => Args}),
    _ = Root,
    {Peer, Node}.

authorize(Name, Keys, AuthDir) ->
    {ok, Path} = bouncer_keys:add_peer(Name, bouncer_keys:public(Keys),
                                       #{authorized_dirs => AuthDir,
                                         node_name => Name}),
    Path.

install_log_capture(Peer) ->
    ok = peer:call(Peer, logger, add_handler,
                   [bouncer_dist_ct_capture, ?MODULE, #{level => all}]),
    ok.

log_contains(Peer, Text) ->
    timer:sleep(100),
    Events = peer:call(Peer, ?MODULE, captured_logs, []),
    Formatted = iolist_to_binary(io_lib:format("~p", [Events])),
    binary:match(Formatted, list_to_binary(Text)) =/= nomatch.

adding_handler(Config) ->
    ensure_ct_data_table(),
    ets:delete_all_objects(bouncer_dist_ct_data),
    {ok, Config}.

removing_handler(_Config) ->
    ok.

log(Event, Config) ->
    _ = Config,
    Id = erlang:unique_integer([positive]),
    true = ets:insert(bouncer_dist_ct_data, {{log, Id}, Event}),
    ok.

put_value(Key, Value) ->
    true = ets:insert(bouncer_dist_ct_data, {{value, Key}, Value}),
    ok.

ensure_ct_data_table() ->
    case ets:whereis(bouncer_dist_ct_data) of
        undefined ->
            Parent = self(),
            Pid = spawn(?MODULE, ct_data_owner, [Parent]),
            receive
                {ct_data_ready, Pid} ->
                    ok
            after 5000 ->
                exit({ct_data_owner_start_timeout, Pid})
            end;
        _Tid ->
            ok
    end.

ct_data_owner(Parent) ->
    _ = ets:new(bouncer_dist_ct_data,
                [named_table, set, public, {read_concurrency, true}]),
    Parent ! {ct_data_ready, self()},
    receive
        stop -> ok
    end.

stop_peer(Peer) when is_pid(Peer) ->
    peer:stop(Peer),
    ok.

temp_dir(Prefix) ->
    filename:join("/tmp", Prefix ++ "_" ++
                  integer_to_list(erlang:unique_integer([positive]))).
