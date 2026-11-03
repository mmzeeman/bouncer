%% Loopback integration tests for the raw-socket Noise XX handshake.
-module(bouncer_hs_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").

-export([all/0, init_per_suite/1, end_per_suite/1]).
-export([success_chachapoly_blake2b/1, success_aesgcm_sha512/1,
         success_aesgcm_sha256/1, success_aesgcm_blake2b/1,
         initiator_rejects_untrusted_responder/1,
         responder_rejects_unknown_initiator/1, responder_rejects_denied_initiator/1,
         known_key_claiming_other_name/1,
         message2_name_mismatch/1, suite_mismatch/1, bad_magic_and_timeout/1,
         tampered_flights/1, flight1_sent_before_reply/1,
         logs_do_not_contain_secret_key/1, max_pending/1]).

all() ->
    [success_chachapoly_blake2b, success_aesgcm_sha512,
     success_aesgcm_sha256, success_aesgcm_blake2b,
     initiator_rejects_untrusted_responder,
     responder_rejects_unknown_initiator, responder_rejects_denied_initiator,
     known_key_claiming_other_name,
     message2_name_mismatch, suite_mismatch, bad_magic_and_timeout,
     tampered_flights, flight1_sent_before_reply,
     logs_do_not_contain_secret_key, max_pending].

init_per_suite(Config) ->
    Root = filename:join("/tmp", "bouncer_hs_" ++
                         integer_to_list(erlang:unique_integer([positive]))),
    ok = file:make_dir(Root),
    IName = <<"init@host">>,
    RName = <<"resp@host">>,
    {IKeys, IAuth} = identity(Root, "initiator", IName),
    {RKeys, RAuth} = identity(Root, "responder", RName),
    [{root, Root}, {i_name, IName}, {r_name, RName},
     {i_keys, IKeys}, {r_keys, RKeys}, {i_auth, IAuth}, {r_auth, RAuth}
     | Config].

end_per_suite(Config) ->
    file:del_dir_r(?config(root, Config)).

success_chachapoly_blake2b(Config) ->
    success(chachapoly_blake2b, Config).

success_aesgcm_sha512(Config) ->
    success(aesgcm_sha512, Config).

success_aesgcm_sha256(Config) ->
    success(aesgcm_sha256, Config).

success_aesgcm_blake2b(Config) ->
    success(aesgcm_blake2b, Config).

success(Suite, Config) ->
    reset_authorizations(Config),
    require_suite(Suite),
    authorize_both(Config),
    IName = ?config(i_name, Config),
    RName = ?config(r_name, Config),
    IKeys = ?config(i_keys, Config),
    RKeys = ?config(r_keys, Config),
    IAuth = ?config(i_auth, Config),
    RAuth = ?config(r_auth, Config),
    IOpts = initiator_opts(IName, IAuth, Suite),
    ROpts = responder_opts(RName, RAuth, Suite),
    {Pid, Listen, Port} = start_responder(RName, RKeys, ROpts),
    {ok, Socket} = connect(Port),
    {ok, IResult} = bouncer_hs:initiate(Socket, RName, IKeys, IOpts),
    RResult = responder_result(Pid),
    {ok, RResultMap} = RResult,
    ?assertEqual(RName, maps:get(remote_name, IResult)),
    ?assertEqual(bouncer_keys:public(RKeys), maps:get(remote_key, IResult)),
    ?assertEqual(IName, maps:get(remote_name, RResultMap)),
    ?assertEqual(bouncer_keys:public(IKeys), maps:get(remote_key, RResultMap)),
    ?assertEqual(Suite, maps:get(suite, IResult)),
    ?assertEqual(Suite, maps:get(suite, RResultMap)),
    Payload = crypto:strong_rand_bytes(1024 * 1024),
    ?assertEqual([Payload],
                 transport_packets(maps:get(send, IResult),
                                   maps:get(recv, RResultMap), Payload)),
    ?assertEqual([Payload],
                 transport_packets(maps:get(send, RResultMap),
                                   maps:get(recv, IResult), Payload)),
    gen_tcp:close(Socket),
    gen_tcp:close(Listen),
    ok.

reset_authorizations(Config) ->
    [case file:del_dir_r(Dir) of
         ok -> ok;
         {error, enoent} -> ok
     end || Dir <- [?config(i_auth, Config), ?config(r_auth, Config)]],
    ok.

initiator_rejects_untrusted_responder(Config) ->
    reset_authorizations(Config),
    RName = ?config(r_name, Config),
    IName = ?config(i_name, Config),
    RKeys = ?config(r_keys, Config),
    IKeys = ?config(i_keys, Config),
    IOpts = initiator_opts(IName, ?config(i_auth, Config), aesgcm_sha512),
    ROpts = responder_opts(RName, ?config(r_auth, Config), aesgcm_sha512),
    {Pid, Listen, Port} = start_responder(RName, RKeys, ROpts),
    {ok, Socket} = connect(Port),
    ?assertEqual({error, {unauthorized_peer, unknown_name}},
                 bouncer_hs:initiate(Socket, RName, IKeys, IOpts)),
    ?assertEqual({error, closed}, responder_result(Pid)),
    gen_tcp:close(Listen),
    ok.

responder_rejects_unknown_initiator(Config) ->
    reset_authorizations(Config),
    RName = ?config(r_name, Config),
    IName = ?config(i_name, Config),
    RKeys = ?config(r_keys, Config),
    IKeys = ?config(i_keys, Config),
    ok = add_peer(RName, bouncer_keys:public(RKeys), ?config(i_auth, Config)),
    IOpts = initiator_opts(IName, ?config(i_auth, Config), aesgcm_sha512),
    ROpts = responder_opts(RName, ?config(r_auth, Config), aesgcm_sha512),
    {Pid, Listen, Port} = start_responder(RName, RKeys, ROpts),
    {ok, Socket} = connect(Port),
    ?assertMatch({ok, _}, bouncer_hs:initiate(Socket, RName, IKeys, IOpts)),
    ?assertEqual({error, {unauthorized_peer, unknown_name}}, responder_result(Pid)),
    ?assertEqual({error, closed}, gen_tcp:recv(Socket, 1, 1000)),
    gen_tcp:close(Listen),
    ok.

responder_rejects_denied_initiator(Config) ->
    reset_authorizations(Config),
    RName = ?config(r_name, Config),
    IName = ?config(i_name, Config),
    RKeys = ?config(r_keys, Config),
    IKeys = ?config(i_keys, Config),
    OtherKeyPair = enoise_keypair:new(dh25519),
    {ok, _} = bouncer_keys:add_peer(IName, enoise_keypair:pubkey(OtherKeyPair),
                                    #{authorized_dirs => [?config(r_auth, Config)],
                                      node_name => IName}),
    ok = add_peer(RName, bouncer_keys:public(RKeys), ?config(i_auth, Config)),
    IOpts = initiator_opts(IName, ?config(i_auth, Config), aesgcm_sha512),
    ROpts = responder_opts(RName, ?config(r_auth, Config), aesgcm_sha512),
    {Pid, Listen, Port} = start_responder(RName, RKeys, ROpts),
    {ok, Socket} = connect(Port),
    ?assertMatch({ok, _}, bouncer_hs:initiate(Socket, RName, IKeys, IOpts)),
    ?assertEqual({error, {unauthorized_peer, denied}}, responder_result(Pid)),
    gen_tcp:close(Listen),
    ok.

known_key_claiming_other_name(Config) ->
    reset_authorizations(Config),
    RName = ?config(r_name, Config),
    IName = ?config(i_name, Config),
    RKeys = ?config(r_keys, Config),
    IKeys = ?config(i_keys, Config),
    ok = add_peer(RName, bouncer_keys:public(RKeys), ?config(i_auth, Config)),
    ok = add_peer(IName, bouncer_keys:public(IKeys), ?config(r_auth, Config)),
    SpoofedName = <<"spoof@host">>,
    IOpts = (initiator_opts(IName, ?config(i_auth, Config), aesgcm_sha512))
                #{own_name => SpoofedName},
    ROpts = responder_opts(RName, ?config(r_auth, Config), aesgcm_sha512),
    {Pid, Listen, Port} = start_responder(RName, RKeys, ROpts),
    {ok, Socket} = connect(Port),
    ?assertMatch({ok, _}, bouncer_hs:initiate(Socket, RName, IKeys, IOpts)),
    ?assertEqual({error, {unauthorized_peer, unknown_name}}, responder_result(Pid)),
    gen_tcp:close(Listen),
    ok.

message2_name_mismatch(Config) ->
    reset_authorizations(Config),
    Target = ?config(r_name, Config),
    OtherName = <<"other@host">>,
    IName = ?config(i_name, Config),
    RKeys = ?config(r_keys, Config),
    IKeys = ?config(i_keys, Config),
    IOpts = initiator_opts(IName, ?config(i_auth, Config), aesgcm_sha512),
    {Pid, Listen, Port} = start_malicious_responder(Target, OtherName, RKeys),
    {ok, Socket} = connect(Port),
    ?assertEqual({error, target_name_mismatch},
                 bouncer_hs:initiate(Socket, Target, IKeys, IOpts)),
    ?assertEqual({error, closed}, malicious_result(Pid)),
    gen_tcp:close(Listen),
    ok.

suite_mismatch(Config) ->
    reset_authorizations(Config),
    RName = ?config(r_name, Config),
    RKeys = ?config(r_keys, Config),
    IOpts = initiator_opts(?config(i_name, Config), ?config(i_auth, Config),
                           chachapoly_blake2b),
    ROpts = responder_opts(RName, ?config(r_auth, Config), aesgcm_sha512),
    {Pid, Listen, Port} = start_responder(RName, RKeys, ROpts),
    {ok, Socket} = connect(Port),
    ?assertEqual({error, unsupported_suite},
                 bouncer_hs:initiate(Socket, RName, ?config(i_keys, Config), IOpts)),
    ?assertEqual({error, unsupported_suite}, responder_result(Pid)),
    gen_tcp:close(Listen),
    ok.

bad_magic_and_timeout(Config) ->
    reset_authorizations(Config),
    RName = ?config(r_name, Config),
    RKeys = ?config(r_keys, Config),
    ROpts = (responder_opts(RName, ?config(r_auth, Config), aesgcm_sha512))
                #{handshake_timeout_ms => 100},
    {Pid1, Listen1, Port1} = start_responder(RName, RKeys, ROpts),
    {ok, Socket1} = connect(Port1),
    ok = gen_tcp:send(Socket1, <<"XNCR", 1, 2, 0, 32>>),
    ?assertEqual({error, bad_hello_header}, responder_result(Pid1)),
    ?assertEqual({error, closed}, gen_tcp:recv(Socket1, 1, 500)),
    gen_tcp:close(Listen1),

    {Pid2, Listen2, Port2} = start_responder(RName, RKeys, ROpts),
    {ok, Socket2} = connect(Port2),
    Started = erlang:monotonic_time(millisecond),
    ?assertEqual({error, timeout}, responder_result(Pid2)),
    Elapsed = erlang:monotonic_time(millisecond) - Started,
    ?assert(Elapsed < 1000),
    ?assertEqual({error, closed}, gen_tcp:recv(Socket2, 1, 500)),
    gen_tcp:close(Listen2),
    ok.

max_pending(Config) ->
    reset_authorizations(Config),
    RName = ?config(r_name, Config),
    RKeys = ?config(r_keys, Config),
    ROpts = (responder_opts(RName, ?config(r_auth, Config), aesgcm_sha512))
                #{max_pending => 1, handshake_timeout_ms => 200},
    {Pid1, Listen1, Port1} = start_responder(RName, RKeys, ROpts),
    {ok, Socket1} = connect(Port1),
    {Pid2, Listen2, Port2} = start_responder(RName, RKeys, ROpts),
    {ok, Socket2} = connect(Port2),
    ok = gen_tcp:send(Socket2, <<"unread">>),
    ?assertEqual({error, busy}, responder_result(Pid2)),
    ?assertEqual({error, closed}, gen_tcp:recv(Socket2, 1, 500)),
    ?assertEqual({error, timeout}, responder_result(Pid1)),
    gen_tcp:close(Socket1),
    gen_tcp:close(Socket2),
    gen_tcp:close(Listen1),
    gen_tcp:close(Listen2),
    ok.

tampered_flights(Config) ->
    reset_authorizations(Config),
    require_suite(aesgcm_sha512),
    authorize_both(Config),
    RName = ?config(r_name, Config),
    IName = ?config(i_name, Config),
    RKeys = ?config(r_keys, Config),
    IKeys = ?config(i_keys, Config),
    IOpts = initiator_opts(IName, ?config(i_auth, Config), aesgcm_sha512),
    ROpts = responder_opts(RName, ?config(r_auth, Config), aesgcm_sha512),
    lists:foreach(
      fun(Flight) ->
              {Pid, Listen, BackendPort} = start_responder(RName, RKeys, ROpts),
              {ProxyPid, ProxyListen, ProxyPort} = start_proxy(BackendPort, Flight),
              {ok, Socket} = connect(ProxyPort),
              InitiatorResult = bouncer_hs:initiate(Socket, RName, IKeys, IOpts),
              case Flight of
                  msg3 -> ?assertMatch({ok, _}, InitiatorResult);
                  _ -> ?assertMatch({error, _}, InitiatorResult)
              end,
              ResponderResult = responder_result(Pid),
              ?assertMatch({error, _}, ResponderResult),
              proxy_result(ProxyPid),
              gen_tcp:close(Socket),
              gen_tcp:close(Listen),
              gen_tcp:close(ProxyListen)
      end,
      [hello_header, msg1, msg2, msg3]),
    ok.

flight1_sent_before_reply(Config) ->
    reset_authorizations(Config),
    RName = ?config(r_name, Config),
    IName = ?config(i_name, Config),
    IKeys = ?config(i_keys, Config),
    IOpts = initiator_opts(IName, ?config(i_auth, Config), aesgcm_sha512),
    {ok, Listen} = gen_tcp:listen(0, [binary, {packet, 0}, {active, false},
                                     {reuseaddr, true}, {ip, {127, 0, 0, 1}}]),
    {ok, {_Address, Port}} = inet:sockname(Listen),
    Parent = self(),
    ServerPid = spawn(fun() ->
                              {ok, ServerSocket} = gen_tcp:accept(Listen),
                              {ok, Flight1} = gen_tcp:recv(ServerSocket, 40, 1000),
                              Parent ! {flight1, self(), Flight1},
                              Parent ! {flight1_idle, self(),
                                        gen_tcp:recv(ServerSocket, 1, 100)},
                              gen_tcp:close(ServerSocket)
                      end),
    ClientPid = spawn(fun() ->
                              Result = case connect(Port) of
                                           {ok, ClientSocket} ->
                                               bouncer_hs:initiate(ClientSocket, RName,
                                                                   IKeys, IOpts);
                                           {error, Reason} ->
                                               {error, Reason}
                                       end,
                              Parent ! {initiate_result, self(), Result}
                      end),
    Flight1 = receive {flight1, ServerPid, Data} -> Data
               after 1000 -> ct:fail(no_flight1)
              end,
    ?assertEqual(40, byte_size(Flight1)),
    ?assertEqual(bouncer_protocol:hello_header(2), binary:part(Flight1, 0, 8)),
    ?assertEqual({error, timeout},
                 receive {flight1_idle, ServerPid, Result} -> Result
                 after 1000 -> ct:fail(flight1_not_idle)
                 end),
    receive {initiate_result, ClientPid, {error, closed}} -> ok
    after 1000 -> ct:fail(initiate_did_not_close)
    end,
    gen_tcp:close(Listen),
    ok.

logs_do_not_contain_secret_key(Config) ->
    reset_authorizations(Config),
    RName = ?config(r_name, Config),
    IName = ?config(i_name, Config),
    RKeys = ?config(r_keys, Config),
    IKeys = ?config(i_keys, Config),
    ok = add_peer(RName, bouncer_keys:public(RKeys), ?config(i_auth, Config)),
    IOpts = initiator_opts(IName, ?config(i_auth, Config), aesgcm_sha512),
    ROpts = responder_opts(RName, ?config(r_auth, Config), aesgcm_sha512),
    LogFile = filename:join(?config(root, Config), "captured.log"),
    Handler = bouncer_hs_secret_check,
    ok = logger:add_handler(Handler, logger_std_h,
                            #{level => warning,
                              config => #{type => file, file => LogFile}}),
    try
        {Pid, Listen, Port} = start_responder(RName, RKeys, ROpts),
        {ok, Socket} = connect(Port),
        ?assertMatch({ok, _}, bouncer_hs:initiate(Socket, RName, IKeys, IOpts)),
        ?assertEqual({error, {unauthorized_peer, unknown_name}}, responder_result(Pid)),
        gen_tcp:close(Socket),
        gen_tcp:close(Listen)
    after
        ok = logger:remove_handler(Handler)
    end,
    {ok, Logs} = file:read_file(LogFile),
    Secrets = [bouncer_keys:secret(IKeys), bouncer_keys:secret(RKeys)],
    [begin
         ?assertEqual(nomatch, binary:match(Logs, base64:encode(Secret))),
         ?assertEqual(nomatch, binary:match(Logs, Secret))
     end || Secret <- Secrets],
    ok.

identity(Root, Label, Name) ->
    Dir = filename:join(Root, Label),
    Auth = filename:join(Dir, "authorized.d"),
    {ok, Keys} = bouncer_keys:load_or_generate(Name, #{dir => Dir}),
    {Keys, Auth}.

authorize_both(Config) ->
    IName = ?config(i_name, Config),
    RName = ?config(r_name, Config),
    IKeys = ?config(i_keys, Config),
    RKeys = ?config(r_keys, Config),
    ok = add_peer(RName, bouncer_keys:public(RKeys), ?config(i_auth, Config)),
    ok = add_peer(IName, bouncer_keys:public(IKeys), ?config(r_auth, Config)).

add_peer(Name, Public, AuthDir) ->
    {ok, _Path} = bouncer_keys:add_peer(Name, Public,
                                        #{authorized_dirs => [AuthDir],
                                          node_name => Name}),
    ok.

initiator_opts(Name, AuthDir, Suite) ->
    #{own_name => Name, node_name => Name, authorized_dirs => [AuthDir],
      suite => Suite, accept_suites => [Suite]}.

responder_opts(Name, AuthDir, Suite) ->
    #{node_name => Name, authorized_dirs => [AuthDir], accept_suites => [Suite]}.

start_responder(Name, Keys, Opts) ->
    {ok, Listen} = gen_tcp:listen(0, [binary, {packet, 0}, {active, false},
                                     {reuseaddr, true}, {ip, {127, 0, 0, 1}}]),
    {ok, {_Address, Port}} = inet:sockname(Listen),
    Parent = self(),
    Pid = spawn(fun() ->
                        {ok, Socket} = gen_tcp:accept(Listen),
                        Result = bouncer_hs:respond(Socket, Name, Keys, Opts),
                        Parent ! {responder_result, self(), Result}
                end),
    {Pid, Listen, Port}.

connect(Port) ->
    gen_tcp:connect({127, 0, 0, 1}, Port,
                    [binary, {packet, 0}, {active, false}], 2000).

responder_result(Pid) ->
    receive
        {responder_result, Pid, Result} -> Result
    after 3000 ->
        ct:fail({responder_timeout, Pid})
    end.

start_malicious_responder(Target, MessageName, Keys) ->
    {ok, Listen} = gen_tcp:listen(0, [binary, {packet, 0}, {active, false},
                                     {reuseaddr, true}, {ip, {127, 0, 0, 1}}]),
    {ok, {_Address, Port}} = inet:sockname(Listen),
    Parent = self(),
    Pid = spawn(fun() ->
                        {ok, Socket} = gen_tcp:accept(Listen),
                        {ok, HelloHeader} = gen_tcp:recv(Socket, 8, 1000),
                        {ok, _Suite, 32} =
                            bouncer_protocol:parse_hello_header(HelloHeader, [2]),
                        {ok, Msg1} = gen_tcp:recv(Socket, 32, 1000),
                        Prologue = bouncer_protocol:prologue(HelloHeader, Target),
                        KeyPair = enoise_keypair:new(dh25519, bouncer_keys:secret(Keys),
                                                     bouncer_keys:public(Keys)),
                        {ok, State0} =
                            enoise:handshake([{noise,
                                              bouncer_protocol:noise_name(aesgcm_sha512)},
                                             {prologue, Prologue}, {s, KeyPair}],
                                            responder),
                        {ok, rcvd, <<>>, State1} =
                            enoise:step_handshake(State0, {rcvd, Msg1}),
                        {ok, send, Msg2, _State2} =
                            enoise:step_handshake(
                              State1, {send, bouncer_protocol:name_payload(MessageName)}),
                        ok = gen_tcp:send(Socket, bouncer_protocol:reply_ok(Msg2)),
                        Result = gen_tcp:recv(Socket, 2, 1000),
                        Parent ! {malicious_result, self(), Result}
                end),
    {Pid, Listen, Port}.

malicious_result(Pid) ->
    receive
        {malicious_result, Pid, Result} -> Result
    after 2000 ->
        ct:fail({malicious_responder_timeout, Pid})
    end.

start_proxy(BackendPort, FlightToFlip) ->
    {ok, Listen} = gen_tcp:listen(0, [binary, {packet, 0}, {active, false},
                                     {reuseaddr, true}, {ip, {127, 0, 0, 1}}]),
    {ok, {_Address, Port}} = inet:sockname(Listen),
    Parent = self(),
    Pid = spawn(fun() ->
                        {ok, Client} = gen_tcp:accept(Listen),
                        {ok, Backend} = connect(BackendPort),
                        Result = proxy_flights(Client, Backend, FlightToFlip),
                        Parent ! {proxy_result, self(), Result}
                end),
    {Pid, Listen, Port}.

proxy_flights(Client, Backend, FlightToFlip) ->
    case gen_tcp:recv(Client, 8, 1000) of
        {ok, Header} ->
            Header1 = maybe_flip(hello_header, Header, FlightToFlip),
            case gen_tcp:send(Backend, Header1) of
                ok ->
                    proxy_msg1(Client, Backend, Header, FlightToFlip);
                {error, Reason} ->
                    {error, Reason}
            end;
        {error, Reason} ->
            {error, Reason}
    end.

proxy_msg1(Client, Backend, <<_:6/binary, Len:16>>, FlightToFlip) ->
    case gen_tcp:recv(Client, Len, 1000) of
        {ok, Msg1} ->
            case gen_tcp:send(Backend, maybe_flip(msg1, Msg1, FlightToFlip)) of
                ok -> proxy_reply(Client, Backend, FlightToFlip);
                {error, Reason} -> {error, Reason}
            end;
        {error, Reason} -> {error, Reason}
    end.

proxy_reply(Client, Backend, FlightToFlip) ->
    case gen_tcp:recv(Backend, 8, 1000) of
        {ok, ReplyHeader = <<_:6/binary, Len:16>>} ->
            case gen_tcp:recv(Backend, Len, 1000) of
                {ok, Msg2} ->
                    case gen_tcp:send(Client, ReplyHeader) of
                        ok ->
                            case gen_tcp:send(Client,
                                              maybe_flip(msg2, Msg2, FlightToFlip)) of
                                ok -> proxy_msg3(Client, Backend, FlightToFlip);
                                {error, Reason} -> {error, Reason}
                            end;
                        {error, Reason} -> {error, Reason}
                    end;
                {error, Reason} -> {error, Reason}
            end;
        {error, Reason} -> {error, Reason}
    end.

proxy_msg3(Client, Backend, FlightToFlip) ->
    case gen_tcp:recv(Client, 2, 1000) of
        {ok, Prefix = <<Len:16>>} ->
            case gen_tcp:recv(Client, Len, 1000) of
                {ok, Msg3} ->
                    gen_tcp:send(Backend,
                                 <<Prefix/binary,
                                   (maybe_flip(msg3, Msg3, FlightToFlip))/binary>>);
                {error, Reason} -> {error, Reason}
            end;
        {error, Reason} -> {error, Reason}
    end.

maybe_flip(Flight, Data, Flight) ->
    <<Byte, Rest/binary>> = Data,
    <<(Byte bxor 1), Rest/binary>>;
maybe_flip(_Flight, Data, _Other) ->
    Data.

proxy_result(Pid) ->
    receive {proxy_result, Pid, Result} -> Result
    after 2000 -> ct:fail({proxy_timeout, Pid})
    end.

transport_packets(SendCS, RecvCS, Payload) ->
    Sender = bouncer_protocol:new_sender(SendCS, #{}),
    Receiver = bouncer_protocol:new_receiver(RecvCS, #{}),
    Frames = packet_frames(Sender, bouncer_protocol:tx_packet(Payload), []),
    {Events, _Receiver} =
        lists:foldl(fun(Frame, {Acc, R}) ->
                            {ok, FrameEvents, R1} =
                                bouncer_protocol:rx_feed(R, iolist_to_binary(Frame)),
                            {Acc ++ FrameEvents, R1}
                    end,
                    {[], Receiver}, Frames),
    [iolist_to_binary(Packet) || {packet, Packet} <- Events].

packet_frames(Sender, Pending, Acc) ->
    case bouncer_protocol:tx_next(Sender, Pending) of
        {Frame, _Sender1, done} ->
            lists:reverse([Frame | Acc]);
        {Frame, Sender1, more, Pending1} ->
            packet_frames(Sender1, Pending1, [Frame | Acc])
    end.

require_suite(Suite) ->
    Probe = try enoise:handshake([{noise, bouncer_protocol:noise_name(Suite)}], initiator)
            catch
                _:_ -> unsupported
            end,
    case Probe of
        {ok, _State} -> ok;
        {error, Reason} ->
            ct:skip(io_lib:format("enoise lacks ~p: ~p", [Suite, Reason]));
        unsupported ->
            ct:skip(io_lib:format("enoise lacks ~p", [Suite]))
    end.
