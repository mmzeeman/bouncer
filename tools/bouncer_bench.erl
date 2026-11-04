%% Standalone distribution benchmark runner. The same worker code is loaded
%% by the peer nodes so measurements run over distribution, not peer control.
-module(bouncer_bench).

-export([main/0, measure/5, measure_mailbox/5,
         start_mailbox_receiver/1, mailbox_receiver/1]).

-define(SUITES, ["chachapoly_blake2b", "aesgcm_sha512",
                 "aesgcm_sha256", "aesgcm_blake2b"]).
-define(DEFAULTS,
        #{suites => ?SUITES,
          compressions => ["none", "zlib:256", "zlib:1024"],
          chunk_sizes => [1024, 16384, 65518],
          small_sizes => [32, 256, 1024],
          iterations => 1000,
          large_bytes => 1048576,
          large_iterations => 16,
          mailbox_workers => 8,
          mailbox_messages => 250,
          mailbox_sizes => [32, 128, 1024],
          warmup => 50,
          payload => compressible,
          output => "-"}).

main() ->
    case parse_args(init:get_plain_arguments(), ?DEFAULTS) of
        help ->
            usage(),
            halt(0);
        {error, Reason} ->
            io:format(standard_error, "bouncer_bench: ~p~n", [Reason]),
            usage(),
            halt(2);
        {ok, Options} ->
            try
                ok = run(Options),
                halt(0)
            catch
                Class:Reason:Stack ->
                    io:format(standard_error,
                              "bouncer_bench failed (~p): ~p~n~p~n",
                              [Class, Reason, Stack]),
                    halt(1)
            end
    end.

run(Options) ->
    _ = os:cmd("epmd -daemon"),
    ok = code:add_paths(filelib:wildcard("_build/default/lib/*/ebin")),
    ok = logger:set_primary_config(level, emergency),
    {ok, Device, Close} = output_device(maps:get(output, Options)),
    try
        write_header(Device),
        Root = make_root(),
        try
            Workloads = workloads(Options),
            io:format(standard_error, "Measuring inet_tcp reference...~n", []),
            Baseline = run_with_pair(
                         inet_tcp, Root, #{},
                         fun(PeerA, PeerB, NodeB) ->
                                 measure_workloads(PeerA, PeerB, NodeB, Workloads,
                                                   Options, inet_tcp,
                                                   #{}, Device, #{})
                         end),
            Matrix = [{Suite, Compression, ChunkSize}
                      || Suite <- maps:get(suites, Options),
                         Compression <- maps:get(compressions, Options),
                         ChunkSize <- maps:get(chunk_sizes, Options)],
            Total = length(Matrix),
            lists:foreach(
              fun({{Suite, Compression, ChunkSize}, Index}) ->
                      io:format(standard_error, "bouncer ~s / ~s / chunk ~B (~B/~B)~n",
                                [Suite, Compression, ChunkSize, Index, Total]),
                      Settings = #{suite => Suite, compression => Compression,
                                   chunk_size => ChunkSize},
                      _ = run_with_pair(
                            bouncer, Root, Settings,
                            fun(PeerA, PeerB, NodeB) ->
                                    measure_workloads(PeerA, PeerB, NodeB, Workloads,
                                                      Options, bouncer,
                                                      Settings, Device, Baseline)
                            end)
              end, lists:zip(Matrix, lists:seq(1, Total))),
            ok
        after
            _ = file:del_dir_r(Root)
        end
    after
        Close()
    end.

make_root() ->
    TempDir = case os:getenv("TMPDIR") of
                  false -> "/tmp";
                  Value -> Value
              end,
    Suffix = integer_to_list(erlang:system_time(microsecond)) ++ "_" ++
        integer_to_list(erlang:unique_integer([positive])),
    Root = filename:join(TempDir, "bouncer_bench_" ++ Suffix),
    case file:make_dir(Root) of
        ok -> Root;
        {error, eexist} -> make_root();
        {error, Reason} -> error({cannot_create_temp_dir, Root, Reason})
    end.

workloads(Options) ->
    Small = [{small, Size, maps:get(iterations, Options)}
             || Size <- maps:get(small_sizes, Options)],
    Small ++ [{bulk, maps:get(large_bytes, Options),
               maps:get(large_iterations, Options)},
              {mailbox, maps:get(mailbox_sizes, Options),
               maps:get(mailbox_workers, Options),
               maps:get(mailbox_messages, Options)}].

measure_workloads(PeerA, PeerB, NodeB, Workloads, Options, Carrier, Settings,
                  Device, Baseline) ->
    Results = lists:map(
                fun(Workload) ->
                        {Kind, Size, Iterations} =
                            workload_fields(Workload, Options),
                        Warmup = min(maps:get(warmup, Options), Iterations),
                        Result = measure_workload(
                                   Workload, PeerA, PeerB, NodeB, Options,
                                   Iterations, Warmup),
                        emit_row(Device, Carrier, Settings, Workload, Kind, Size,
                                 Iterations, Result,
                                 maps:get(workload_key(Workload), Baseline,
                                          undefined)),
                        {workload_key(Workload), Result}
                end, Workloads),
    maps:from_list(Results).

workload_fields({small, Size, Iterations}, _Options) ->
    {small, Size, Iterations};
workload_fields({bulk, Size, Iterations}, _Options) ->
    {bulk, Size, Iterations};
workload_fields({mailbox, Sizes, Workers, Messages}, _Options) ->
    {mailbox, lists:flatten(lists:join("|", [integer_to_list(S) || S <- Sizes])),
     Workers * Messages}.

workload_key({mailbox, Sizes, Workers, Messages}) ->
    {mailbox, Sizes, Workers, Messages};
workload_key({Kind, Size, Iterations}) ->
    {Kind, Size, Iterations}.

measure_workload({mailbox, Sizes, Workers, Messages}, PeerA, PeerB, _NodeB,
                 Options, _Iterations, _Warmup) ->
    Total = Workers * Messages,
    Receiver = peer:call(PeerB, ?MODULE, start_mailbox_receiver, [Total]),
    try
        peer:call(PeerA, ?MODULE, measure_mailbox,
                  [Receiver, Sizes, Workers, Messages,
                   maps:get(payload, Options)], 3600000)
    after
        _ = peer:call(PeerB, erlang, exit, [Receiver, kill])
    end;
measure_workload({_Kind, Size, Iterations}, PeerA, _PeerB, NodeB, Options,
                 Iterations, Warmup) ->
    peer:call(PeerA, ?MODULE, measure,
              [NodeB, Size, Iterations, Warmup, maps:get(payload, Options)],
              3600000).

emit_row(Device, inet_tcp, _Settings, Workload, Kind, Size, Iterations,
         Result, _Baseline) ->
    write_row(Device, ["inet_tcp", "-", "-", "-", workload_name(Kind),
                       atom_to_list(maps:get(payload_mode, Result, compressible)),
                       Size, Iterations | workload_columns(Workload)] ++
              [maps:get(latency_ms, Result),
                       maps:get(mib_per_second, Result), "", "", "", ""]);
emit_row(Device, bouncer, Settings, Workload, Kind, Size, Iterations,
         Result, Baseline) ->
    BaseLatency = maps:get(latency_ms, Baseline),
    BaseThroughput = maps:get(mib_per_second, Baseline),
    write_row(Device, ["bouncer", maps:get(suite, Settings),
                       maps:get(compression, Settings),
                       maps:get(chunk_size, Settings), workload_name(Kind),
                       atom_to_list(maps:get(payload_mode, Result, compressible)),
                       Size, Iterations | workload_columns(Workload)] ++
              [maps:get(latency_ms, Result),
                       maps:get(mib_per_second, Result), BaseLatency,
                       BaseThroughput,
                       percent_change(maps:get(latency_ms, Result), BaseLatency),
                       percent_change(maps:get(mib_per_second, Result),
                                      BaseThroughput)]).

workload_columns({mailbox, _Sizes, Workers, Messages}) ->
    [Workers, Messages];
workload_columns(_) ->
    ["", ""].

workload_name(small) -> "small_rpc_roundtrip";
workload_name(bulk) -> "bulk_rpc_one_way";
workload_name(mailbox) -> "concurrent_mailbox_request_reply".

percent_change(_Value, 0) -> "";
percent_change(Value, Baseline) -> (Value - Baseline) / Baseline * 100.

write_header(Device) ->
    write_row(Device,
              ["carrier", "suite", "compression", "chunk_size", "workload",
               "payload", "message_bytes", "iterations", "workers",
               "messages_per_worker", "latency_ms",
               "payload_mib_per_second", "inet_latency_ms",
               "inet_payload_mib_per_second", "latency_change_pct",
               "throughput_change_pct"]).

write_row(Device, Values) ->
    Csv = [csv_value(Value) || Value <- Values],
    io:format(Device, "~s~n", [lists:join(",", Csv)]).

csv_value(Value) when is_integer(Value) ->
    integer_to_list(Value);
csv_value(Value) when is_float(Value) ->
    lists:flatten(io_lib:format("~.3f", [Value]));
csv_value(Value) when is_atom(Value) ->
    atom_to_list(Value);
csv_value(Value) when is_list(Value) ->
    [$", [case C of $" -> "\"\""; _ -> C end || C <- Value], $"].

output_device("-") ->
    {ok, standard_io, fun() -> ok end};
output_device(Path) ->
    case file:open(Path, [write, {encoding, utf8}]) of
        {ok, Device} -> {ok, Device, fun() -> file:close(Device) end};
        {error, Reason} -> error({cannot_open_output, Path, Reason})
    end.

run_with_pair(Carrier, Root, Settings, Fun) ->
    {PeerA, PeerB, NodeB} = start_pair(Carrier, Root, Settings),
    try
        pong = peer:call(PeerA, net_adm, ping, [NodeB], 30000),
        Fun(PeerA, PeerB, NodeB)
    after
        stop_pair(PeerA, PeerB)
    end.

start_pair(Carrier, Root, Settings) ->
    Tag = integer_to_list(erlang:unique_integer([positive])),
    {PeerA, NameA, _NodeA, AuthA, KeysA} =
        start_node(Carrier, Root, "a_" ++ Tag, Settings),
    try
        {PeerB, NameB, NodeB, AuthB, KeysB} =
            start_node(Carrier, Root, "b_" ++ Tag, Settings),
        try
            case Carrier of
                inet_tcp -> ok;
                bouncer ->
                    {ok, _} = bouncer_keys:add_peer(
                                NameA, bouncer_keys:public(KeysA),
                                #{authorized_dirs => AuthB, node_name => NameB}),
                    {ok, _} = bouncer_keys:add_peer(
                                NameB, bouncer_keys:public(KeysB),
                                #{authorized_dirs => AuthA, node_name => NameA})
            end,
            {PeerA, PeerB, NodeB}
        catch
            InnerClass:InnerReason:InnerStack ->
                stop_peer(PeerB),
                erlang:raise(InnerClass, InnerReason, InnerStack)
        end
    catch
        OuterClass:OuterReason:OuterStack ->
            stop_peer(PeerA),
            erlang:raise(OuterClass, OuterReason, OuterStack)
    end.

start_node(Carrier, Root, Suffix, Settings) ->
    Name = list_to_atom("bench_" ++ Suffix),
    NodeName = <<(atom_to_binary(Name, utf8))/binary, "@127.0.0.1">>,
    Dir = filename:join(Root, atom_to_list(Name)),
    AuthDir = filename:join(Dir, "authorized.d"),
    ok = filelib:ensure_dir(filename:join(AuthDir, "marker")),
    {Keys, BouncerArgs} =
        case Carrier of
            inet_tcp ->
                {undefined, []};
            bouncer ->
                {ok, KeyInfo} = bouncer_keys:load_or_generate(
                                  NodeName, #{dir => Dir, generate => true}),
                {KeyInfo,
                 ["-bouncer", "dir", Dir,
                  "-bouncer", "authorized_dirs", AuthDir,
                  "-bouncer", "generate", "false",
                  "-bouncer", "accept_compression", "true",
                  "-bouncer", "accept_suites",
                  string:join(?SUITES, ","),
                  "-bouncer", "suite", maps:get(suite, Settings),
                  "-bouncer", "compression", maps:get(compression, Settings),
                  "-bouncer", "chunk_size",
                  integer_to_list(maps:get(chunk_size, Settings))]}
        end,
    Dist = case Carrier of inet_tcp -> "inet_tcp"; bouncer -> "bouncer" end,
    Args = ["+S", "2:2", "+SDio", "1", "+SDcpu", "1:1",
            "-proto_dist", Dist,
            "-kernel", "net_ticktime", "8",
            "-kernel", "inet_backend", "socket"
            "logger_level", "emergency",
            "inet_dist_use_interface", "{127,0,0,1}",
            "+zdbbl", "1000000"] ++ BouncerArgs ++
        ["-pa" | code:get_path()],
    case peer:start_link(#{name => Name, host => "127.0.0.1",
                           longnames => true, connection => standard_io,
                           args => Args}) of
        {ok, Peer, Node} -> {Peer, NodeName, Node, AuthDir, Keys};
        {error, Reason} -> error({peer_start_failed, Name, Reason})
    end.

stop_pair(PeerA, PeerB) ->
    stop_peer(PeerB),
    stop_peer(PeerA).

stop_peer(Peer) when is_pid(Peer) ->
    _ = peer:stop(Peer),
    ok.

%% Executed on the initiating peer; peer control traffic is excluded from
%% the timed interval. Each rpc call sends one dist message to the responder.
measure(NodeB, Size, Iterations, Warmup, PayloadMode) ->
    Payload = make_payload(Size, PayloadMode),
    lists:foreach(fun(_) -> check_rpc(NodeB, Payload, Size) end,
                  lists:seq(1, Warmup)),
    Start = erlang:monotonic_time(microsecond),
    lists:foreach(fun(_) -> check_rpc(NodeB, Payload, Size) end,
                  lists:seq(1, Iterations)),
    Elapsed = max(1, erlang:monotonic_time(microsecond) - Start),
    Seconds = Elapsed / 1000000,
    #{latency_ms => Elapsed / Iterations / 1000,
      mib_per_second => Size * Iterations / Seconds / 1048576,
      payload_mode => PayloadMode}.

start_mailbox_receiver(Count) ->
    spawn(?MODULE, mailbox_receiver, [Count]).

mailbox_receiver(0) ->
    ok;
mailbox_receiver(Count) when Count > 0 ->
    receive
        {bench_mailbox, Ref, From, Sequence, _Payload} ->
            From ! {bench_mailbox_ack, Ref, Sequence},
            mailbox_receiver(Count - 1);
        stop ->
            ok
    end.

measure_mailbox(Target, Sizes, Workers, Messages, PayloadMode)
  when is_pid(Target), is_list(Sizes), Sizes =/= [],
       is_integer(Workers), Workers > 0,
       is_integer(Messages), Messages > 0 ->
    Parent = self(),
    Ref = make_ref(),
    Payloads = [make_payload(Size, PayloadMode) || Size <- Sizes],
    Monitors = [begin
                    {Pid, Monitor} =
                        spawn_monitor(fun() ->
                                              mailbox_sender(Parent, Ref, Target,
                                                             Payloads, Messages)
                                      end),
                    {Pid, Monitor}
                end || _ <- lists:seq(1, Workers)],
    try
        Start = erlang:monotonic_time(microsecond),
        lists:foreach(fun({Pid, _Monitor}) -> Pid ! {Ref, start} end, Monitors),
        LatencyTotal = collect_mailbox_workers(Ref, Monitors, 0),
        Elapsed = max(1, erlang:monotonic_time(microsecond) - Start),
        Total = Workers * Messages,
        PayloadBytes = Workers *
            lists:sum([byte_size(lists:nth(((Sequence - 1) rem length(Payloads)) + 1,
                                           Payloads))
                       || Sequence <- lists:seq(1, Messages)]),
        #{latency_ms => LatencyTotal / Total / 1000,
          mib_per_second => PayloadBytes / (Elapsed / 1000000) / 1048576,
          payload_mode => PayloadMode}
    after
        lists:foreach(
          fun({Pid, Monitor}) ->
                  _ = erlang:demonitor(Monitor, [flush]),
                  case is_process_alive(Pid) of
                      true -> exit(Pid, kill);
                      false -> ok
                  end
          end, Monitors)
    end.

mailbox_sender(Parent, Ref, Target, Payloads, Messages) ->
    receive
        {Ref, start} -> ok
    end,
    LatencyTotal = mailbox_send_loop(Ref, Target, Payloads, Messages, 1, 0),
    Parent ! {Ref, mailbox_worker_done, self(), LatencyTotal}.

mailbox_send_loop(_Ref, _Target, _Payloads, Messages, Sequence, Total)
  when Sequence > Messages ->
    Total;
mailbox_send_loop(Ref, Target, Payloads, Messages, Sequence, Total) ->
    Payload = lists:nth(((Sequence - 1) rem length(Payloads)) + 1, Payloads),
    Start = erlang:monotonic_time(microsecond),
    Target ! {bench_mailbox, Ref, self(), Sequence, Payload},
    receive
        {bench_mailbox_ack, Ref, Sequence} ->
            Elapsed = erlang:monotonic_time(microsecond) - Start,
            mailbox_send_loop(Ref, Target, Payloads, Messages, Sequence + 1,
                              Total + Elapsed)
    after 60000 ->
        exit({mailbox_ack_timeout, Sequence})
    end.

collect_mailbox_workers(_Ref, [], Total) ->
    Total;
collect_mailbox_workers(Ref, Monitors, Total) ->
    receive
        {Ref, mailbox_worker_done, Pid, WorkerLatency} ->
            case lists:keytake(Pid, 1, Monitors) of
                {value, {_Pid, Monitor}, Remaining} ->
                    _ = erlang:demonitor(Monitor, [flush]),
                    collect_mailbox_workers(Ref, Remaining,
                                            Total + WorkerLatency);
                false ->
                    error({unexpected_mailbox_worker, Pid})
            end;
        {'DOWN', Monitor, process, Pid, Reason} ->
            case lists:keymember(Monitor, 2, Monitors) of
                true -> error({mailbox_worker_failed, Pid, Reason});
                false -> collect_mailbox_workers(Ref, Monitors, Total)
            end
    after 120000 ->
        error({mailbox_workers_timeout, length(Monitors)})
    end.

check_rpc(Node, Payload, Size) ->
    case rpc:call(Node, erlang, byte_size, [Payload], 60000) of
        Size ->
            ok;
        {badrpc, Reason} ->
            error({rpc_failed, Reason});
        Other ->
            error({unexpected_rpc_result, Other, Size})
    end.

make_payload(Size, compressible) ->
    binary:copy(<<"b">>, Size);
make_payload(Size, random) ->
    Pattern = list_to_binary([((Byte * 73 + Size * 19) band 16#ff)
                               || Byte <- lists:seq(0, 255)]),
    binary:part(binary:copy(Pattern, (Size + 255) div 256), 0, Size).

parse_args([], Options) ->
    {ok, Options};
parse_args(["--help" | _], _Options) ->
    help;
parse_args([Key, Value | Rest], Options) ->
    case parse_option(Key, Value, Options) of
        {ok, Updated} -> parse_args(Rest, Updated);
        Error -> Error
    end;
parse_args([Key], _Options) ->
    {error, {missing_value, Key}}.

parse_option("--suites", Value, Options) ->
    Values = comma_values(Value),
    case all_member(Values, ?SUITES) of
        true -> {ok, Options#{suites => Values}};
        false -> {error, {invalid_suites, Values, ?SUITES}}
    end;
parse_option("--compressions", Value, Options) ->
    Values = comma_values(Value),
    case lists:all(fun valid_compression/1, Values) of
        true -> {ok, Options#{compressions => Values}};
        false -> {error, {invalid_compressions, Values}}
    end;
parse_option("--chunk-sizes", Value, Options) ->
    parse_integer_list("--chunk-sizes", Value, 1, 65518,
                       fun(Values) -> Options#{chunk_sizes => Values} end);
parse_option("--small-sizes", Value, Options) ->
    parse_integer_list("--small-sizes", Value, 1, 65518,
                       fun(Values) -> Options#{small_sizes => Values} end);
parse_option("--mailbox-sizes", Value, Options) ->
    parse_integer_list("--mailbox-sizes", Value, 1, 65518,
                       fun(Values) -> Options#{mailbox_sizes => Values} end);
parse_option("--iterations", Value, Options) ->
    parse_integer("--iterations", Value, 1,
                  fun(Number) -> Options#{iterations => Number} end);
parse_option("--large-bytes", Value, Options) ->
    parse_integer("--large-bytes", Value, 1,
                  fun(Number) -> Options#{large_bytes => Number} end);
parse_option("--large-iterations", Value, Options) ->
    parse_integer("--large-iterations", Value, 1,
                  fun(Number) -> Options#{large_iterations => Number} end);
parse_option("--mailbox-workers", Value, Options) ->
    parse_integer("--mailbox-workers", Value, 1,
                  fun(Number) -> Options#{mailbox_workers => Number} end);
parse_option("--mailbox-messages", Value, Options) ->
    parse_integer("--mailbox-messages", Value, 1,
                  fun(Number) -> Options#{mailbox_messages => Number} end);
parse_option("--warmup", Value, Options) ->
    parse_integer("--warmup", Value, 0,
                  fun(Number) -> Options#{warmup => Number} end);
parse_option("--payload", "compressible", Options) ->
    {ok, Options#{payload => compressible}};
parse_option("--payload", "random", Options) ->
    {ok, Options#{payload => random}};
parse_option("--output", Value, Options) ->
    {ok, Options#{output => Value}};
parse_option(Key, _Value, _Options) ->
    {error, {unknown_option, Key}}.

parse_integer_list(Option, Value, Min, Max, Update) ->
    case parse_numbers(comma_values(Value), []) of
        {ok, Numbers} when Numbers =/= [] ->
            case lists:all(fun(N) -> N >= Min andalso N =< Max end, Numbers) of
                true -> {ok, Update(Numbers)};
                false -> {error, {out_of_range, Option, Min, Max}}
            end;
        _ -> {error, {invalid_integer_list, Option, Value}}
    end.

parse_integer(Option, Value, Min, Update) ->
    try list_to_integer(Value) of
        Number when Number >= Min -> {ok, Update(Number)};
        _ -> {error, {out_of_range, Option, Min}}
    catch
        error:badarg -> {error, {invalid_integer, Option, Value}}
    end.

parse_numbers([], Acc) -> {ok, lists:reverse(Acc)};
parse_numbers([Value | Rest], Acc) ->
    try list_to_integer(Value) of
        Number -> parse_numbers(Rest, [Number | Acc])
    catch
        error:badarg -> error
    end.

comma_values(Value) ->
    string:split(Value, ",", all).

all_member(Values, Allowed) ->
    Values =/= [] andalso lists:all(fun(Value) -> lists:member(Value, Allowed) end,
                                    Values).

valid_compression("none") -> true;
valid_compression("zlib:" ++ MinSize) ->
    try list_to_integer(MinSize) of
        Number -> Number >= 0 andalso Number =< 65518
    catch
        error:badarg -> false
    end;
valid_compression(_) -> false.

usage() ->
    io:format(standard_error,
              "Usage: tools/bouncer_bench [options]~n"
              "  --suites comma,list       Noise suites (default: all four)~n"
              "  --compressions comma,list none,zlib:N (default: none,zlib:256,zlib:1024)~n"
              "  --chunk-sizes comma,list  1..65518 (default: 1024,16384,65518)~n"
              "  --small-sizes comma,list  Small payload sizes (default: 32,256,1024)~n"
              "  --iterations N            Small round trips (default: 1000)~n"
              "  --large-bytes N           Bulk payload size (default: 1048576)~n"
              "  --large-iterations N      Bulk transfers (default: 16)~n"
              "  --mailbox-workers N       Concurrent sender processes (default: 8)~n"
              "  --mailbox-messages N      Messages per sender (default: 250)~n"
              "  --mailbox-sizes comma,list Tuple payload sizes (default: 32,128,1024)~n"
              "  --warmup N                Warmup calls per workload (default: 50)~n"
              "  --payload compressible|random (default: compressible)~n"
              "  --output FILE             Write CSV to FILE (default: stdout)~n",
              []).
