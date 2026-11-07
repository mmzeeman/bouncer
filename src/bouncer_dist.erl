%% Noise-authenticated Erlang distribution over TCP.
-module(bouncer_dist).

-export([
     listen/1,
     listen/2,
     accept/1,
     accept_connection/5,
     setup/5,
     close/1,
     select/1,
     address/0,
     is_node_name/1
]).

-export([
    do_accept/6,
    do_setup/6,

    start_reader/4,
    receive_data/4,

    controller_init/6,
    tick/1
]).

-include_lib("kernel/include/net_address.hrl").
-include_lib("kernel/include/dist_util.hrl").

-define(SETTINGS, {?MODULE, settings}).
-define(DRAIN_MAX_PACKETS, 64).
-define(SEND_BATCH_MAX, 262144).  %% 256 KiB per send call; Fixed for now.. tune with bouncer_bench

-spec listen(atom() | binary() | string()) -> term().
listen(Name) ->
    {ok, Host} = inet:gethostname(),
    listen(Name, Host).

-spec listen(atom() | binary() | string(), atom() | binary() | string()) -> term().
listen(Name, Host) ->
    NodeName = node_name(Name, Host),
    FlagSettings = argument_settings(),
    EnvSettings = environment_settings(),
    KeySettings = effective_key_settings(FlagSettings, EnvSettings, NodeName),
    case bouncer_keys:load_or_generate(NodeName, KeySettings) of
        {ok, Keys} ->
            case validate_settings(FlagSettings, EnvSettings, Keys, NodeName) of
                {ok, Settings} ->
                    persistent_term:put(?SETTINGS, Settings),
                    logger:notice("bouncer_dist: suite=~p accept_suites=~p fingerprint=~ts",
                                  [maps:get(suite, Settings),
                                   maps:get(accept_suites, Settings),
                                   bouncer_keys:fingerprint(Keys)]),
                    inet_tcp_dist:listen(Name, Host);
                {error, _} = Error ->
                    Error
            end;
        {error, _} = Error ->
            Error
    end.

-spec accept(term()) -> term().
accept(Listen) ->
    inet_tcp_dist:accept(Listen).

-spec accept_connection(pid(), term(), atom(), term(), term()) -> term().
accept_connection(AcceptPid, Socket, MyNode, Allowed, SetupTime) ->
    spawn_opt(?MODULE, do_accept,
              [self(), AcceptPid, Socket, MyNode, Allowed, SetupTime],
              dist_util:net_ticker_spawn_options()).

-spec do_accept(pid(), pid(), term(), atom(), term(), term()) -> term().
do_accept(Kernel, AcceptPid, Socket, MyNode, Allowed, SetupTime) ->
    receive
        {AcceptPid, controller} ->
            case settings() of
                {ok, Settings} ->
                    case inet:setopts(Socket, socket_options(Settings)) of
                        ok ->
                            accept_handshake(Kernel, Socket, MyNode, Allowed,
                                             SetupTime, Settings);
                        {error, Reason} ->
                            stop_connection(MyNode, {socket_options, Reason})
                    end;
                {error, Reason} ->
                    stop_connection(MyNode, Reason)
            end;
        {'EXIT', _From, Reason} ->
            stop_connection(MyNode, {accept_handover_failed, Reason})
    end.

accept_handshake(Kernel, Socket, MyNode, Allowed, SetupTime, #{ keys := Keys, node_name := OwnName, hs_opts := HsOptions } = Settings) ->
    Timer = dist_util:start_timer(SetupTime),
    case bouncer_hs:respond(Socket, OwnName, Keys, HsOptions) of
        {ok, Result} ->
            start_dist_handshake(Kernel, Socket, MyNode, undefined, Allowed, Timer, Settings, Result, responder);
        {error, Reason} ->
            stop_connection(MyNode, {noise_handshake, Reason})
    end.

-spec setup(atom(), atom(), atom(), boolean(), term()) -> term().
setup(Node, Type, MyNode, LongOrShortNames, SetupTime) ->
    spawn_opt(?MODULE, do_setup,
              [self(), Node, Type, MyNode, LongOrShortNames, SetupTime],
              dist_util:net_ticker_spawn_options()).

-spec do_setup(pid(), atom(), atom(), atom(), boolean(), term()) -> term().
do_setup(Kernel, Node, Type, MyNode, LongOrShortNames, SetupTime) ->
    case settings() of
        {ok, Settings} ->
            setup_connection(Kernel, Node, Type, MyNode, LongOrShortNames,
                             SetupTime, Settings);
        {error, Reason} ->
            stop_connection(Node, Reason)
    end.

setup_connection(Kernel, Node, Type, MyNode, LongOrShortNames, SetupTime,
                 Settings) ->
    Timer = dist_util:start_timer(SetupTime),
    try inet_tcp_dist:fam_setup(inet, Node, LongOrShortNames,
                                fun inet:parse_address/1) of
        {#net_address{address = {Ip, Port}} = NetAddress, _ConnectOptions, Version} ->
            dist_util:reset_timer(Timer),
            case gen_tcp:connect(Ip, Port, socket_options(Settings)) of
                {ok, Socket} ->
                    InitiateOpts = maps:get(hs_opts, Settings),
                    TargetName = atom_to_binary(Node, utf8),
                    case bouncer_hs:initiate(Socket, TargetName,
                                             maps:get(keys, Settings),
                                             InitiateOpts) of
                        {ok, Result} ->
                            start_dist_handshake(Kernel, Socket, MyNode, Node, undefined, Timer, Settings, Result, {initiator, NetAddress, Type, Version});
                        {error, Reason} ->
                            stop_connection(Node, {noise_handshake, Reason})
                    end;
                {error, Reason} ->
                    stop_connection(Node, {connect, Reason})
            end
    catch
        exit:Reason ->
            stop_connection(Node, {address_lookup, Reason});
        error:Reason ->
            stop_connection(Node, {address_lookup, Reason})
    end.

start_dist_handshake(Kernel, Socket, MyNode, OtherNode, Allowed, Timer, Settings, Result, Role) ->
    case initialize_controller(Socket, Result, Settings, Role) of
        {ok, Controller, Reader} ->
            HSData0 = #hs_data{
                         kernel_pid = Kernel,
                         other_node = OtherNode,
                         this_node = MyNode,
                         socket = Controller,
                         timer = Timer,
                         this_flags = 0,
                         allowed = Allowed,
                         f_send = send_fun(Controller),
                         f_recv = recv_fun(Controller, Reader, Result, Role),
                         f_setopts_pre_nodeup = fun(_Ctrl) -> ok end,
                         f_setopts_post_nodeup = fun(_Ctrl) -> ok end,
                         f_getll = fun(Ctrl) -> {ok, Ctrl} end,
                         f_address = address_fun(Socket),
                         mf_tick = fun ?MODULE:tick/1,
                         mf_getstat = getstats_fun(Controller, Socket),
                         mf_setopts = setopts_fun(Controller, Socket),
                         mf_getopts = getopts_fun(Controller, Socket),
                         f_handshake_complete = fun(Ctrl, _Node, DHandle) ->
                                     handshake_complete(Ctrl, Reader, DHandle)
                             end},
            case Role of
                responder ->
                    dist_util:handshake_other_started(HSData0);
                {initiator, NetAddress, Type, Version} ->
                    HSData = HSData0#hs_data{
                               other_node = OtherNode,
                               other_version = Version,
                               f_address = fun(_Ctrl, _Node) -> NetAddress end,
                               request_type = Type},
                    dist_util:handshake_we_started(HSData)
            end;
        {error, Reason} ->
            stop_connection(OtherNode, {controller_setup, Reason})
    end.

initialize_controller(Socket, Result, Settings, Role) ->
    try
        #{send := Send, recv := Recv} = Result,
        #{sender_policy := SP, receiver_policy := RP} = Settings,

        Sender = bouncer_protocol:new_sender(Send, SP),
        Receiver = bouncer_protocol:new_receiver(Recv, RP),

        Ref = make_ref(),
        Controller = spawn_opt(?MODULE, controller_init,
                               [self(), Ref, Socket, Receiver, Sender, {Role, maps:get(node_name, Settings)}],
                               [link, {priority, max}, {message_queue_data, off_heap}]),

        receive
            {Ref, {ok, Controller, Reader}} ->
                case gen_tcp:controlling_process(Socket, Reader) of
                    ok ->
                        {ok, Controller, Reader};
                    {error, Reason} ->
                        exit(Controller, kill),
                        {error, {controlling_process, Reason}}
                end
        after 5000 ->
            exit(Controller, kill),
            {error, controller_start_timeout}
        end
    catch
        error:ControllerReason -> {error, ControllerReason}
    end.

-spec controller_init(pid(), reference(), inet:socket(), bouncer_protocol:receiver(),
                      bouncer_protocol:sender(), {atom(), binary()}) -> no_return().
controller_init(Parent, Ref, Socket, Receiver, Sender, {Role, OwnName}) ->
    process_flag(trap_exit, true),

    Reader = spawn_opt(?MODULE, start_reader,
                       [Socket, Receiver, Role, OwnName],
                       [link, {priority, max}, {message_queue_data, off_heap}]),

    Sender1 = bouncer_protocol:tx_start(Sender),
    Parent ! {Ref, {ok, self(), Reader}},
    controller_loop(Socket, OwnName, Reader, Sender1, undefined).

-spec controller_loop(inet:socket(), binary(), pid(), bouncer_protocol:sender(),
                      undefined | erlang:dist_handle()) -> no_return().
controller_loop(Socket, OwnName, Reader, Sender, undefined) ->
    receive
        {send_packet, From, Ref, Packet} ->
            case write_packet(Socket, Sender, Packet) of
                {ok, Sender1} ->
                    From ! {Ref, ok},
                    controller_loop(Socket, OwnName, Reader, Sender1, undefined);
                {error, Reason} ->
                    From ! {Ref, {error, Reason}},
                    log_io_error(OwnName, {send, Reason}),
                    gen_tcp:close(Socket),
                    exit({send_error, Reason})
            end;
        tick ->
            case send_tick(Socket, Sender) of
                {ok, Sender1} ->
                    controller_loop(Socket, OwnName, Reader, Sender1, undefined);
                {error, Reason} ->
                    log_io_error(OwnName, {tick, Reason}),
                    gen_tcp:close(Socket),
                    exit({send_error, Reason})
            end;
        {handshake_complete, From, Ref, Reader, DHandle} ->
            ok = erlang:dist_ctrl_input_handler(DHandle, Reader),
            Reader ! {data_phase, DHandle},
            erlang:dist_ctrl_get_data_notification(DHandle),
            From ! {Ref, ok},
            controller_loop(Socket, OwnName, Reader, Sender, DHandle);
        {'EXIT', _Pid, Reason} ->
            gen_tcp:close(Socket),
            exit({controller_child_exit, Reason})
    end;
controller_loop(Socket, OwnName, Reader, Sender, DHandle) ->
    receive
        dist_data ->
            controller_drain(Socket, OwnName, Reader, Sender, DHandle, 0);
        tick ->
            case send_tick(Socket, Sender) of
                {ok, Sender1} ->
                    controller_loop(Socket, OwnName, Reader, Sender1, DHandle);
                {error, Reason} ->
                    log_io_error(OwnName, {tick, Reason}),
                    gen_tcp:close(Socket),
                    exit({send_error, Reason})
            end;
        %{info, Ref, Pid} ->
        %    Pid ! {Ref, {inet:getstat(Socket),
        %                 inet:peername(Socket)
        %                }},
        %    controller_loop(Socket, OwnName, Reader, Sender, DHandle);
        {'EXIT', _Pid, Reason} ->
            gen_tcp:close(Socket),
            exit({controller_child_exit, Reason})
    end.


controller_drain(Socket, OwnName, Reader, Sender, DHandle, Count) ->
    drain_batch(Socket, OwnName, Reader, Sender, DHandle, [], 0, Count).

%% Pending: encrypted frames not yet written, in reverse order.
%% PendingBytes: total byte size of Pending.
drain_batch(Socket, OwnName, Reader, Sender, DHandle, Pending, PendingBytes, Count) ->
    case erlang:dist_ctrl_get_data(DHandle) of
        none ->
            %% Re-arm the VM notification first; it may queue more data
            %% while we are writing the batch to the socket.
            erlang:dist_ctrl_get_data_notification(DHandle),
            case send_frames(Socket, Pending) of
                ok ->
                    controller_loop(Socket, OwnName, Reader, Sender, DHandle);
                {error, Reason} ->
                    drain_send_failed(Socket, OwnName, Reason)
            end;
        Packet ->
            case tx_frames(Socket, Sender, Packet, Pending, PendingBytes) of
                {ok, Sender1, Pending1, PendingBytes1}
                  when PendingBytes1 >= ?SEND_BATCH_MAX ->
                    %% Byte cap reached: write the batch out and keep draining.
                    case send_frames(Socket, Pending1) of
                        ok ->
                            drain_batch(Socket, OwnName, Reader, Sender1,
                                        DHandle, [], 0, Count + 1);
                        {error, Reason} ->
                            drain_send_failed(Socket, OwnName, Reason)
                    end;
                {ok, Sender1, Pending1, _}
                  when Count + 1 >= ?DRAIN_MAX_PACKETS ->
                    %% Packet cap reached: flush, then yield to other
                    %% messages (tick, EXIT) exactly as before,
                    %% and continue with a fresh drain via self() ! dist_data.
                    case send_frames(Socket, Pending1) of
                        ok ->
                            self() ! dist_data,
                            controller_loop(Socket, OwnName, Reader,
                                            Sender1, DHandle);
                        {error, Reason} ->
                            drain_send_failed(Socket, OwnName, Reason)
                    end;
                {ok, Sender1, Pending1, PendingBytes1} ->
                    drain_batch(Socket, OwnName, Reader, Sender1, DHandle,
                                Pending1, PendingBytes1, Count + 1);
                {error, Reason} ->
                    drain_send_failed(Socket, OwnName, Reason)
            end
    end.

-spec write_packet(inet:socket(), bouncer_protocol:sender(), iodata()) ->
          {ok, bouncer_protocol:sender()} | {error, term()}.
write_packet(Socket, Sender, Packet) ->
    case tx_frames(Socket, Sender, Packet, [], 0) of
        {ok, Sender1, Pending, _PendingBytes} ->
            case send_frames(Socket, Pending) of
                ok ->
                    {ok, Sender1};
                {error, Reason} ->
                    {error, Reason}
            end;
        {error, Reason} ->
            {error, Reason}
    end.

tx_frames(Socket, Sender, Packet, Pending, PendingBytes) ->
    try bouncer_protocol:tx_packet(Packet) of
        Tx ->
            tx_next_frames(Socket, Sender, Tx, Pending, PendingBytes)
    catch
        error:Reason ->
            {error, Reason}
    end.

tx_next_frames(Socket, Sender, Tx, Acc, Bytes) ->
    case bouncer_protocol:tx_next(Sender, Tx) of
        {Frame, Sender1, more, Tx1} ->
            Acc1 = [Frame | Acc],
            Bytes1 = Bytes + erlang:iolist_size(Frame),
            case Bytes1 >= ?SEND_BATCH_MAX of
                true ->
                    case send_frames(Socket, Acc1) of
                        ok ->
                            tx_next_frames(Socket, Sender1, Tx1, [], 0);
                        {error, Reason} ->
                            {error, Reason}
                    end;
                false ->
                    tx_next_frames(Socket, Sender1, Tx1, Acc1, Bytes1)
            end;
        {Frame, Sender1, done} ->
            {ok, Sender1, [Frame | Acc], Bytes + erlang:iolist_size(Frame)}
    end.

drain_send_failed(Socket, OwnName, Reason) ->
    log_io_error(OwnName, {send, Reason}),
    gen_tcp:close(Socket),
    exit({send_error, Reason}).

-spec start_reader(inet:socket(), bouncer_protocol:receiver(), term(), binary()) -> term().
start_reader(Socket, Receiver0, Role, OwnName) ->
    Receiver = bouncer_protocol:rx_start(Receiver0),
    reader_loop(Socket, Receiver, Role, OwnName, []).

reader_loop(Socket, Receiver, Role, OwnName, Events) ->
    receive
        {read, From, Ref, Timeout} ->
            read_handshake(Socket, Receiver, Role, OwnName, From, Ref, Timeout, Events);
        {data_phase, DHandle} ->
            deliver_events(Events, DHandle),
            ?MODULE:receive_data(Socket, Receiver, DHandle, OwnName)
    end.

read_handshake(Socket, Receiver, Role, OwnName, From, Ref, Timeout, Events) ->
    case take_packet(Events) of
        {packet, Data, Rest} ->
            From ! {Ref, {ok, Data}},
            reader_loop(Socket, Receiver, Role, OwnName, Rest);
        {none, Rest} ->
            case gen_tcp:recv(Socket, 0, Timeout) of
                {ok, Bytes} ->
                    case bouncer_protocol:rx_feed(Receiver, Bytes) of
                        {ok, NewEvents, Receiver1} ->
                            read_handshake(Socket, Receiver1, Role, OwnName,
                                           From, Ref, Timeout, Rest ++ NewEvents);
                        {error, Reason, _Dead} ->
                            log_rx_error(OwnName, Reason),
                            gen_tcp:close(Socket),
                            From ! {Ref, {error, Reason}},
                            exit({receive_error, Reason})
                    end;
                {error, Reason} ->
                    log_io_error(OwnName, {'receive', Reason}),
                    From ! {Ref, {error, Reason}},
                    wait_for_caller(From),
                    exit({receive_error, Reason})
            end
    end.

%% Exiting at once would propagate through the links and kill the caller
%% before it has handled the error, so it could not log the failure.
wait_for_caller(From) ->
    Monitor = erlang:monitor(process, From),
    receive
        {'DOWN', Monitor, process, From, _} -> ok
    after 5000 ->
            erlang:demonitor(Monitor, [flush])
    end.

take_packet([]) ->
    {none, []};
take_packet([tick | Rest]) ->
    take_packet(Rest);
take_packet([{packet, Data} | Rest]) ->
    {packet, iolist_to_binary(Data), Rest}.

-spec receive_data(inet:socket(), bouncer_protocol:receiver(), erlang:dist_handle(),
                   binary()) -> term().
receive_data(Socket, Receiver, DHandle, OwnName) ->
    case gen_tcp:recv(Socket, 0, infinity) of
        {ok, Bytes} ->
            case bouncer_protocol:rx_feed(Receiver, Bytes) of
                {ok, Events, Receiver1} ->
                    deliver_events(Events, DHandle),
                    ?MODULE:receive_data(Socket, Receiver1, DHandle, OwnName);
                {error, Reason, _Dead} ->
                    log_rx_error(OwnName, Reason),
                    gen_tcp:close(Socket),
                    exit({receive_error, Reason})
            end;
        {error, Reason} ->
            log_io_error(OwnName, {'receive', Reason}),
            gen_tcp:close(Socket),
            exit({receive_error, Reason})
    end.

deliver_events([], _DHandle) ->
    ok;
deliver_events([{packet, Data} | Rest], DHandle) ->
    erlang:dist_ctrl_put_data(DHandle, Data),
    deliver_events(Rest, DHandle);
deliver_events([tick | Rest], DHandle) ->
    %% An empty distribution-controller input mirrors the example's empty TCP tick packet.
    erlang:dist_ctrl_put_data(DHandle, <<>>),
    deliver_events(Rest, DHandle).

send_frames(_Socket, []) ->
    ok;
send_frames(Socket, [Frame]) ->
    gen_tcp:send(Socket, Frame);
send_frames(Socket, Frames) ->
    gen_tcp:send(Socket, lists:reverse(Frames)).

send_tick(Socket, Sender) ->
    {Frame, Sender1} = bouncer_protocol:tx_tick(Sender),
    case gen_tcp:send(Socket, Frame) of
        ok -> {ok, Sender1};
        {error, Reason} -> {error, Reason}
    end.

handshake_complete(Controller, Reader, DHandle) ->
    Ref = make_ref(),
    Controller ! {handshake_complete, self(), Ref, Reader, DHandle},
    receive
        {Ref, ok} -> ok;
        {Ref, {error, Reason}} -> exit({input_handler_setup, Reason});
        {'EXIT', Controller, Reason} -> exit({controller_exit, Reason})
    end.

send_fun(Controller) ->
    fun(Ctrl, Packet) when Ctrl =:= Controller ->
            Ref = make_ref(),
            Monitor = erlang:monitor(process, Controller),
            Controller ! {send_packet, self(), Ref, Packet},
            receive
                {Ref, Result} ->
                    erlang:demonitor(Monitor, [flush]),
                    Result;
                {'DOWN', Monitor, process, Controller, Reason} ->
                    {error, {controller_exit, Reason}}
            end
    end.

recv_fun(Controller, Reader, Result, Role) ->
    fun(Ctrl, _Length, Timeout) when Ctrl =:= Controller ->
            Ref = make_ref(),
            Monitor = erlang:monitor(process, Reader),
            Reader ! {read, self(), Ref, Timeout},
            receive
                {Ref, {ok, Packet}} ->
                    erlang:demonitor(Monitor, [flush]),
                    do_packet(Role, Packet, Result);
                {Ref, {error, closed}} ->
                    erlang:demonitor(Monitor, [flush]),
                    maybe_log_unauthorized(Role, Result),
                    {error, closed};
                {Ref, {error, Reason}} ->
                    erlang:demonitor(Monitor, [flush]),
                    {error, Reason};
                {'DOWN', Monitor, process, Reader, Reason} ->
                    {error, {reader_exit, Reason}}
            end
    end.

%% Verify the expected name with the name from the handshake from dist_utils
do_packet(responder, <<$N, _Flags:64, _Creation:32, Len:16, Name:Len/binary, _/binary>> = Packet, Result) ->
    do_expected_name_check(maps:get(remote_name, Result), Name, Packet);
do_packet(responder, <<$n, _Version:16, _Flags:32, Name/binary>> = Packet, Result) ->
    do_expected_name_check(maps:get(remote_name, Result), Name, Packet);
do_packet(_Role, Packet, _Result) ->
    {ok, binary_to_list(Packet)}.

do_expected_name_check(Expected, Expected, Packet) ->
    {ok, binary_to_list(Packet)};
do_expected_name_check(Expected, Actual, _Packet) ->
    {error, {authenticated_name_mismatch, Expected, Actual}}.

maybe_log_unauthorized({initiator, _NetAddress, _Type, _Version}, Result) ->
    Fingerprint = bouncer_keys:fingerprint(maps:get(keys, settings_value())),
    logger:warning("peer closed the connection during handshake; our key is probably not authorized there: ~p ~ts",
                   [maps:get(remote_name, Result), Fingerprint]);
maybe_log_unauthorized(_, _) ->
    ok.


settings_value() ->
    {ok, Settings} = settings(),
    Settings.

-spec tick(pid()) -> ok.
tick(Controller) when is_pid(Controller) ->
    Controller ! tick,
    ok.

getstats_fun(Controller, Socket) ->
    fun(C) when C =:= Controller ->
        case inet:getstat(Socket, [recv_cnt, send_cnt, send_pend]) of
            {ok, Stat} ->
                {ok, proplists:get_value(recv_cnt, Stat, 0),
                     proplists:get_value(send_cnt, Stat, 0),
                     proplists:get_value(send_pend, Stat, 0)};
            Error ->
                Error
        end
    end.

setopts_fun(Controller, Socket) ->
    fun(C, Opts) when C =:= Controller->
            case
                [Opt || {K, _}=Opt <- Opts,
                        K =:= active
                        orelse K =:= deliver
                        orelse K =:= packet]
            of
                [] ->
                    inet:setopts(Socket, Opts);
                Opts1 ->
                    {error, {badopts,Opts1}}
            end
    end.

getopts_fun(Controller, Socket) ->
    fun(C, Opts) when C =:= Controller ->
        inet:getopts(Socket, Opts)
    end.
            
address_fun(Socket) ->
    fun(_Controller, Node) ->
            case inet:peername(Socket) of
                {ok, Address} ->
                    Host = case dist_util:split_node(Node) of
                               {node, _Name, PeerHost} -> PeerHost;
                               _ -> ""
                           end,
                    #net_address{address = Address, host = Host,
                                 protocol = tcp, family = inet};
                {error, _} ->
                    dist_util:shutdown(?MODULE, ?LINE, no_node)
            end
    end.

-spec close(term()) -> term().
close(Listen) ->
    inet_tcp_dist:close(Listen).

-spec select(atom()) -> term().
select(Node) ->
    inet_tcp_dist:select(Node).

-spec address() -> term().
address() ->
    inet_tcp_dist:address().

-spec is_node_name(term()) -> boolean().
is_node_name(Node) ->
    inet_tcp_dist:is_node_name(Node).

-spec stop_connection(term(), term()) -> no_return().
stop_connection(Node, Reason) ->
    Fingerprint = case settings() of
                      {ok, Settings} ->
                          bouncer_keys:fingerprint(maps:get(keys, Settings));
                      _ ->
                          "unavailable"
                  end,
    logger:warning("bouncer_dist: connection failed node=~p fingerprint=~ts reason=~p",
                   [Node, Fingerprint, Reason]),
    dist_util:shutdown(?MODULE, ?LINE, {Node, Reason}).

log_rx_error(NodeName, Reason) ->
    logger:warning("bouncer_dist: receive failed node=~ts fingerprint=~ts reason=~p",
                   [NodeName, identity_fingerprint(), Reason]).

log_io_error(NodeName, Reason) ->
    logger:warning("bouncer_dist: transport failed node=~ts fingerprint=~ts reason=~p",
                   [NodeName, identity_fingerprint(), Reason]).

identity_fingerprint() ->
    case settings() of
        {ok, Settings} ->
            bouncer_keys:fingerprint(maps:get(keys, Settings));
        _ ->
            "unavailable"
    end.

socket_options(Settings) ->
    [binary,
     {packet, 0},
     {active, false},
     {nodelay, true},
     {sndbuf, 262144},
     {recbuf, 262144},
     {buffer, 262144},
     {send_timeout, maps:get(send_timeout_ms, Settings)},
     {send_timeout_close, true}].

settings() ->
    case persistent_term:get(?SETTINGS, undefined) of
        undefined ->
            {error, settings_not_initialized};
        Settings ->
            {ok, Settings}
    end.

node_name(Name, Host) ->
    NameBin = to_binary(Name),
    HostBin = to_binary(Host),
    <<NameBin/binary, "@", HostBin/binary>>.

to_binary(Value) when is_atom(Value) ->
    atom_to_binary(Value, utf8);
to_binary(Value) when is_binary(Value) ->
    Value;
to_binary(Value) when is_list(Value) ->
    unicode:characters_to_binary(Value).

argument_settings() ->
    case init:get_argument(bouncer) of
        {ok, Groups} ->
            lists:foldl(fun add_argument_group/2, #{}, Groups);
        error ->
            #{}
    end.

add_argument_group(Group, Acc) ->
    add_argument_pairs(Group, Acc).

add_argument_pairs([Key, Value | Rest], Acc) ->
    Acc1 = case maps:is_key(Key, Acc) of
               true -> Acc;
               false -> maps:put(Key, Value, Acc)
           end,
    add_argument_pairs(Rest, Acc1);
add_argument_pairs(_, Acc) ->
    Acc.

environment_settings() ->
    Keys = ["dir", "generate", "authorized_dirs", "chunk_size", "padding",
            "compression", "rekey_after", "max_packet", "accept_compression",
            "max_bytes_without_rekey", "handshake_timeout_ms", "suite",
            "accept_suites", "max_pending", "send_timeout_ms"],
    lists:foldl(fun(Key, Acc) ->
                        case os:getenv("BOUNCER_" ++ string:uppercase(Key)) of
                            false -> Acc;
                            "" -> Acc;
                            Value -> maps:put(Key, Value, Acc)
                        end
                end, #{}, Keys).

key_option_settings(Flags, Env) ->
    lists:foldl(fun({StringKey, AtomKey}, Acc) ->
                        case effective(StringKey, Flags, Env, undefined) of
                            undefined -> Acc;
                            Value -> maps:put(AtomKey, Value, Acc)
                        end
                end, #{}, [{"dir", dir}, {"generate", generate},
                           {"authorized_dirs", authorized_dirs}]).

effective_key_settings(Flags, Env, NodeName) ->
    maps:merge(#{node_name => NodeName},
               key_option_settings(Flags, Env)).

validate_settings(Flags, Env, Keys, NodeName) ->
    Opts = #{},
    Layers = [Opts, policy_layer(Flags), policy_layer(Env)],
    case {bouncer_protocol:sender_policy(Layers),
          bouncer_protocol:receiver_policy(Layers),
          carrier_values(Flags, Env, NodeName, Keys)}
    of
        {{ok, SenderPolicy}, {ok, ReceiverPolicy}, {ok, Carrier}} ->
            {ok, Carrier#{sender_policy => SenderPolicy,
                          receiver_policy => ReceiverPolicy}};
        {{error, Reason}, _, _} -> {error, Reason};
        {_, {error, Reason}, _} -> {error, Reason};
        {_, _, {error, _} = Error} -> Error
    end.

carrier_values(Flags, Env, NodeName, Keys) ->
    Values = [{handshake_timeout_ms, effective("handshake_timeout_ms", Flags, Env,
                                                "5000"), 5000,
               "a positive integer"},
              {send_timeout_ms, effective("send_timeout_ms", Flags, Env, "30000"),
               30000, "a positive integer"},
              {max_pending, effective("max_pending", Flags, Env, "64"), 64,
               "a positive integer"}],
    case parse_positive_values(Values, #{}) of
        {ok, Parsed} ->
            case parse_suite(effective("suite", Flags, Env, "aesgcm_sha512")) of
                {ok, Suite} ->
                    case parse_suites(effective("accept_suites", Flags, Env,
                                                "aesgcm_sha512")) of
                        {ok, AcceptSuites} ->
                            KeyOptions = key_option_settings(Flags, Env),
                            HsOpts = maps:merge(
                                       Parsed#{own_name => NodeName, suite => Suite,
                                               accept_suites => AcceptSuites,
                                               node_name => NodeName},
                                       KeyOptions),
                            {ok, #{keys => Keys, node_name => NodeName,
                                   suite => Suite, accept_suites => AcceptSuites,
                                   hs_opts => HsOpts,
                                   send_timeout_ms => maps:get(send_timeout_ms,
                                                               Parsed)}};
                        {error, _} = Error -> Error
                    end;
                {error, _} = Error -> Error
            end;
        {error, _} = Error -> Error
    end.

parse_positive_values([], Acc) ->
    {ok, Acc};
parse_positive_values([{Key, Value, Default, Allowed} | Rest], Acc) ->
    case positive_integer(Value) of
        {ok, Integer} ->
            parse_positive_values(Rest, maps:put(Key, Integer, Acc));
        error ->
            case Value of
                undefined ->
                    parse_positive_values(Rest, maps:put(Key, Default, Acc));
                _ ->
                    {error, {invalid_setting, Key, Value, Allowed}}
            end
    end.

positive_integer(Value) when is_integer(Value), Value > 0 ->
    {ok, Value};
positive_integer(Value) when is_list(Value); is_binary(Value) ->
    try string:to_integer(to_list(Value)) of
        {Integer, ""} when Integer > 0 -> {ok, Integer};
        _ -> error
    catch
        _:_ -> error
    end;
positive_integer(_) ->
    error.

parse_suite(Value) ->
    case suite_atom(Value) of
        {ok, _} = Ok -> Ok;
        error ->
            {error, {invalid_setting, suite, Value,
                     "chachapoly_blake2b | aesgcm_sha512 | aesgcm_sha256 | aesgcm_blake2b"}}
    end.

parse_suites(Value) when is_list(Value), Value =/= [], is_atom(hd(Value)) ->
    case lists:all(fun(S) -> suite_atom(S) =/= error end, Value) of
        true -> {ok, Value};
        false -> invalid_suites(Value)
    end;
parse_suites(Value) when is_list(Value); is_binary(Value) ->
    Names = [string:trim(Name) || Name <- string:split(to_list(Value), ",", all)],
    case Names =/= [] andalso lists:all(fun(Name) -> Name =/= "" end, Names) of
        true ->
            case [Suite || Name <- Names, {ok, Suite} <- [suite_atom(Name)]] of
                Suites when length(Suites) =:= length(Names) -> {ok, Suites};
                _ -> invalid_suites(Value)
            end;
        false -> invalid_suites(Value)
    end;
parse_suites(Value) ->
    invalid_suites(Value).

suite_atom(chachapoly_blake2b) -> {ok, chachapoly_blake2b};
suite_atom(aesgcm_sha512) -> {ok, aesgcm_sha512};
suite_atom(aesgcm_sha256) -> {ok, aesgcm_sha256};
suite_atom(aesgcm_blake2b) -> {ok, aesgcm_blake2b};
suite_atom("chachapoly_blake2b") -> {ok, chachapoly_blake2b};
suite_atom("aesgcm_sha512") -> {ok, aesgcm_sha512};
suite_atom("aesgcm_sha256") -> {ok, aesgcm_sha256};
suite_atom("aesgcm_blake2b") -> {ok, aesgcm_blake2b};
suite_atom(<<"chachapoly_blake2b">>) -> {ok, chachapoly_blake2b};
suite_atom(<<"aesgcm_sha512">>) -> {ok, aesgcm_sha512};
suite_atom(<<"aesgcm_sha256">>) -> {ok, aesgcm_sha256};
suite_atom(<<"aesgcm_blake2b">>) -> {ok, aesgcm_blake2b};
suite_atom(_) -> error.

invalid_suites(Value) ->
    {error, {invalid_setting, accept_suites, Value,
             "comma-separated suite names from chachapoly_blake2b, aesgcm_sha512, aesgcm_sha256, aesgcm_blake2b"}}.

effective(Key, Flags, Env, Default) ->
    case maps:find(Key, Flags) of
        {ok, Value} -> Value;
        error ->
            case maps:find(Key, Env) of
                {ok, Value} -> Value;
                error -> Default
            end
    end.

policy_layer(Settings) ->
    lists:foldl(fun({StringKey, AtomKey}, Acc) ->
                        case maps:find(StringKey, Settings) of
                            {ok, Value} -> maps:put(AtomKey, Value, Acc);
                            error -> Acc
                        end
                end, #{},
                [{"chunk_size", chunk_size},
                 {"padding", padding},
                 {"compression", compression},
                 {"rekey_after", rekey_after},
                 {"max_packet", max_packet},
                 {"accept_compression", accept_compression},
                 {"max_bytes_without_rekey", max_bytes_without_rekey}]).

to_list(Value) when is_binary(Value) ->
    unicode:characters_to_list(Value);
to_list(Value) when is_list(Value) ->
    Value.
