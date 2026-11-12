%% Noise-authenticated Erlang distribution over TCP.
-module(noisegate_dist).

-export([
    childspecs/0,
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
    accept_loop/3,
    do_accept/6,
    do_accept/7,
    do_setup/6,

    start_reader/4,
    receive_data/4,

    controller_init/3,
    tick/1
]).

-include_lib("kernel/include/net_address.hrl").
-include_lib("kernel/include/dist_util.hrl").

-define(DRAIN_MAX_PACKETS, 64).
-define(SEND_BATCH_MAX, 262144).  %% 256 KiB per send call; Fixed for now.. tune with noisegate_bench

-record(controller_state, {
    socket    :: inet:socket(),
    role      :: responder | initiator,
    own_name  :: binary(),

    receiver  :: noisegate_protocol:receiver(),
    sender    :: noisegate_protocol:sender(),

    reader_pid :: undefined | pid(),

    dhandle    :: undefined | erlang:dist_handle()
}).

-spec listen(atom() | binary() | string()) -> term().
listen(Name) ->
    {ok, Host} = inet:gethostname(),
    listen(Name, Host).

-spec listen(atom() | binary() | string(), atom() | binary() | string()) -> term().
listen(Name, Host) ->
    NodeName = node_name(Name, Host),
    case noisegate_dist_config:configure_node(NodeName) of
        ok ->
            inet_tcp_dist:listen(Name, Host);
        {error, _} = Error ->
            Error
    end.

childspecs() ->
    noisegate_dist_sup:childspecs().

-spec accept(term()) -> term().
accept(ListenSocket) ->
    case noisegate_dist_config:connection_settings() of
        {ok, Settings} ->
            spawn_opt(?MODULE, accept_loop, [self(), ListenSocket, Settings],
                      [link, {priority, max}]);
        {error, Reason} ->
            exit(Reason)
    end.

accept_loop(Kernel, ListenSocket, Settings) ->
    case gen_tcp:accept(ListenSocket) of
        {ok, Socket} ->
            Kernel ! {accept, self(), Socket, inet, tcp},
            Settings1 = accept_controller(Kernel, Socket, Settings),
            accept_loop(Kernel, ListenSocket, Settings1);
        Error ->
            exit(Error)
    end.

accept_controller(Kernel, Socket, Settings) ->
    receive
        {noisegate_settings_request, Pid} ->
            case noisegate_dist_config:connection_settings() of
                {ok, CurrentSettings} ->
                    Pid ! {noisegate_settings, self(), CurrentSettings},
                    accept_controller(Kernel, Socket, CurrentSettings);
                {error, Reason} ->
                    Pid ! {noisegate_settings_error, self(), Reason},
                    accept_controller(Kernel, Socket, Settings)
            end;
        {Kernel, controller, Pid} ->
            case gen_tcp:controlling_process(Socket, Pid) of
                ok ->
                    Pid ! {self(), controller},
                    Settings;
                {error, Reason} ->
                    Pid ! {self(), exit},
                    exit({controlling_process, Reason})
            end;
        {Kernel, unsupported_protocol} ->
            exit(unsupported_protocol)
    end.

-spec accept_connection(pid(), term(), atom(), term(), term()) -> term().
accept_connection(AcceptPid, Socket, MyNode, Allowed, SetupTime) ->
    AcceptPid ! {noisegate_settings_request, self()},
    Settings =
        receive
            {noisegate_settings, AcceptPid, Settings0} ->
                {ok, Settings0};
            {noisegate_settings_error, AcceptPid, Reason} ->
                {error, Reason}
        after SetupTime ->
            {error, settings_not_initialized}
        end,
    spawn_opt(?MODULE, do_accept,
              [self(), AcceptPid, Socket, MyNode, Allowed, SetupTime, Settings],
              dist_util:net_ticker_spawn_options()).

-spec do_accept(pid(), pid(), term(), atom(), term(), term()) -> term().
do_accept(Kernel, AcceptPid, Socket, MyNode, Allowed, SetupTime) ->
    do_accept(Kernel, AcceptPid, Socket, MyNode, Allowed, SetupTime,
              noisegate_dist_config:connection_settings()).

-spec do_accept(pid(), pid(), term(), atom(), term(), term(), term()) -> term().
do_accept(Kernel, AcceptPid, Socket, MyNode, Allowed, SetupTime, SettingsResult) ->
    receive
        {AcceptPid, controller} ->
            case SettingsResult of
                {ok, Settings} ->
                    case noisegate_dist_config:key_info() of
                        {ok, Keys} ->
                            do_accept_socket(Kernel, Socket, MyNode,
                                             Allowed, SetupTime,
                                             Settings, Keys);
                        {error, Reason} ->
                            stop_connection(MyNode, Reason)
                    end;
                {error, Reason} ->
                    stop_connection(MyNode, Reason)
            end;
        {'EXIT', _From, Reason} ->
            stop_connection(MyNode, {accept_handover_failed, Reason})
    end.

do_accept_socket(Kernel, Socket, MyNode, Allowed, SetupTime, Settings, Keys) ->
    case inet:setopts(Socket, socket_options(Settings)) of
        ok ->
            accept_handshake(Kernel, Socket, MyNode, Allowed,
                             SetupTime, Settings, Keys);
        {error, Reason} ->
            stop_connection(MyNode, {socket_options, Reason})
    end.

accept_handshake(Kernel, Socket, MyNode, Allowed, SetupTime,
                 #{node_name := OwnName, hs_opts := HsOptions} = Settings, Keys) ->
    Timer = dist_util:start_timer(SetupTime),
    case noisegate_hs:respond(Socket, OwnName, Keys, HsOptions) of
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
    case noisegate_dist_config:connection_settings() of
        {ok, Settings} ->
            case noisegate_dist_config:key_info() of
                {ok, Keys} ->
                    setup_connection(Kernel, Node, Type, MyNode,
                                     LongOrShortNames, SetupTime, Settings,
                                     Keys);
                {error, Reason} ->
                    stop_connection(Node, Reason)
            end;
        {error, Reason} ->
            stop_connection(Node, Reason)
    end.

setup_connection(Kernel, Node, Type, MyNode, LongOrShortNames, SetupTime,
                 Settings, Keys) ->
    Timer = dist_util:start_timer(SetupTime),
    try inet_tcp_dist:fam_setup(inet, Node, LongOrShortNames,
                                fun inet:parse_address/1) of
        {#net_address{address = {Ip, Port}} = NetAddress, _ConnectOptions, Version} ->
            dist_util:reset_timer(Timer),
            case gen_tcp:connect(Ip, Port, socket_options(Settings)) of
                {ok, Socket} ->
                    InitiateOpts = maps:get(hs_opts, Settings),
                    TargetName = atom_to_binary(Node, utf8),
                    case noisegate_hs:initiate(Socket, TargetName,
                                             Keys,
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

        Sender = noisegate_protocol:new_sender(Send, SP),
        Receiver = noisegate_protocol:new_receiver(Recv, RP),

        Ref = make_ref(),
        State = #controller_state{ own_name = maps:get(node_name, Settings),
                                   socket = Socket,
                                   role = Role,
                                   sender = Sender,
                                   receiver = Receiver
                                 },
        Controller = spawn_opt(?MODULE, controller_init,
                               [self(), Ref, State],
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

-spec controller_init(pid(), reference(), #controller_state{}) -> no_return().
controller_init(Parent, Ref, #controller_state{ socket = Socket, receiver = Receiver, sender = Sender, role = Role, own_name = OwnName}=State) ->
    process_flag(trap_exit, true),


    % Start the reader/receiver.
    Reader = spawn_opt(?MODULE, start_reader,
                       [Socket, Receiver, Role, OwnName],
                       [link, {priority, max}, {message_queue_data, off_heap}]),

    % Tell the parent controller and reader are ready to start the handshake.
    Parent ! {Ref, {ok, self(), Reader}},

    % The controller itself is the sender.
    State1 = State#controller_state{ sender = noisegate_protocol:tx_start(Sender),
                                     reader_pid = Reader },

    % Do the dist handshake.
    controller_handshake(State1).

-spec controller_handshake(#controller_state{}) -> no_return().
controller_handshake(#controller_state{ socket = Socket, own_name = OwnName, reader_pid = Reader, sender = Sender}=State) ->
    receive
        {send_packet, From, Ref, Packet} ->
            case write_packet(Socket, Sender, Packet) of
                {ok, Sender1} ->
                    From ! {Ref, ok},
                    controller_handshake(State#controller_state{ sender = Sender1 });
                {error, Reason} ->
                    From ! {Ref, {error, Reason}},
                    log_io_error(OwnName, {send, Reason}),
                    gen_tcp:close(Socket),
                    exit({send_error, Reason})
            end;
        tick ->
            case send_tick(Socket, Sender) of
                {ok, Sender1} ->
                    controller_handshake(State#controller_state{ sender = Sender1 });
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

            controller_connected(State#controller_state{ dhandle = DHandle });
        {'EXIT', _Pid, Reason} ->
            gen_tcp:close(Socket),
            exit({controller_child_exit, Reason})
    end.

 -spec controller_connected(#controller_state{}) -> no_return().
controller_connected(#controller_state{ socket = Socket, own_name = OwnName, sender = Sender}=State) ->
    receive
        dist_data ->
            controller_drain(0, State);
        tick ->
            case send_tick(Socket, Sender) of
                {ok, Sender1} ->
                    controller_connected(State#controller_state{ sender = Sender1});
                {error, Reason} ->
                    log_io_error(OwnName, {tick, Reason}),
                    gen_tcp:close(Socket),
                    exit({send_error, Reason})
            end;
        %{info, Ref, Pid} ->
        %    Pid ! {Ref, {inet:getstat(Socket),
        %                 inet:peername(Socket)
        %                }},
        %    controller_connected(Socket, OwnName, Reader, Sender, DHandle);
        {'EXIT', _Pid, Reason} ->
            gen_tcp:close(Socket),
            exit({controller_child_exit, Reason})
    end.


controller_drain(Count, State) ->
    drain_batch([], 0, Count, State).

%% Pending: encrypted frames not yet written, in reverse order.
%% PendingBytes: total byte size of Pending.
drain_batch(Pending, PendingBytes, Count, #controller_state{ socket = Socket, own_name = OwnName, sender = Sender, dhandle = DHandle}=State) ->
    case erlang:dist_ctrl_get_data(DHandle) of
        none ->
            %% Re-arm the VM notification first; it may queue more data
            %% while we are writing the batch to the socket.
            erlang:dist_ctrl_get_data_notification(DHandle),
            case send_frames(Socket, Pending) of
                ok ->
                    controller_connected(State);
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
                            drain_batch([], 0, Count + 1, State#controller_state{ sender = Sender1});
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
                            controller_connected(State#controller_state{ sender = Sender1 });
                        {error, Reason} ->
                            drain_send_failed(Socket, OwnName, Reason)
                    end;
                {ok, Sender1, Pending1, PendingBytes1} ->
                    drain_batch(Pending1, PendingBytes1, Count + 1, State#controller_state{ sender = Sender1});
                {error, Reason} ->
                    drain_send_failed(Socket, OwnName, Reason)
            end
    end.

-spec write_packet(inet:socket(), noisegate_protocol:sender(), iodata()) ->
          {ok, noisegate_protocol:sender()} | {error, term()}.
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
    try noisegate_protocol:tx_packet(Packet) of
        Tx ->
            tx_next_frames(Socket, Sender, Tx, Pending, PendingBytes)
    catch
        error:Reason ->
            {error, Reason}
    end.

tx_next_frames(Socket, Sender, Tx, Acc, Bytes) ->
    case noisegate_protocol:tx_next(Sender, Tx) of
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

-spec start_reader(inet:socket(), noisegate_protocol:receiver(), term(), binary()) -> term().
start_reader(Socket, Receiver0, Role, OwnName) ->
    Receiver = noisegate_protocol:rx_start(Receiver0),
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
                    case noisegate_protocol:rx_feed(Receiver, Bytes) of
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

-spec receive_data(inet:socket(), noisegate_protocol:receiver(), erlang:dist_handle(),
                   binary()) -> term().
receive_data(Socket, Receiver, DHandle, OwnName) ->
    case gen_tcp:recv(Socket, 0, infinity) of
        {ok, Bytes} ->
            case noisegate_protocol:rx_feed(Receiver, Bytes) of
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
    {Frame, Sender1} = noisegate_protocol:tx_tick(Sender),
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
    Fingerprint = identity_fingerprint(),
    logger:warning("peer closed the connection during handshake; our key is probably not authorized there: ~p ~ts",
                   [maps:get(remote_name, Result), Fingerprint]);
maybe_log_unauthorized(_, _) ->
    ok.


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
    Fingerprint = identity_fingerprint(),
    logger:warning("noisegate_dist: connection failed node=~p fingerprint=~ts reason=~p",
                   [Node, Fingerprint, Reason]),
    dist_util:shutdown(?MODULE, ?LINE, {Node, Reason}).

log_rx_error(NodeName, Reason) ->
    logger:warning("noisegate_dist: receive failed node=~ts fingerprint=~ts reason=~p",
                   [NodeName, identity_fingerprint(), Reason]).

log_io_error(NodeName, Reason) ->
    logger:warning("noisegate_dist: transport failed node=~ts fingerprint=~ts reason=~p",
                   [NodeName, identity_fingerprint(), Reason]).

identity_fingerprint() ->
    case noisegate_dist_config:get(fingerprint) of
        {ok, Fingerprint} ->
            Fingerprint;
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
