-module(bouncer_dist_config).
-behaviour(gen_server).

-export([
    create_config_table/0,
    start_link/0,
    configure_node/1,
    get/1,
    connection_settings/0,
    key_info/0,
    key_info/1,
    node_name/0,
    limit_handle/0
]).

-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).

-define(TABLE, bouncer_dist_config).

-record(state, {
    parsed,
    node_name = undefined,
    key_info = undefined,
    settings = undefined,
    limit_handle
}).

create_config_table() ->
    _ = ets:new(?TABLE, [set, public, named_table, {read_concurrency, true}]).

start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

configure_node(NodeName) ->
    call({configure_node, NodeName}).

get(Key) ->
    table_value(Key).

connection_settings() ->
    table_value(connection_settings).

key_info() ->
    call(key_info).

key_info(Generation) ->
    call({key_info, Generation}).

node_name() ->
    table_value(node_name).

limit_handle() ->
    table_value(limit_handle).

init([]) ->
    %% Sensitive limits tracing and process_info exposure, but does not hide
    %% this state from sys:get_state/1.
    process_flag(sensitive, true),

    case bouncer_settings:parse() of
        {ok, Parsed} ->
            LimitHandle = bouncer_limit:new(maps:get(max_pending, Parsed)),
            State0 = #state{parsed = Parsed, limit_handle = LimitHandle},
            case current_node_name() of
                undefined ->
                    {ok, State0};
                NodeName ->
                    case load_node(NodeName, State0) of
                        {ok, State1} -> {ok, State1};
                        {error, Reason} ->
                            logger:error("bouncer distribution config failed: ~p",
                                         [Reason]),
                            {stop, Reason}
                    end
            end;
        {error, Reason} ->
            logger:error("bouncer distribution settings are invalid: ~p",
                         [Reason]),
            {stop, Reason}
    end.

handle_call({configure_node, NodeName}, _From,
            #state{node_name = NodeName, settings = Settings} = State)
  when Settings =/= undefined ->
    {reply, ok, State};
handle_call({configure_node, NodeName}, _From, State) ->
    case load_node(NodeName, State) of
        {ok, State1} ->
            {reply, ok, State1};
        {error, Reason} ->
            {reply, {error, Reason}, State}
    end;
handle_call(key_info, _From, #state{key_info = undefined} = State) ->
    {reply, {error, not_ready}, State};
handle_call(key_info, _From, #state{key_info = KeyInfo} = State) ->
    {reply, {ok, KeyInfo}, State};
handle_call({key_info, _Generation}, _From,
            #state{settings = undefined} = State) ->
    {reply, {error, not_ready}, State};
handle_call({key_info, Generation}, _From,
            #state{settings = #{config_generation := Generation},
                   key_info = KeyInfo} = State) ->
    {reply, {ok, KeyInfo}, State};
handle_call({key_info, _Generation}, _From, State) ->
    {reply, {error, stale_configuration}, State};
handle_call(_Request, _From, State) ->
    {reply, {error, bad_request}, State}.

handle_cast(_Request, State) ->
    {noreply, State}.

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVersion, State, _Extra) ->
    {ok, State}.

load_node(NodeName, #state{parsed = Parsed, limit_handle = LimitHandle} = State) ->
    KeyOptions = (maps:get(key_options, Parsed))#{node_name => NodeName},
    case bouncer_keys:load_or_generate(NodeName, KeyOptions) of
        {ok, KeyInfo} ->
            Generation = make_ref(),
            HsOpts0 = maps:merge(maps:get(hs_opts, Parsed),
                                 maps:get(key_options, Parsed)),
            HsOpts = HsOpts0#{own_name => NodeName, node_name => NodeName,
                              limit_handle => LimitHandle},
            Settings = Parsed#{node_name => NodeName,
                               config_generation => Generation,
                               fingerprint => bouncer_keys:fingerprint(KeyInfo),
                               hs_opts => HsOpts},
            Published = maps:merge(
                          maps:without([key_options, hs_opts], Settings),
                          HsOpts),
            SnapshotKeys = [node_name, config_generation, fingerprint,
                            send_timeout_ms, sender_policy, receiver_policy,
                            hs_opts],
            Snapshot = maps:with(SnapshotKeys, Settings),
            true = ets:insert(?TABLE,
                              [{connection_settings, Snapshot} |
                               maps:to_list(Published)]),
            logger:notice("bouncer_dist: suite=~p accept_suites=~p fingerprint=~ts",
                          [maps:get(suite, Settings),
                           maps:get(accept_suites, Settings),
                           maps:get(fingerprint, Settings)]),
            {ok, State#state{node_name = NodeName,
                             key_info = KeyInfo,
                             settings = Settings}};
        {error, _} = Error ->
            Error
    end.

current_node_name() ->
    case node() of
        nonode@nohost -> undefined;
        Node -> atom_to_binary(Node, utf8)
    end.

table_value(Key) ->
    try ets:lookup(?TABLE, Key) of
        [{Key, Value}] -> {ok, Value};
        [] -> {error, not_ready}
    catch
        error:badarg -> {error, not_ready}
    end.

call(Request) ->
    case whereis(?MODULE) of
        undefined ->
            {error, not_ready};
        _Pid ->
            try gen_server:call(?MODULE, Request, infinity) of
                Reply -> Reply
            catch
                exit:{noproc, _} -> {error, not_ready};
                exit:{normal, _} -> {error, not_ready}
            end
    end.
