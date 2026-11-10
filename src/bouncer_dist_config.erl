-module(bouncer_dist_config).
-behaviour(gen_server).

-export([
    create_config_table/0,
    load_settings/0,
    start_link/0,
    configure_node/1,
    get/1,
    connection_settings/0,
    key_info/0,
    node_name/0,
    limit_handle/0
]).

-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).

-define(TABLE, bouncer_dist_config).

-record(state, {
    key_info = undefined
}).

create_config_table() ->
    _ = ets:new(?TABLE, [set, public, named_table, {read_concurrency, true}]).

load_settings() ->
    case bouncer_settings:parse() of
        {ok, Parsed} ->
            LimitHandle = bouncer_limit:new(maps:get(max_pending, Parsed)),
            Values = maps:merge(maps:without([key_options, hs_opts], Parsed),
                                maps:get(hs_opts, Parsed)),
            Published = maps:merge(Values, maps:get(key_options, Parsed)),
            true = ets:insert(?TABLE, [{limit_handle, LimitHandle} |
                                       maps:to_list(Published)]),
            ok;
        {error, Reason} ->
            logger:error("bouncer distribution settings are invalid: ~p",
                         [Reason]),
            {error, Reason}
    end.

start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

configure_node(NodeName) ->
    call({configure_node, NodeName}).

get(Key) ->
    table_value(Key).

connection_settings() ->
    BaseKeys = [node_name, fingerprint, send_timeout_ms,
                sender_policy, receiver_policy],
    HandshakeKeys = [handshake_timeout_ms, send_timeout_ms, max_pending, suite,
                     accept_suites, own_name, node_name, limit_handle],
    case setting_values(lists:usort(BaseKeys ++ HandshakeKeys)) of
        {ok, Values} ->
            case optional_setting_values([dir, generate, authorized_dirs]) of
                {ok, KeyOptions} ->
                    HsOpts = maps:merge(maps:with(HandshakeKeys, Values),
                                        KeyOptions),
                    {ok, (maps:with(BaseKeys, Values))#{hs_opts => HsOpts}};
                {error, _} = Error ->
                    Error
            end;
        {error, _} = Error ->
            Error
    end.

key_info() ->
    call(key_info).

node_name() ->
    table_value(node_name).

limit_handle() ->
    table_value(limit_handle).

init([]) ->
    %% Sensitive limits tracing and process_info exposure, but does not hide
    %% this state from sys:get_state/1.
    process_flag(sensitive, true),

    State0 = #state{},
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
    end.

handle_call({configure_node, NodeName}, _From, State) ->
    case {table_value(node_name), State#state.key_info} of
        {{ok, NodeName}, KeyInfo} when KeyInfo =/= undefined ->
            {reply, ok, State};
        _ ->
            case load_node(NodeName, State) of
                {ok, State1} ->
                    {reply, ok, State1};
                {error, Reason} ->
                    {reply, {error, Reason}, State}
            end
    end;
handle_call(key_info, _From, #state{key_info = undefined} = State) ->
    {reply, {error, not_ready}, State};
handle_call(key_info, _From, #state{key_info = KeyInfo} = State) ->
    {reply, {ok, KeyInfo}, State};
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

load_node(NodeName, State) ->
    case optional_setting_values([dir, generate, authorized_dirs]) of
        {ok, Options} ->
            load_node_key(NodeName, Options#{node_name => NodeName}, State);
        {error, _} = Error ->
            Error
    end.

load_node_key(NodeName, KeyOptions, State) ->
    case bouncer_keys:load_or_generate(NodeName, KeyOptions) of
        {ok, KeyInfo} ->
            Fingerprint = bouncer_keys:fingerprint(KeyInfo),
            true = ets:insert(?TABLE, [{node_name, NodeName},
                                       {own_name, NodeName},
                                       {fingerprint, Fingerprint}]),
            {ok, Suite} = table_value(suite),
            {ok, AcceptSuites} = table_value(accept_suites),
            logger:notice("bouncer_dist: suite=~p accept_suites=~p fingerprint=~ts",
                          [Suite, AcceptSuites, Fingerprint]),
            {ok, State#state{key_info = KeyInfo}};
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

setting_values(Keys) ->
    lists:foldl(
      fun(Key, {ok, Acc}) ->
              case table_value(Key) of
                  {ok, Value} -> {ok, Acc#{Key => Value}};
                  {error, _} = Error -> Error
              end;
         (_Key, {error, _} = Error) ->
              Error
      end, {ok, #{}}, Keys).

optional_setting_values(Keys) ->
    try
        Values = lists:foldl(
                   fun(Key, Acc) ->
                           case ets:lookup(?TABLE, Key) of
                               [{Key, Value}] -> Acc#{Key => Value};
                               [] -> Acc
                           end
                   end, #{}, Keys),
        {ok, Values}
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
