%% Process-free admission control for pending handshakes.
-module(noisegate_limit).

-export([new/1, acquire/1, release/0, release/1]).
-export_type([handle/0]).

-opaque handle() :: {noisegate_limit, pos_integer(), atomics:atomics_ref()}.
-define(ACQUISITIONS, {?MODULE, acquisitions}).

%% Creates a counters handle with a fixed maximum number of pending handshakes.
-spec new(pos_integer()) -> handle().
new(Limit) when is_integer(Limit), Limit > 0 ->
    {noisegate_limit, Limit, atomics:new(1, [])}.

%% Acquires one pending-handshake slot. The carrier passes a limit_handle in Opts.
-spec acquire(map()) -> ok | {error, busy}.
acquire(Opts) when is_map(Opts) ->
    case handle(Opts) of
        {ok, Handle} ->
            {noisegate_limit, HandleLimit, Ref} = Handle,
            Limit = maps:get(max_pending, Opts, HandleLimit),
            case is_integer(Limit) andalso Limit > 0 of
                true ->
                    case reserve(Ref, Limit) of
                        ok ->
                            remember(Handle),
                            ok;
                        {error, busy} = Error ->
                            Error
                    end;
                false -> {error, busy}
            end;
        error ->
            {error, busy}
    end;
acquire(_) ->
    {error, busy}.

%% Releases one pending-handshake slot acquired with acquire/1.
-spec release() -> ok.
release() ->
    case get(?ACQUISITIONS) of
        [Handle | Rest] ->
            put_or_erase(Rest),
            release_counter(Handle);
        _ ->
            case handle(#{}) of
                {ok, Handle} -> release_counter(Handle);
                error -> ok
            end
    end.

-spec release(map() | handle()) -> ok.
release(Opts) when is_map(Opts) ->
    case handle(Opts) of
        {ok, Handle} -> release(Handle);
        error -> ok
    end;
release({noisegate_limit, _Limit, _Ref} = Handle) ->
    forget(Handle),
    release_counter(Handle).

release_counter({noisegate_limit, _Limit, Ref}) ->
    atomics:sub(Ref, 1, 1),
    ok.

remember(Handle) ->
    put(?ACQUISITIONS, [Handle | acquisition_stack()]),
    ok.

forget(Handle) ->
    Stack = acquisition_stack(),
    case lists:delete(Handle, Stack) of
        [] -> erase(?ACQUISITIONS);
        Remaining -> put(?ACQUISITIONS, Remaining)
    end,
    ok.

acquisition_stack() ->
    case get(?ACQUISITIONS) of
        undefined -> [];
        Stack -> Stack
    end.

put_or_erase([]) ->
    erase(?ACQUISITIONS);
put_or_erase(Stack) ->
    put(?ACQUISITIONS, Stack).

handle(Opts) ->
    case maps:find(limit_handle, Opts) of
        {ok, {noisegate_limit, Limit, _Ref} = Handle}
          when is_integer(Limit), Limit > 0 ->
            {ok, Handle};
        {ok, _} ->
            error;
        error ->
            case noisegate_dist_config:limit_handle() of
                {ok, {noisegate_limit, Limit, _Ref} = Handle}
                  when is_integer(Limit), Limit > 0 ->
                    {ok, Handle};
                _ ->
                    error
            end
    end.

reserve(Ref, Limit) ->
    Current = atomics:get(Ref, 1),
    case Current >= Limit of
        true ->
            {error, busy};
        false ->
            case atomics:compare_exchange(Ref, 1, Current, Current + 1) of
                ok -> ok;
                _ -> reserve(Ref, Limit)
            end
    end.
