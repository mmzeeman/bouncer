%% Process-free admission control for pending handshakes.
-module(bouncer_limit).

-export([acquire/1, release/0]).

-define(COUNTER, {?MODULE, pending}).

-doc """
Acquires one pending-handshake slot. `max_pending` defaults to 64.
""".
-spec acquire(map()) -> ok | {error, busy}.
acquire(Opts) when is_map(Opts) ->
    Limit = maps:get(max_pending, Opts, 64),
    case is_integer(Limit) andalso Limit > 0 of
        true ->
            Ref = counter(),
            reserve(Ref, Limit);
        false ->
            {error, busy}
    end;
acquire(_) ->
    {error, busy}.

-doc "Releases one pending-handshake slot acquired with `acquire/1`.".
-spec release() -> ok.
release() ->
    atomics:sub(counter(), 1, 1),
    ok.

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

counter() ->
    case persistent_term:get(?COUNTER, undefined) of
        undefined ->
            global:trans({?MODULE, self()},
                         fun() ->
                                 case persistent_term:get(?COUNTER, undefined) of
                                     undefined ->
                                         Ref = atomics:new(1, []),
                                         persistent_term:put(?COUNTER, Ref),
                                         Ref;
                                     Ref ->
                                         Ref
                                 end
                         end);
        Ref ->
            Ref
    end.
