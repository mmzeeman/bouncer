-module(bouncer_limit_tests).

-include_lib("eunit/include/eunit.hrl").

capacity_and_release_test() ->
    Limit = 16,
    Handle = bouncer_limit:new(Limit),
    Parent = self(),
    [spawn(fun() ->
                   Parent ! {acquired,
                             bouncer_limit:acquire(
                               #{max_pending => Limit, limit_handle => Handle})}
           end)
     || _ <- lists:seq(1, 200)],
    Results = [receive {acquired, Result} -> Result end || _ <- lists:seq(1, 200)],
    ?assertEqual(Limit, length([ok || ok <- Results])),
    ?assertEqual(200 - Limit,
                 length([busy || {error, busy} <- Results])),
    [bouncer_limit:release(Handle) || _ <- lists:seq(1, Limit)],
    [ok = bouncer_limit:acquire(#{max_pending => Limit,
                                  limit_handle => Handle})
     || _ <- lists:seq(1, Limit)],
    ?assertEqual({error, busy},
                 bouncer_limit:acquire(#{max_pending => Limit,
                                         limit_handle => Handle})),
    [ok = bouncer_limit:release(Handle) || _ <- lists:seq(1, Limit)],
    ?assertEqual(ok, bouncer_limit:acquire(#{max_pending => Limit,
                                             limit_handle => Handle})),
    ?assertEqual(ok, bouncer_limit:release(Handle)).

release_zero_api_test() ->
    Handle = bouncer_limit:new(1),
    Opts = #{limit_handle => Handle},
    ?assertEqual(ok, bouncer_limit:acquire(Opts)),
    ?assertEqual({error, busy}, bouncer_limit:acquire(Opts)),
    ?assertEqual(ok, bouncer_limit:release()),
    ?assertEqual(ok, bouncer_limit:acquire(Opts)),
    ?assertEqual(ok, bouncer_limit:release()).
