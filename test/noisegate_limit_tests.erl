-module(noisegate_limit_tests).

-include_lib("eunit/include/eunit.hrl").

capacity_and_release_test() ->
    Limit = 16,
    Handle = noisegate_limit:new(Limit),
    Parent = self(),
    [spawn(fun() ->
                   Parent ! {acquired,
                             noisegate_limit:acquire(
                               #{max_pending => Limit, limit_handle => Handle})}
           end)
     || _ <- lists:seq(1, 200)],
    Results = [receive {acquired, Result} -> Result end || _ <- lists:seq(1, 200)],
    ?assertEqual(Limit, length([ok || ok <- Results])),
    ?assertEqual(200 - Limit,
                 length([busy || {error, busy} <- Results])),
    [noisegate_limit:release(Handle) || _ <- lists:seq(1, Limit)],
    [ok = noisegate_limit:acquire(#{max_pending => Limit,
                                  limit_handle => Handle})
     || _ <- lists:seq(1, Limit)],
    ?assertEqual({error, busy},
                 noisegate_limit:acquire(#{max_pending => Limit,
                                         limit_handle => Handle})),
    [ok = noisegate_limit:release(Handle) || _ <- lists:seq(1, Limit)],
    ?assertEqual(ok, noisegate_limit:acquire(#{max_pending => Limit,
                                             limit_handle => Handle})),
    ?assertEqual(ok, noisegate_limit:release(Handle)).

release_zero_api_test() ->
    Handle = noisegate_limit:new(1),
    Opts = #{limit_handle => Handle},
    ?assertEqual(ok, noisegate_limit:acquire(Opts)),
    ?assertEqual({error, busy}, noisegate_limit:acquire(Opts)),
    ?assertEqual(ok, noisegate_limit:release()),
    ?assertEqual(ok, noisegate_limit:acquire(Opts)),
    ?assertEqual(ok, noisegate_limit:release()).
