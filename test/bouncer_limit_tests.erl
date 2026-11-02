-module(bouncer_limit_tests).

-include_lib("eunit/include/eunit.hrl").

capacity_and_release_test() ->
    Limit = 16,
    Parent = self(),
    [spawn(fun() -> Parent ! {acquired, bouncer_limit:acquire(#{max_pending => Limit})} end)
     || _ <- lists:seq(1, 200)],
    Results = [receive {acquired, Result} -> Result end || _ <- lists:seq(1, 200)],
    ?assertEqual(Limit, length([ok || ok <- Results])),
    ?assertEqual(200 - Limit,
                 length([busy || {error, busy} <- Results])),
    [bouncer_limit:release() || _ <- lists:seq(1, Limit)],
    [ok = bouncer_limit:acquire(#{max_pending => Limit})
     || _ <- lists:seq(1, Limit)],
    ?assertEqual({error, busy}, bouncer_limit:acquire(#{max_pending => Limit})),
    [ok = bouncer_limit:release() || _ <- lists:seq(1, Limit)],
    ?assertEqual(ok, bouncer_limit:acquire(#{max_pending => Limit})),
    ?assertEqual(ok, bouncer_limit:release()).
