-module(noisegate_dist_config_tests).

-include_lib("eunit/include/eunit.hrl").

connection_settings_from_ets_test() ->
    ?assertEqual({error, not_ready}, noisegate_dist_config:connection_settings()),
    noisegate_dist_config:create_config_table(),
    try
        ?assertEqual({error, not_ready},
                     noisegate_dist_config:connection_settings()),
        NodeName = <<"test@localhost">>,
        Entries = [{node_name, NodeName}, {own_name, NodeName},
                   {fingerprint, "fingerprint"},
                   {send_timeout_ms, 30000}, {sender_policy, sender},
                   {receiver_policy, receiver}, {handshake_timeout_ms, 5000},
                   {max_pending, 64}, {suite, aesgcm_sha512},
                   {accept_suites, [aesgcm_sha512]}, {limit_handle, handle},
                   {dir, "/keys"}],
        true = ets:insert(noisegate_dist_config, Entries),
        HsOpts = #{node_name => NodeName, own_name => NodeName,
                   send_timeout_ms => 30000, handshake_timeout_ms => 5000,
                   max_pending => 64, suite => aesgcm_sha512,
                   accept_suites => [aesgcm_sha512], limit_handle => handle,
                   dir => "/keys"},
        Expected = #{node_name => NodeName,
                     fingerprint => "fingerprint", send_timeout_ms => 30000,
                     sender_policy => sender, receiver_policy => receiver,
                     hs_opts => HsOpts},
        ?assertEqual({ok, Expected}, noisegate_dist_config:connection_settings()),
        true = ets:insert(noisegate_dist_config, {send_timeout_ms, 1234}),
        {ok, Changed} = noisegate_dist_config:connection_settings(),
        ?assertEqual(1234, maps:get(send_timeout_ms, Changed)),
        ?assertEqual(1234, maps:get(send_timeout_ms, maps:get(hs_opts, Changed))),
        ?assertEqual(30000, maps:get(send_timeout_ms, Expected)),
        true = ets:delete(noisegate_dist_config, dir),
        {ok, WithoutDir} = noisegate_dist_config:connection_settings(),
        ?assertNot(maps:is_key(dir, maps:get(hs_opts, WithoutDir))),
        lists:foreach(
          fun(Key) ->
                  [{Key, Value}] = ets:lookup(noisegate_dist_config, Key),
                  true = ets:delete(noisegate_dist_config, Key),
                  ?assertEqual({error, not_ready},
                               noisegate_dist_config:connection_settings()),
                  true = ets:insert(noisegate_dist_config, {Key, Value})
          end, [node_name, own_name, fingerprint,
                send_timeout_ms, sender_policy, receiver_policy,
                handshake_timeout_ms, max_pending, suite, accept_suites,
                limit_handle])
    after
        ets:delete(noisegate_dist_config)
    end,
    ?assertEqual({error, not_ready}, noisegate_dist_config:connection_settings()).

config_state_test_() ->
    case node() of
        nonode@nohost ->
            fun() ->
                noisegate_dist_config:create_config_table(),
                try
                    ok = noisegate_dist_config:load_settings(),
                    true = ets:insert(noisegate_dist_config,
                                      {send_timeout_ms, 1234}),
                    {ok, Pid} = noisegate_dist_config:start_link(),
                    try
                        ?assertEqual({state, undefined}, sys:get_state(Pid)),
                        ?assertMatch({ok, _}, noisegate_dist_config:get(suite)),
                        ?assertEqual({ok, 1234},
                                     noisegate_dist_config:get(send_timeout_ms)),
                        ?assertEqual([], ets:lookup(noisegate_dist_config,
                                                    connection_settings)),
                        ?assertEqual({error, not_ready},
                                     noisegate_dist_config:connection_settings())
                    after
                        gen_server:stop(Pid)
                    end
                after
                    ets:delete(noisegate_dist_config)
                end
            end;
        _ ->
            []
    end.

supervisor_settings_test_() ->
    case node() of
        nonode@nohost ->
            fun() ->
                {ok, Sup} = noisegate_dist_sup:start_link(),
                try
                    ?assertEqual(Sup, ets:info(noisegate_dist_config, owner)),
                    {ok, LimitHandle} = noisegate_dist_config:limit_handle(),
                    true = ets:insert(noisegate_dist_config,
                                      {send_timeout_ms, 1234}),
                    ok = supervisor:terminate_child(Sup, noisegate_dist_config),
                    {ok, _} = supervisor:restart_child(Sup, noisegate_dist_config),
                    ?assertEqual({ok, 1234},
                                 noisegate_dist_config:get(send_timeout_ms)),
                    ?assertEqual({ok, LimitHandle},
                                 noisegate_dist_config:limit_handle())
                after
                    unlink(Sup),
                    Ref = monitor(process, Sup),
                    exit(Sup, shutdown),
                    receive
                        {'DOWN', Ref, process, Sup, shutdown} -> ok
                    after 5000 ->
                        error(supervisor_shutdown_timeout)
                    end
                end,
                ?assertEqual(undefined, ets:info(noisegate_dist_config))
            end;
        _ ->
            []
    end.
