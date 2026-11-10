-module(bouncer_dist_config_tests).

-include_lib("eunit/include/eunit.hrl").

connection_settings_from_ets_test() ->
    ?assertEqual({error, not_ready}, bouncer_dist_config:connection_settings()),
    bouncer_dist_config:create_config_table(),
    try
        ?assertEqual({error, not_ready},
                     bouncer_dist_config:connection_settings()),
        NodeName = <<"test@localhost">>,
        Generation = make_ref(),
        Entries = [{node_name, NodeName}, {own_name, NodeName},
                   {config_generation, Generation}, {fingerprint, "fingerprint"},
                   {send_timeout_ms, 30000}, {sender_policy, sender},
                   {receiver_policy, receiver}, {handshake_timeout_ms, 5000},
                   {max_pending, 64}, {suite, aesgcm_sha512},
                   {accept_suites, [aesgcm_sha512]}, {limit_handle, handle},
                   {dir, "/keys"}],
        true = ets:insert(bouncer_dist_config, Entries),
        HsOpts = #{node_name => NodeName, own_name => NodeName,
                   send_timeout_ms => 30000, handshake_timeout_ms => 5000,
                   max_pending => 64, suite => aesgcm_sha512,
                   accept_suites => [aesgcm_sha512], limit_handle => handle,
                   dir => "/keys"},
        Expected = #{node_name => NodeName, config_generation => Generation,
                     fingerprint => "fingerprint", send_timeout_ms => 30000,
                     sender_policy => sender, receiver_policy => receiver,
                     hs_opts => HsOpts},
        ?assertEqual({ok, Expected}, bouncer_dist_config:connection_settings()),
        true = ets:insert(bouncer_dist_config, {send_timeout_ms, 1234}),
        {ok, Changed} = bouncer_dist_config:connection_settings(),
        ?assertEqual(1234, maps:get(send_timeout_ms, Changed)),
        ?assertEqual(1234, maps:get(send_timeout_ms, maps:get(hs_opts, Changed))),
        true = ets:delete(bouncer_dist_config, dir),
        {ok, WithoutDir} = bouncer_dist_config:connection_settings(),
        ?assertNot(maps:is_key(dir, maps:get(hs_opts, WithoutDir))),
        lists:foreach(
          fun(Key) ->
                  [{Key, Value}] = ets:lookup(bouncer_dist_config, Key),
                  true = ets:delete(bouncer_dist_config, Key),
                  ?assertEqual({error, not_ready},
                               bouncer_dist_config:connection_settings()),
                  true = ets:insert(bouncer_dist_config, {Key, Value})
          end, [node_name, own_name, config_generation, fingerprint,
                send_timeout_ms, sender_policy, receiver_policy,
                handshake_timeout_ms, max_pending, suite, accept_suites,
                limit_handle])
    after
        ets:delete(bouncer_dist_config)
    end,
    ?assertEqual({error, not_ready}, bouncer_dist_config:connection_settings()).

config_state_test_() ->
    case node() of
        nonode@nohost ->
            fun() ->
                bouncer_dist_config:create_config_table(),
                try
                    {ok, Pid} = bouncer_dist_config:start_link(),
                    try
                        ?assertEqual({state, undefined}, sys:get_state(Pid)),
                        ?assertMatch({ok, _}, bouncer_dist_config:get(suite)),
                        ?assertEqual([], ets:lookup(bouncer_dist_config,
                                                    connection_settings)),
                        ?assertEqual({error, not_ready},
                                     bouncer_dist_config:connection_settings())
                    after
                        gen_server:stop(Pid)
                    end
                after
                    ets:delete(bouncer_dist_config)
                end
            end;
        _ ->
            []
    end.
