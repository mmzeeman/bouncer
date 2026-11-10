-module(bouncer_dist_config_tests).

-include_lib("eunit/include/eunit.hrl").

connection_settings_from_ets_test() ->
    ?assertEqual({error, not_ready}, bouncer_dist_config:connection_settings()),
    bouncer_dist_config:create_config_table(),
    try
        ?assertEqual({error, not_ready},
                     bouncer_dist_config:connection_settings()),
        Snapshot = #{node_name => <<"test@localhost">>,
                     config_generation => make_ref()},
        true = ets:insert(bouncer_dist_config, {connection_settings, Snapshot}),
        ?assertEqual({ok, Snapshot}, bouncer_dist_config:connection_settings())
    after
        ets:delete(bouncer_dist_config)
    end,
    ?assertEqual({error, not_ready}, bouncer_dist_config:connection_settings()).
