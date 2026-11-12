-module(noisegate_settings_tests).

-include_lib("eunit/include/eunit.hrl").

defaults_test() ->
    {ok, Settings} = noisegate_settings:parse(#{}, #{}, #{}),
    ?assertEqual(aesgcm_sha512, maps:get(suite, Settings)),
    ?assertEqual([aesgcm_sha512], maps:get(accept_suites, Settings)),
    ?assertEqual(5000, maps:get(handshake_timeout_ms,
                                maps:get(hs_opts, Settings))),
    ?assertEqual(30000, maps:get(send_timeout_ms, Settings)),
    ?assertEqual(64, maps:get(max_pending, Settings)).

precedence_test() ->
    Opts = #{suite => aesgcm_sha256, chunk_size => 8192, dir => "/opts"},
    Flags = #{"suite" => "aesgcm_blake2b",
              "chunk_size" => "4096",
              "dir" => "/flags"},
    Env = #{"suite" => "chachapoly_blake2b",
            "chunk_size" => "2048",
            "dir" => "/env"},
    {ok, Settings} = noisegate_settings:parse(Opts, Flags, Env),
    ?assertEqual(aesgcm_sha256, maps:get(suite, Settings)),
    ?assertEqual(8192,
                 maps:get(chunk_size, maps:get(sender_policy, Settings))),
    ?assertEqual("/opts", maps:get(dir, maps:get(key_options, Settings))).

flag_over_environment_test() ->
    {ok, Settings} =
        noisegate_settings:parse(#{}, #{"suite" => "aesgcm_sha256"},
                               #{"suite" => "aesgcm_blake2b"}),
    ?assertEqual(aesgcm_sha256, maps:get(suite, Settings)).

invalid_suite_names_allowed_values_test() ->
    ?assertMatch({error, {invalid_setting, suite, "foo",
                          "chachapoly_blake2b | aesgcm_sha512 | aesgcm_sha256 | aesgcm_blake2b"}},
                 noisegate_settings:parse(#{suite => "foo"}, #{}, #{})).

invalid_positive_setting_names_allowed_values_test() ->
    ?assertEqual({error, {invalid_setting, max_pending, "zero",
                          "a positive integer"}},
                 noisegate_settings:parse(#{}, #{"max_pending" => "zero"}, #{})).
