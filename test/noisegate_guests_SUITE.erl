%% Runs the escript built by `rebar3 escriptize` through a port.
-module(noisegate_guests_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").

-export([all/0, init_per_suite/1, end_per_suite/1]).
-export([init_show_self/1, add_check_remove/1, add_from_stdin/1, exit_codes/1,
         no_secret_in_output/1]).

all() ->
    [init_show_self, add_check_remove, add_from_stdin, exit_codes, no_secret_in_output].

init_per_suite(Config) ->
    [Root, _] = string:split(proplists:get_value(data_dir, Config), "/_build/"),
    Out = os:cmd("cd " ++ Root ++ " && rebar3 escriptize 2>&1"),
    Script = filename:join([Root, "_build", "default", "bin", "noisegate_guests"]),
    case filelib:is_regular(Script) of
        true -> ok;
        false -> ct:fail({escriptize_failed, Out})
    end,
    Base = "/tmp/noisegate_guests_ct_" ++ integer_to_list(erlang:unique_integer([positive])),
    ok = file:make_dir(Base),
    [{script, Script}, {base, Base} | Config].

end_per_suite(Config) ->
    file:del_dir_r(?config(base, Config)),
    ok.

%% Returns {ExitStatus, Stdout}; stderr is discarded.
cmd(Config, Args) -> cmd(Config, Args, none).

cmd(Config, Args, Stdin) ->
    Script = ?config(script, Config),
    Escript = os:find_executable("escript"),
    {Shell, Env} = case Stdin of
                       none -> {"\"$@\" </dev/null 2>/dev/null", []};
                       _ -> {"printf '%s\\n' \"$BG_STDIN\" | \"$@\" 2>/dev/null",
                             [{"BG_STDIN", binary_to_list(Stdin)}]}
                   end,
    Port = open_port({spawn_executable, "/bin/sh"},
                     [{args, ["-c", Shell, "sh", Escript, Script | Args]}, {env, Env},
                      exit_status, binary, use_stdio]),
    collect(Port, <<>>).

collect(Port, Acc) ->
    receive
        {Port, {data, D}} -> collect(Port, <<Acc/binary, D/binary>>);
        {Port, {exit_status, S}} -> {S, Acc}
    after 60000 ->
        ct:fail(timeout)
    end.

dirs(Config, Name) ->
    Base = filename:join(?config(base, Config), Name),
    ["--dir", filename:join(Base, "key"), "--authorized-dir", filename:join(Base, "auth")].

has(Bin, Part) -> binary:match(Bin, list_to_binary(Part)) =/= nomatch.

init_show_self(Config) ->
    G = dirs(Config, "n1"),
    {0, Out} = cmd(Config, ["init", "--node", "n1@h" | G]),
    [Line, FpLine] = binary:split(string:trim(Out), <<"\n">>),
    ?assertMatch(<<"n1@h ", _/binary>>, Line),
    ?assert(has(FpLine, "SHA256:")),
    ?assertEqual({0, Out}, cmd(Config, ["init", "--node", "n1@h" | G])),
    ?assertEqual({0, Out}, cmd(Config, ["show", "--self", "--node", "n1@h" | G])),
    {0, Q} = cmd(Config, ["show", "--self", "-q", "--node", "n1@h" | G]),
    ?assertEqual(<<Line/binary, "\n">>, Q).

add_check_remove(Config) ->
    GA = dirs(Config, "a"),
    GB = dirs(Config, "b"),
    {0, _} = cmd(Config, ["init", "--node", "a@h" | GA]),
    {0, _} = cmd(Config, ["init", "--node", "b@h" | GB]),
    {0, OutA} = cmd(Config, ["init", "--node", "a@h" | GA]),
    [LineA, <<"# fingerprint ", FpA/binary>>] = binary:split(string:trim(OutA), <<"\n">>),
    [Name, Key] = binary:split(LineA, <<" ">>),
    NameS = binary_to_list(Name), KeyS = binary_to_list(Key), FpS = binary_to_list(FpA),
    {4, <<>>} = cmd(Config, ["add", NameS, KeyS, "--fingerprint", "SHA256:AAAA" | GB]),
    {0, AddOut} = cmd(Config, ["add", NameS, KeyS, "--fingerprint", FpS | GB]),
    ?assert(has(AddOut, "added")),
    ?assert(has(AddOut, FpS)),
    {0, AddOut2} = cmd(Config, ["add", NameS, KeyS | GB]),
    ?assert(has(AddOut2, "already present")),
    {0, <<"ok\n">>} = cmd(Config, ["check", NameS, FpS | GB]),
    {4, <<>>} = cmd(Config, ["check", NameS, "SHA256:AAAA" | GB]),
    {1, <<>>} = cmd(Config, ["check", "zz@h", FpS | GB]),
    {0, ShowOut} = cmd(Config, ["show", NameS | GB]),
    ?assert(has(ShowOut, KeyS)),
    {0, ListOut} = cmd(Config, ["list" | GB]),
    ?assert(has(ListOut, FpS)),
    {0, RmOut} = cmd(Config, ["remove", NameS | GB]),
    ?assert(has(RmOut, FpS)),
    {1, <<>>} = cmd(Config, ["check", NameS, FpS | GB]),
    {1, <<>>} = cmd(Config, ["remove", NameS | GB]).

add_from_stdin(Config) ->
    GA = dirs(Config, "sa"),
    GB = dirs(Config, "sb"),
    {0, OutA} = cmd(Config, ["init", "--node", "sa@h" | GA]),
    {0, AddOut} = cmd(Config, ["add", "-" | GB], OutA),
    ?assert(has(AddOut, "added")),
    [_, <<"# fingerprint ", Fp/binary>>] = binary:split(string:trim(OutA), <<"\n">>),
    {0, <<"ok\n">>} = cmd(Config, ["check", "sa@h", binary_to_list(Fp) | GB]),
    {2, <<>>} = cmd(Config, ["add", "-" | GB], <<"a@h AAAA\nb@h AAAA">>).

exit_codes(Config) ->
    {2, <<>>} = cmd(Config, ["bogus"]),
    {2, <<>>} = cmd(Config, []),
    {0, Help} = cmd(Config, ["--help"]),
    ?assert(has(Help, "NEW handshakes")),
    {1, <<>>} = cmd(Config, ["show", "x@h" | dirs(Config, "empty")]).

no_secret_in_output(Config) ->
    G = dirs(Config, "sec"),
    {0, Out} = cmd(Config, ["init", "--node", "sec@h" | G]),
    {ok, Secret} = file:read_file(filename:join(lists:nth(2, G), "id_x25519")),
    ?assertEqual(nomatch, binary:match(Out, string:trim(Secret))).
