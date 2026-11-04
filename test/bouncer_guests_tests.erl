-module(bouncer_guests_tests).
-include_lib("eunit/include/eunit.hrl").
-include_lib("kernel/include/file.hrl").

%%% Helpers

with_dir(Fun) ->
    Base = "/tmp/bouncer_guests_test_" ++ integer_to_list(erlang:unique_integer([positive]))
        ++ "_" ++ os:getpid(),
    ok = file:make_dir(Base),
    try
        Fun(Base)
    after
        file:del_dir_r(Base)
    end.

run(Args) -> run(Args, #{}).

run(Args, Env) ->
    {Code, Out, Err} = bouncer_guests:run(Args, Env),
    {Code, unicode:characters_to_binary(Out), unicode:characters_to_binary(Err)}.

mode(Path) ->
    {ok, #file_info{mode = M}} = file:read_link_info(Path),
    M band 8#777.

contains(Bin, Part) -> binary:match(Bin, unicode:characters_to_binary(Part)) =/= nomatch.

new_pub() ->
    {Pub, _} = crypto:generate_key(ecdh, x25519),
    Pub.

b64(K) -> binary_to_list(base64:encode(K)).
fp(K) -> binary_to_list(bouncer_keys:fingerprint(K)).

%% Directories of a node: {KeyDir, AuthDir, GlobalArgs}.
node_dirs(B, Name) ->
    K = filename:join([B, Name, "key"]),
    A = filename:join([B, Name, "auth"]),
    {K, A, ["--dir", K, "--authorized-dir", A]}.

keys_opts(K, A) -> #{dir => K, authorized_dirs => [A], node_name => <<"x@h">>}.

dir_count(Dir) ->
    {ok, L} = file:list_dir(Dir),
    length(L).

add(Args, G) -> run(["add" | Args] ++ G).

%%% init

init_test_() ->
    [{"init creates dirs, key and prints line + fingerprint",
      fun() -> with_dir(fun(B) ->
          {K, A, G} = node_dirs(B, "a"),
          {0, Out, <<>>} = run(["init", "--node", "a@h" | G]),
          ?assertEqual(8#700, mode(K)),
          ?assertEqual(8#755, mode(A)),
          KeyFile = filename:join(K, "id_x25519"),
          ?assertEqual(8#600, mode(KeyFile)),
          {ok, Info} = bouncer_keys:load_or_generate(<<"a@h">>, (keys_opts(K, A))#{generate => false}),
          Pub = bouncer_keys:public(Info),
          [Line, FpLine] = binary:split(string:trim(Out), <<"\n">>),
          ?assertEqual(string:trim(bouncer_keys:authorized_line(<<"a@h">>, Pub)), Line),
          ?assert(contains(FpLine, "SHA256:")),
          ?assert(contains(FpLine, fp(Pub))),
          {ok, Before} = file:read_file(KeyFile),
          {0, Out2, <<>>} = run(["init", "--node", "a@h" | G]),
          ?assertEqual(Out, Out2),
          ?assertEqual({ok, Before}, file:read_file(KeyFile)),
          ?assertEqual(8#700, mode(K))
      end) end},
     {"init never loosens an existing key dir",
      fun() -> with_dir(fun(B) ->
          {K, _A, G} = node_dirs(B, "a"),
          ok = filelib:ensure_path(K),
          ok = file:change_mode(K, 8#750),
          {0, _, _} = run(["init", "--node", "a@h" | G]),
          ?assertEqual(8#750, mode(K))
      end) end},
     {"key file with mode 0644 -> exit 3",
      fun() -> with_dir(fun(B) ->
          {K, _A, G} = node_dirs(B, "a"),
          {0, _, _} = run(["init", "--node", "a@h" | G]),
          ok = file:change_mode(filename:join(K, "id_x25519"), 8#644),
          {3, <<>>, Err} = run(["init", "--node", "a@h" | G]),
          ?assert(contains(Err, "insecure permissions"))
      end) end},
     {"--no-generate creates no key",
      fun() -> with_dir(fun(B) ->
          {K, _A, G} = node_dirs(B, "a"),
          {0, _, <<>>} = run(["init", "--node", "a@h", "--no-generate" | G]),
          ?assertNot(filelib:is_file(filename:join(K, "id_x25519")))
      end) end},
     {"init needs a valid --node",
      fun() -> with_dir(fun(B) ->
          {_, _, G} = node_dirs(B, "a"),
          ?assertMatch({2, _, _}, run(["init" | G])),
          ?assertMatch({2, _, _}, run(["init", "--node", "../x@y" | G])),
          ?assertNot(filelib:is_file(filename:join(B, "a")))
      end) end}].

%%% add

add_test_() ->
    [{"NAME KEY, --line, stdin",
      fun() -> with_dir(fun(B) ->
          {K, A, G} = node_dirs(B, "b"),
          [P1, P2, P3] = [new_pub() || _ <- [1, 2, 3]],
          {0, Out, <<>>} = add(["p1@h", b64(P1), "--comment", "first one"], G),
          ?assert(contains(Out, "added")),
          ?assert(contains(Out, fp(P1))),
          {0, Out2, _} = add(["--line", "p2@h " ++ b64(P2) ++ " some comment"], G),
          ?assert(contains(Out2, fp(P2))),
          {0, Out4, _} = run(["add", "-" | G],
                             #{stdin => <<"\n# fingerprint x\np3@h ", (base64:encode(P3))/binary, "\n\n">>}),
          ?assert(contains(Out4, fp(P3))),
          O = keys_opts(K, A),
          [?assertEqual(allowed, bouncer_keys:check_peer(N, P, O))
           || {N, P} <- [{<<"p1@h">>, P1}, {<<"p2@h">>, P2}, {<<"p3@h">>, P3}]],
          {ok, Entries, []} = bouncer_keys:list_peers(O),
          ?assertMatch([#{comment := <<"first one">>}], [E || #{name := <<"p1@h">>} = E <- Entries]),
          ?assertMatch([#{comment := <<"some comment">>}], [E || #{name := <<"p2@h">>} = E <- Entries])
      end) end},
     {"invalid input writes nothing",
      fun() -> with_dir(fun(B) ->
          {_K, A, G} = node_dirs(B, "b"),
          Good = b64(new_pub()),
          [?assertMatch({2, <<>>, _}, add([N, Good], G))
           || N <- ["../x@y", "a/b@c", ""]],
          ?assertMatch({2, <<>>, _}, add(["a@h", "!!!notbase64"], G)),
          ?assertMatch({2, <<>>, _}, add(["a@h", b64(<<1, 2, 3>>)], G)),
          ?assertMatch({2, <<>>, _}, add(["a@h", b64(crypto:strong_rand_bytes(33))], G)),
          ?assertMatch({2, <<>>, _}, add(["a@h", Good, "--comment", "x\ny"], G)),
          ?assertMatch({2, <<>>, _}, add(["a@h"], G)),
          ?assertMatch({2, <<>>, _}, add(["a@h", Good, "extra"], G)),
          ?assertNot(filelib:is_dir(A))
      end) end},
     {"second add -> already present",
      fun() -> with_dir(fun(B) ->
          {_K, A, G} = node_dirs(B, "b"),
          Key = new_pub(),
          {0, _, _} = add(["a@h", b64(Key)], G),
          {0, Out, <<>>} = add(["a@h", b64(Key), "--comment", "changed"], G),
          ?assert(contains(Out, "already present")),
          ?assert(contains(Out, fp(Key))),
          ?assertEqual(1, dir_count(A))
      end) end},
     {"--fingerprint right / wrong / without prefix",
      fun() -> with_dir(fun(B) ->
          {_K, A, G} = node_dirs(B, "b"),
          Key = new_pub(),
          {4, <<>>, Err} = add(["a@h", b64(Key), "--fingerprint", fp(new_pub())], G),
          ?assert(contains(Err, fp(Key))),
          ?assertNot(filelib:is_dir(A)),
          {0, _, _} = add(["a@h", b64(Key), "--fingerprint", fp(Key)], G),
          Bare = lists:nthtail(7, fp(Key)),
          {0, _, _} = add(["a@h", b64(Key), "--fingerprint", Bare], G),
          {0, _, _} = add(["a@h", b64(Key), "--fingerprint=" ++ fp(Key)], G),
          ?assertEqual(1, dir_count(A))
      end) end},
     {"stdin with two lines -> usage error, nothing written",
      fun() -> with_dir(fun(B) ->
          {_K, A, G} = node_dirs(B, "b"),
          L = fun(N) -> ["p", N, "@h ", b64(new_pub()), "\n"] end,
          Stdin = unicode:characters_to_binary([L("1"), L("2")]),
          ?assertMatch({2, <<>>, _}, run(["add", "-" | G], #{stdin => Stdin})),
          ?assertMatch({2, <<>>, _}, run(["add", "-" | G], #{stdin => <<"\n">>})),
          ?assertNot(filelib:is_dir(A))
      end) end},
     {"add reads stdin through a fun",
      fun() -> with_dir(fun(B) ->
          {_K, _A, G} = node_dirs(B, "b"),
          Key = new_pub(),
          Line = unicode:characters_to_binary(["a@h ", b64(Key), "\n"]),
          {0, _, _} = run(["add", "-" | G], #{stdin => fun() -> Line end})
      end) end}].

%%% remove

remove_test_() ->
    [{"one entry",
      fun() -> with_dir(fun(B) ->
          {K, A, G} = node_dirs(B, "b"),
          Key = new_pub(),
          {0, _, _} = add(["a@h", b64(Key)], G),
          {0, Out, <<>>} = run(["remove", "a@h" | G]),
          ?assert(contains(Out, fp(Key))),
          ?assertEqual(unknown_name, bouncer_keys:check_peer(<<"a@h">>, Key, keys_opts(K, A)))
      end) end},
     {"several entries need --fingerprint or --all",
      fun() -> with_dir(fun(B) ->
          {K, A, G} = node_dirs(B, "b"),
          [K1, K2] = [new_pub(), new_pub()],
          {0, _, _} = add(["a@h", b64(K1)], G),
          {0, _, _} = add(["a@h", b64(K2)], G),
          {2, <<>>, Err} = run(["remove", "a@h" | G]),
          ?assert(contains(Err, fp(K1))),
          ?assert(contains(Err, fp(K2))),
          ?assertEqual(2, dir_count(A)),
          {0, _, _} = run(["remove", "a@h", "--fingerprint", fp(K1) | G]),
          O = keys_opts(K, A),
          ?assertEqual(denied, bouncer_keys:check_peer(<<"a@h">>, K1, O)),
          ?assertEqual(allowed, bouncer_keys:check_peer(<<"a@h">>, K2, O)),
          {0, _, _} = add(["a@h", b64(K1)], G),
          {0, _, _} = run(["remove", "a@h", "--all" | G]),
          ?assertEqual(unknown_name, bouncer_keys:check_peer(<<"a@h">>, K1, O)),
          ?assertEqual(unknown_name, bouncer_keys:check_peer(<<"a@h">>, K2, O))
      end) end},
     {"unknown name / fingerprint -> 1; conflicting options -> 2",
      fun() -> with_dir(fun(B) ->
          {_K, A, G} = node_dirs(B, "b"),
          Key = new_pub(),
          {0, _, _} = add(["a@h", b64(Key)], G),
          ?assertMatch({1, _, _}, run(["remove", "zz@h" | G])),
          ?assertMatch({1, _, _}, run(["remove", "a@h", "--fingerprint", fp(new_pub()) | G])),
          ?assertMatch({2, _, _}, run(["remove", "a@h", "--all", "--fingerprint", fp(Key) | G])),
          ?assertMatch({2, _, _}, run(["remove", "../x@y" | G])),
          ?assertEqual(1, dir_count(A))
      end) end}].

%%% show

show_test_() ->
    [{"show NAME: one entry, rotated keys, unknown",
      fun() -> with_dir(fun(B) ->
          {_K, A, G} = node_dirs(B, "b"),
          [K1, K2] = [new_pub(), new_pub()],
          {0, _, _} = add(["a@h", b64(K1), "--comment", "hello world"], G),
          {0, Out, <<>>} = run(["show", "a@h" | G]),
          [?assert(contains(Out, S)) || S <- ["a@h", fp(K1), b64(K1), "hello world", A, ".pub"]],
          {0, _, _} = add(["a@h", b64(K2)], G),
          {0, Out2, _} = run(["show", "a@h" | G]),
          [?assert(contains(Out2, S)) || S <- [fp(K1), fp(K2)]],
          ?assertMatch({1, <<>>, _}, run(["show", "zz@h" | G]))
      end) end},
     {"show --self with and without a key; never prints the secret",
      fun() -> with_dir(fun(B) ->
          {K, _A, G} = node_dirs(B, "a"),
          {1, <<>>, Err} = run(["show", "--self", "--node", "a@h" | G]),
          ?assert(contains(Err, "init")),
          ?assertNot(filelib:is_file(filename:join(K, "id_x25519"))),
          {0, InitOut, InitErr} = run(["init", "--node", "a@h" | G]),
          {0, Out, <<>>} = run(["show", "--self", "--node", "a@h" | G]),
          ?assertEqual(InitOut, Out),
          {ok, Secret} = file:read_file(filename:join(K, "id_x25519")),
          Sec = string:trim(Secret),
          [?assertNot(contains(O, Sec)) || O <- [InitOut, InitErr, Out]],
          {_, ShowOut, _} = run(["show", "a@h" | G]),
          ?assertNot(contains(ShowOut, Sec)),
          {_, HelpOut, _} = run(["--help"]),
          ?assertNot(contains(HelpOut, Sec))
      end) end}].

%%% list

list_test_() ->
    [{"sorted output, skipped files on stderr",
      fun() -> with_dir(fun(B) ->
          {_K, A, G} = node_dirs(B, "b"),
          [K1, K2, K3] = [new_pub() || _ <- [1, 2, 3]],
          {0, _, _} = add(["b@h", b64(K1)], G),
          {0, _, _} = add(["a@h", b64(K2)], G),
          {0, _, _} = add(["a@h", b64(K3)], G),
          Dot = filename:join(A, ".hidden.pub"),
          ok = file:write_file(Dot, "x"),
          ok = file:make_symlink(filename:join(A, "a@h." ++ hex(K2) ++ ".pub"), filename:join(A, "link.pub")),
          Big = filename:join(A, "big.pub"),
          ok = file:write_file(Big, binary:copy(<<"x">>, 5000)),
          ok = file:change_mode(Big, 8#644),
          Bad = filename:join(A, "bad.pub"),
          ok = file:write_file(Bad, "garbage\n"),
          ok = file:change_mode(Bad, 8#644),
          {0, Out, Err} = run(["list" | G]),
          Lines = [binary:split(L, <<"  ">>, [global]) || L <- binary:split(Out, <<"\n">>, [global, trim_all])],
          ?assertEqual(3, length(Lines)),
          Names = [N || [N | _] <- Lines],
          ?assertEqual([<<"a@h">>, <<"a@h">>, <<"b@h">>], Names),
          AFps = [F || [_, F, _] <- lists:sublist(Lines, 2)],
          ?assertEqual(AFps, lists:sort(AFps)),
          [?assert(contains(Err, S)) || S <- ["link.pub", "symlink", "big.pub", "too large", "bad.pub", "malformed"]],
          ?assertNot(contains(Err, ".hidden")),
          {0, Out, <<>>} = run(["list", "-q" | G])
      end) end},
     {"missing directory is empty; group-writable directory -> 3",
      fun() -> with_dir(fun(B) ->
          {_K, A, G} = node_dirs(B, "b"),
          ?assertEqual({0, <<>>, <<>>}, run(["list" | G])),
          ok = filelib:ensure_path(A),
          ok = file:change_mode(A, 8#775),
          {3, <<>>, Err} = run(["list" | G]),
          ?assert(contains(Err, "refused"))
      end) end},
     {"all authorized directories are listed",
      fun() -> with_dir(fun(B) ->
          A1 = filename:join(B, "a1"), A2 = filename:join(B, "a2"),
          {0, _, _} = run(["add", "x@h", b64(new_pub()), "--authorized-dir", A1, "--authorized-dir", A2]),
          {0, _, _} = run(["add", "y@h", b64(new_pub()), "--authorized-dir", A2, "--authorized-dir", A1]),
          {0, Out, _} = run(["list", "--authorized-dir", A1, "--authorized-dir", A2]),
          ?assertEqual(2, length(binary:split(Out, <<"\n">>, [global, trim_all]))),
          ?assertEqual(1, dir_count(A1)),
          ?assertEqual(1, dir_count(A2))
      end) end},
     {"needs a directory or a node",
      fun() ->
          case {os:getenv("BOUNCER_DIR"), os:getenv("BOUNCER_AUTHORIZED_DIRS")} of
              {false, false} -> ?assertMatch({2, _, _}, run(["list"]));
              _ -> ok
          end
      end}].

hex(K) ->
    <<H:12/binary, _/binary>> = binary:encode_hex(crypto:hash(sha256, K), lowercase),
    binary_to_list(H).

%%% check

check_test_() ->
    [{"match, mismatch, unknown",
      fun() -> with_dir(fun(B) ->
          {_K, _A, G} = node_dirs(B, "b"),
          [K1, K2] = [new_pub(), new_pub()],
          {0, _, _} = add(["a@h", b64(K1)], G),
          {0, <<"ok\n">>, <<>>} = run(["check", "a@h", fp(K1) | G]),
          {0, <<"ok\n">>, <<>>} = run(["check", "a@h", lists:nthtail(7, fp(K1)) | G]),
          {0, <<>>, <<>>} = run(["check", "-q", "a@h", fp(K1) | G]),
          {4, _, Err} = run(["check", "a@h", fp(K2) | G]),
          ?assert(contains(Err, fp(K1))),
          {4, _, _} = run(["check", "a@h", string:lowercase(fp(K1)) | G]),
          {1, _, _} = run(["check", "zz@h", fp(K1) | G]),
          {2, _, _} = run(["check", "a@h" | G])
      end) end}].

%%% general

usage_test_() ->
    [{"unknown command/option, no args, help",
      fun() ->
          ?assertMatch({2, <<>>, _}, run(["frobnicate"])),
          ?assertMatch({2, <<>>, _}, run([])),
          ?assertMatch({2, <<>>, _}, run(["list", "--bogus"])),
          ?assertMatch({2, <<>>, _}, run(["init", "--node"])),
          ?assertMatch({2, <<>>, _}, run(["list", "--dir"])),
          {0, Out, <<>>} = run(["--help"]),
          ?assert(contains(Out, "NEW handshakes")),
          ?assertMatch({0, _, <<>>}, run(["add", "--help"]))
      end},
     {"-q suppresses everything except primary values",
      fun() -> with_dir(fun(B) ->
          {_K, _A, G} = node_dirs(B, "a"),
          Key = new_pub(),
          {0, InitOut, <<>>} = run(["init", "-q", "--node", "a@h" | G]),
          ?assertEqual(1, length(binary:split(InitOut, <<"\n">>, [global, trim_all]))),
          {0, AddOut, <<>>} = add(["b@h", b64(Key), "-q"], G),
          ?assertEqual(list_to_binary(fp(Key) ++ "\n"), AddOut),
          {0, <<>>, <<>>} = run(["remove", "-q", "b@h" | G])
      end) end}].

%%% workflow

two_node_workflow_test() ->
    with_dir(fun(B) ->
        {KA, AA, GA} = node_dirs(B, "a"),
        {KB, AB, GB} = node_dirs(B, "b"),
        {0, OutA, _} = run(["init", "--node", "a@h" | GA]),
        {0, OutB, _} = run(["init", "--node", "b@h" | GB]),
        {0, _, _} = run(["add", "-" | GB], #{stdin => OutA}),
        {0, _, _} = run(["add", "-" | GA], #{stdin => OutB}),
        {ok, IA} = bouncer_keys:load_or_generate(<<"a@h">>, (keys_opts(KA, AA))#{generate => false}),
        {ok, IB} = bouncer_keys:load_or_generate(<<"b@h">>, (keys_opts(KB, AB))#{generate => false}),
        PubA = bouncer_keys:public(IA),
        PubB = bouncer_keys:public(IB),
        ?assertEqual(allowed, bouncer_keys:check_peer(<<"a@h">>, PubA, keys_opts(KB, AB))),
        ?assertEqual(allowed, bouncer_keys:check_peer(<<"b@h">>, PubB, keys_opts(KA, AA))),
        ?assertEqual(denied, bouncer_keys:check_peer(<<"a@h">>, PubB, keys_opts(KB, AB))),
        {0, _, _} = run(["check", "a@h", fp(PubA) | GB]),
        {0, _, _} = run(["remove", "a@h" | GB]),
        ?assertEqual(unknown_name, bouncer_keys:check_peer(<<"a@h">>, PubA, keys_opts(KB, AB)))
    end).

%% Runs every command in a fresh VM whose code path has no enoise.
no_enoise_test_() ->
    {timeout, 60, fun() -> with_dir(fun(B) ->
        Ebin = filename:dirname(code:which(bouncer_guests)),
        {ok, Peer, _Node} = peer:start_link(#{args => ["-pa", Ebin], connection => standard_io}),
        try
            ?assertEqual({error, nofile}, peer:call(Peer, code, ensure_loaded, [enoise_keypair])),
            {_, _, G} = node_dirs(B, "a"),
            Key = b64(new_pub()),
            Cmds = [["init", "--node", "a@h" | G], ["show", "--self", "--node", "a@h" | G],
                    ["add", "b@h", Key | G], ["list" | G], ["show", "b@h" | G],
                    ["check", "b@h", fp(base64:decode(Key)) | G], ["remove", "b@h" | G]],
            [?assertMatch({0, _, _}, peer:call(Peer, bouncer_guests, run, [C, #{}])) || C <- Cmds],
            ?assertEqual(false, peer:call(Peer, code, is_loaded, [enoise])),
            ?assertEqual(false, peer:call(Peer, code, is_loaded, [enoise_keypair]))
        after
            peer:stop(Peer)
        end
    end) end}.
