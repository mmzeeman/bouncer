-module(noisegate_keys_tests).
-include_lib("eunit/include/eunit.hrl").
-include_lib("kernel/include/file.hrl").

-export([log/2]).

%%% Helpers

with_dir(Fun) ->
    Base = "/tmp/noisegate_keys_test_" ++ integer_to_list(erlang:unique_integer([positive]))
        ++ "_" ++ os:getpid(),
    ok = file:make_dir(Base),
    try
        Fun(Base)
    after
        file:del_dir_r(Base)
    end.

%% Runs Fun(Dir) with logger events forwarded to the test process; returns {Result, Messages}.
with_log(Fun) ->
    Id = list_to_atom("noisegate_keys_test_h" ++ integer_to_list(erlang:unique_integer([positive]))),
    #{level := OldLevel} = logger:get_primary_config(),
    ok = logger:set_primary_config(level, all),
    ok = logger:add_handler(Id, ?MODULE, #{config => #{pid => self()}}),
    try
        Result = Fun(),
        {Result, collect_logs([])}
    after
        logger:remove_handler(Id),
        logger:set_primary_config(level, OldLevel)
    end.

log(Event, #{config := #{pid := Pid}}) ->
    Pid ! {noisegate_log, lists:flatten(logger_formatter:format(Event, #{single_line => true,
                                                                       template => [msg]}))},
    ok.

collect_logs(Acc) ->
    receive {noisegate_log, M} -> collect_logs([M | Acc]) after 0 -> lists:reverse(Acc) end.

keyopts(Base) -> #{dir => filename:join(Base, "key")}.

mode(Path) ->
    {ok, #file_info{mode = M}} = file:read_link_info(Path),
    M band 8#777.

mkdir(Dir, Mode) ->
    ok = filelib:ensure_path(Dir),
    ok = file:change_mode(Dir, Mode).

write_pub(Dir, File, Content) ->
    Path = filename:join(Dir, File),
    ok = file:write_file(Path, Content),
    ok = file:change_mode(Path, 8#644),
    Path.

new_pub() ->
    {Pub, _} = crypto:generate_key(ecdh, x25519),
    Pub.

auth_opts(Base) ->
    Dir = filename:join(Base, "auth"),
    mkdir(Dir, 8#755),
    {Dir, #{authorized_dirs => [Dir], node_name => <<"me@host">>}}.

dotfiles(Dir) ->
    {ok, Names} = file:list_dir(Dir),
    [N || [$. | _] = N <- Names].

%%% Identity key

identity_test_() ->
    [{"generate, then load",
      fun() -> with_dir(fun(B) ->
          O = keyopts(B),
          Dir = maps:get(dir, O),
          {ok, Info1} = noisegate_keys:load_or_generate(<<"a@h">>, O),
          Pub = noisegate_keys:public(Info1),
          Sec = noisegate_keys:secret(Info1),
          ?assert(noisegate_keys:generated(Info1)),
          ?assertEqual(8#600, mode(filename:join(Dir, "id_x25519"))),
          ?assertEqual(8#700, mode(Dir)),
          ?assertEqual({Pub, Sec}, crypto:generate_key(ecdh, x25519, Sec)),
          {ok, Info2} = noisegate_keys:load_or_generate(<<"a@h">>, O),
          ?assertNot(noisegate_keys:generated(Info2)),
          ?assertEqual(Pub, noisegate_keys:public(Info2)),
          ?assertEqual(Sec, noisegate_keys:secret(Info2)),
          ?assertEqual([], dotfiles(Dir))
      end) end},
     {"existing directory mode is never loosened",
      fun() -> with_dir(fun(B) ->
          O = keyopts(B),
          Dir = maps:get(dir, O),
          mkdir(Dir, 8#750),
          {ok, _} = noisegate_keys:load_or_generate(<<"a@h">>, O),
          ?assertEqual(8#750, mode(Dir))
      end) end},
     {"mode 0644 key refused",
      fun() -> with_dir(fun(B) ->
          O = keyopts(B),
          {ok, _} = noisegate_keys:load_or_generate(<<"a@h">>, O),
          Path = filename:join(maps:get(dir, O), "id_x25519"),
          ok = file:change_mode(Path, 8#644),
          ?assertEqual({error, {insecure_permissions, Path}},
                       noisegate_keys:load_or_generate(<<"a@h">>, O))
      end) end},
     {"symlinked key refused",
      fun() -> with_dir(fun(B) ->
          O = keyopts(B),
          Dir = maps:get(dir, O),
          mkdir(Dir, 8#700),
          Real = filename:join(B, "real"),
          ok = file:write_file(Real, base64:encode(crypto:strong_rand_bytes(32))),
          ok = file:change_mode(Real, 8#600),
          ok = file:make_symlink(Real, filename:join(Dir, "id_x25519")),
          ?assertMatch({error, {symlink_refused, _}}, noisegate_keys:load_or_generate(<<"a@h">>, O))
      end) end},
     {"wrong length and invalid base64",
      fun() -> with_dir(fun(B) ->
          O = keyopts(B),
          Dir = maps:get(dir, O),
          mkdir(Dir, 8#700),
          Path = filename:join(Dir, "id_x25519"),
          lists:foreach(fun(Content) ->
              ok = file:write_file(Path, Content),
              ok = file:change_mode(Path, 8#600),
              ?assertMatch({error, {bad_key, Path}}, noisegate_keys:load_or_generate(<<"a@h">>, O))
          end, [base64:encode(crypto:strong_rand_bytes(31)), <<"!!!not base64!!!">>, <<>>])
      end) end},
     {"generate false creates nothing",
      fun() -> with_dir(fun(B) ->
          O = (keyopts(B))#{generate => false},
          Path = filename:join(maps:get(dir, O), "id_x25519"),
          ?assertEqual({error, {no_key, Path}}, noisegate_keys:load_or_generate(<<"a@h">>, O)),
          ?assertEqual({ok, []}, file:list_dir(B))
      end) end},
     {"keygen option honored",
      fun() -> with_dir(fun(B) ->
          Sec = crypto:strong_rand_bytes(32),
          O = (keyopts(B))#{keygen => fun() -> {<<>>, Sec} end},
          {ok, Info} = noisegate_keys:load_or_generate(<<"a@h">>, O),
          ?assertEqual(Sec, noisegate_keys:secret(Info)),
          ?assert(noisegate_keys:generated(Info)),
          ?assertMatch({error, bad_keygen},
                       noisegate_keys:load_or_generate(<<"b@h">>,
                           (keyopts(filename:join(B, "x")))#{keygen => fun() -> {<<>>, <<1>>} end}))
      end) end},
     {"20 concurrent starters agree on one key",
      {timeout, 60, fun() -> with_dir(fun(B) ->
          O = keyopts(B),
          Dir = maps:get(dir, O),
          Me = self(),
          Watcher = spawn_link(fun() -> watch(Dir, Me, []) end),
          Pids = [spawn_monitor(fun() ->
                      receive go -> ok end,
                      Me ! {result, self(), noisegate_keys:load_or_generate(<<"a@h">>, O)}
                  end) || _ <- lists:seq(1, 20)],
          [P ! go || {P, _} <- Pids],
          Results = [receive {result, P, R} -> R end || {P, _} <- Pids],
          Watcher ! stop,
          Loose = receive {watch_done, L} -> L end,
          ?assertEqual([], Loose),
          [{ok, First} | _] = Results,
          Pub = noisegate_keys:public(First),
          ?assert(lists:all(fun({ok, I}) -> noisegate_keys:public(I) =:= Pub end, Results)),
          ?assertEqual(1, length([x || {ok, I} <- Results, noisegate_keys:generated(I)])),
          ?assertEqual([], dotfiles(Dir))
      end) end}},
     {"temp file never has loose permissions or leftovers",
      fun() -> with_dir(fun(B) ->
          O = keyopts(B),
          Dir = maps:get(dir, O),
          Check = fun() ->
              {ok, Names} = file:list_dir(Dir),
              [] = [N || N <- Names, N =/= "id_x25519"],
              crypto:generate_key(ecdh, x25519)
          end,
          {ok, _} = noisegate_keys:load_or_generate(<<"a@h">>, O#{keygen => Check}),
          ?assertEqual([], dotfiles(Dir)),
          {ok, #file_info{size = Size}} = file:read_file_info(filename:join(Dir, "id_x25519")),
          ?assertEqual(45, Size)
      end) end},
     {"secret never logged",
      fun() -> with_dir(fun(B) ->
          Sec = crypto:strong_rand_bytes(32),
          O = (keyopts(B))#{keygen => fun() -> {<<>>, Sec} end},
          {_, Logs} = with_log(fun() ->
              {ok, _} = noisegate_keys:load_or_generate(<<"a@h">>, O),
              {ok, _} = noisegate_keys:load_or_generate(<<"a@h">>, O)
          end),
          ?assert(Logs =/= []),
          All = lists:flatten(Logs),
          Forbidden = [binary_to_list(base64:encode(Sec)),
                       binary_to_list(binary:encode_hex(Sec)),
                       lists:flatten(io_lib:format("~w", [binary_to_list(Sec)])),
                       lists:flatten(io_lib:format("~p", [Sec]))],
          [?assertEqual(nomatch, string:find(All, F, leading), F) || F <- Forbidden]
      end) end}].

watch(Dir, Parent, Loose) ->
    receive
        stop -> Parent ! {watch_done, Loose}
    after 0 ->
        case file:list_dir(Dir) of
            {ok, Names} ->
                Bad = [N || N <- Names,
                            case file:read_link_info(filename:join(Dir, N)) of
                                {ok, #file_info{size = S, mode = M}} ->
                                    S > 0 andalso (M band 8#077) =/= 0;
                                _ -> false
                            end],
                watch(Dir, Parent, Bad ++ Loose);
            {error, enoent} ->
                receive
                    stop -> Parent ! {watch_done, Loose}
                after 1 ->
                    watch(Dir, Parent, Loose)
                end;
            {error, Reason} ->
                exit({watch_list_dir, Reason})
        end
    end.

%%% Node names

valid_node_name_test_() ->
    [?_assert(noisegate_keys:valid_node_name(<<"a@b">>)),
     ?_assert(noisegate_keys:valid_node_name(<<"a_b-c.d@host.example.com">>)),
     [?_assertNot(noisegate_keys:valid_node_name(N)) ||
         N <- [<<"../x@y">>, <<"a/b@c">>, <<"a@b/../c">>, <<".a@b">>, <<"a@.b">>, <<>>,
               <<"a@b..c">>, <<"a@b@c">>, <<"@b">>, <<"a@">>, <<"a@b\n">>, <<"a b@c">>,
               "a@b", a, <<"é@b"/utf8>>]],
     ?_assertNot(noisegate_keys:valid_node_name(binary:copy(<<"a">>, 256))),
     ?_assert(noisegate_keys:valid_node_name(<<(binary:copy(<<"a">>, 126))/binary, "@",
                                           (binary:copy(<<"b">>, 128))/binary>>))].

%%% Authorized directory

check_peer_test_() ->
    [{"allowed, denied, unknown_name",
      fun() -> with_dir(fun(B) ->
          {Dir, O} = auth_opts(B),
          K = new_pub(),
          write_pub(Dir, "a.1.pub", noisegate_keys:authorized_line(<<"a@h">>, K)),
          ?assertEqual(allowed, noisegate_keys:check_peer(<<"a@h">>, K, O)),
          ?assertEqual(denied, noisegate_keys:check_peer(<<"a@h">>, new_pub(), O)),
          ?assertEqual(unknown_name, noisegate_keys:check_peer(<<"b@h">>, K, O)),
          ?assertEqual(denied, noisegate_keys:check_peer(<<"a@h">>, <<1, 2>>, O))
      end) end},
     {"comment and newline handling, rotation",
      fun() -> with_dir(fun(B) ->
          {Dir, O} = auth_opts(B),
          K1 = new_pub(), K2 = new_pub(), K3 = new_pub(),
          B1 = base64:encode(K1), B2 = base64:encode(K2), B3 = base64:encode(K3),
          write_pub(Dir, "a.1.pub", <<"a@h ", B1/binary, " my laptop, 2024">>),
          write_pub(Dir, "a.2.pub", <<"a@h\t", B2/binary, "\n\n">>),
          write_pub(Dir, "a.3.pub", <<"\n", "a@h ", B3/binary, "\r\n">>),
          [?assertEqual(allowed, noisegate_keys:check_peer(<<"a@h">>, K, O)) || K <- [K1, K2, K3]]
      end) end},
     {"malformed files skipped, others load",
      fun() -> with_dir(fun(B) ->
          {Dir, O} = auth_opts(B),
          K = new_pub(),
          Enc = base64:encode(K),
          write_pub(Dir, "bad1.pub", <<"a@h not-base64!!\n">>),
          write_pub(Dir, "bad2.pub", <<"a@h ", (base64:encode(<<1, 2, 3>>))/binary, "\n">>),
          write_pub(Dir, "bad3.pub", <<"../x@h ", Enc/binary, "\n">>),
          write_pub(Dir, "bad4.pub", <<"a@h ", Enc/binary, "\nb@h ", Enc/binary, "\n">>),
          write_pub(Dir, "bad5.pub", <<>>),
          write_pub(Dir, "bad6.pub", <<"a@h\n">>),
          write_pub(Dir, "good.pub", noisegate_keys:authorized_line(<<"g@h">>, K)),
          {R, Logs} = with_log(fun() -> noisegate_keys:check_peer(<<"g@h">>, K, O) end),
          ?assertEqual(allowed, R),
          ?assertEqual(6, length(Logs))
      end) end},
     {"changes are picked up on the next call",
      fun() -> with_dir(fun(B) ->
          {Dir, O} = auth_opts(B),
          K = new_pub(),
          ?assertEqual(unknown_name, noisegate_keys:check_peer(<<"a@h">>, K, O)),
          P = write_pub(Dir, "a.pub", noisegate_keys:authorized_line(<<"a@h">>, K)),
          ?assertEqual(allowed, noisegate_keys:check_peer(<<"a@h">>, K, O)),
          ok = file:delete(P),
          ?assertEqual(unknown_name, noisegate_keys:check_peer(<<"a@h">>, K, O))
      end) end},
     {"missing directory is empty and silent",
      fun() -> with_dir(fun(B) ->
          O = #{authorized_dirs => [filename:join(B, "nope")], node_name => <<"me@h">>},
          {R, Logs} = with_log(fun() -> noisegate_keys:check_peer(<<"a@h">>, new_pub(), O) end),
          ?assertEqual({unknown_name, []}, {R, Logs})
      end) end},
     {"ignored: dotfiles, non-.pub, symlinks, directories, big files",
      fun() -> with_dir(fun(B) ->
          {Dir, O} = auth_opts(B),
          K = new_pub(),
          Line = noisegate_keys:authorized_line(<<"a@h">>, K),
          write_pub(Dir, ".hidden.pub", Line),
          write_pub(Dir, "a.txt", Line),
          write_pub(Dir, "big.pub", <<Line/binary, "# ", (binary:copy(<<"x">>, 4096))/binary>>),
          Real = write_pub(B, "real", Line),
          ok = file:make_symlink(Real, filename:join(Dir, "link.pub")),
          ok = file:make_dir(filename:join(Dir, "dir.pub")),
          {R, Logs} = with_log(fun() -> noisegate_keys:check_peer(<<"a@h">>, K, O) end),
          ?assertEqual(unknown_name, R),
          ?assert(lists:any(fun(M) -> string:find(M, "symlink refused") =/= nomatch end, Logs))
      end) end},
     {"file of exactly 4096 bytes is accepted",
      fun() -> with_dir(fun(B) ->
          {Dir, O} = auth_opts(B),
          K = new_pub(),
          Line = noisegate_keys:authorized_line(<<"a@h">>, K),
          Pad = binary:copy(<<"x">>, 4096 - byte_size(Line) - 1),
          write_pub(Dir, "a.pub", <<(binary:part(Line, 0, byte_size(Line) - 1))/binary, " ",
                                    Pad/binary>>),
          ?assertEqual(allowed, noisegate_keys:check_peer(<<"a@h">>, K, O))
      end) end},
     {"group/other writable directory or file refused",
      fun() -> with_dir(fun(B) ->
          {Dir, O} = auth_opts(B),
          K = new_pub(),
          Line = noisegate_keys:authorized_line(<<"a@h">>, K),
          P = write_pub(Dir, "a.pub", Line),
          ok = file:change_mode(P, 8#664),
          {R1, L1} = with_log(fun() -> noisegate_keys:check_peer(<<"a@h">>, K, O) end),
          ?assertEqual(unknown_name, R1),
          ?assert(lists:any(fun(M) -> string:find(M, P) =/= nomatch end, L1)),
          ok = file:change_mode(P, 8#644),
          ?assertEqual(allowed, noisegate_keys:check_peer(<<"a@h">>, K, O)),
          ok = file:change_mode(Dir, 8#757),
          {R2, L2} = with_log(fun() -> noisegate_keys:check_peer(<<"a@h">>, K, O) end),
          ?assertEqual(unknown_name, R2),
          ?assert(lists:any(fun(M) -> string:find(M, Dir) =/= nomatch end, L2))
      end) end},
     {"invalid names never touch the filesystem",
      fun() -> with_dir(fun(B) ->
          {Dir, O} = auth_opts(B),
          K = new_pub(),
          write_pub(Dir, "a.pub", noisegate_keys:authorized_line(<<"x@y">>, K)),
          ok = file:change_mode(Dir, 8#777),
          Missing = #{authorized_dirs => [filename:join(B, "missing")], node_name => <<"me@h">>},
          Names = [<<"../x@y">>, <<"a/b@c">>, <<"a@b/../c">>, <<".a@b">>, <<>>],
          {Rs, Logs} = with_log(fun() ->
              [{noisegate_keys:check_peer(N, K, O), noisegate_keys:check_peer(N, K, Missing)}
               || N <- Names]
          end),
          ?assertEqual([{unknown_name, unknown_name} || _ <- Names], Rs),
          ?assertEqual([], Logs),
          %% sanity: a valid name does read the (world-writable) directory and logs
          {_, Logs2} = with_log(fun() -> noisegate_keys:check_peer(<<"x@y">>, K, O) end),
          ?assertNotEqual([], Logs2)
      end) end},
     {"union of directories",
      fun() -> with_dir(fun(B) ->
          D1 = filename:join(B, "d1"), D2 = filename:join(B, "d2"),
          mkdir(D1, 8#755), mkdir(D2, 8#755),
          K1 = new_pub(), K2 = new_pub(),
          write_pub(D1, "a.pub", noisegate_keys:authorized_line(<<"a@h">>, K1)),
          write_pub(D2, "b.pub", noisegate_keys:authorized_line(<<"b@h">>, K2)),
          O = #{authorized_dirs => D1 ++ ":" ++ D2, node_name => <<"me@h">>},
          ?assertEqual(allowed, noisegate_keys:check_peer(<<"a@h">>, K1, O)),
          ?assertEqual(allowed, noisegate_keys:check_peer(<<"b@h">>, K2, O)),
          ?assertEqual(denied, noisegate_keys:check_peer(<<"b@h">>, K1, O))
      end) end}].

add_remove_test_() ->
    [{"add_peer is idempotent; remove_peer revokes",
      fun() -> with_dir(fun(B) ->
          Dir = filename:join(B, "new_auth"),
          O = #{authorized_dirs => [Dir], node_name => <<"me@h">>},
          K = new_pub(),
          {ok, P} = noisegate_keys:add_peer(<<"a@h">>, K, O),
          ?assertEqual({ok, P}, noisegate_keys:add_peer(<<"a@h">>, K, O)),
          ?assertEqual(8#755, mode(Dir)),
          ?assertEqual(8#644, mode(P)),
          <<Hex:12/binary, _/binary>> = binary:encode_hex(crypto:hash(sha256, K), lowercase),
          ?assertEqual("a@h." ++ binary_to_list(Hex) ++ ".pub", filename:basename(P)),
          ?assertEqual([], dotfiles(Dir)),
          ?assertEqual(allowed, noisegate_keys:check_peer(<<"a@h">>, K, O)),
          ?assertEqual({error, not_found},
                       noisegate_keys:remove_peer(<<"a@h">>, noisegate_keys:fingerprint(new_pub()), O)),
          ?assertEqual({error, not_found},
                       noisegate_keys:remove_peer(<<"b@h">>, noisegate_keys:fingerprint(K), O)),
          ?assertEqual(ok, noisegate_keys:remove_peer(<<"a@h">>, noisegate_keys:fingerprint(K), O)),
          ?assertEqual(unknown_name, noisegate_keys:check_peer(<<"a@h">>, K, O)),
          ?assertEqual({error, not_found},
                       noisegate_keys:remove_peer(<<"a@h">>, noisegate_keys:fingerprint(K), O))
      end) end},
     {"concurrent add_peer for different peers",
      fun() -> with_dir(fun(B) ->
          Dir = filename:join(B, "auth"),
          O = #{authorized_dirs => [Dir], node_name => <<"me@h">>},
          Me = self(),
          Peers = [{iolist_to_binary(["p", integer_to_list(I), "@h"]), new_pub()}
                   || I <- lists:seq(1, 20)],
          Pids = [spawn_link(fun() -> Me ! {done, self(), noisegate_keys:add_peer(N, K, O)} end)
                  || {N, K} <- Peers],
          Rs = [receive {done, P, R} -> R end || P <- Pids],
          ?assert(lists:all(fun({ok, _}) -> true; (_) -> false end, Rs)),
          [?assertEqual(allowed, noisegate_keys:check_peer(N, K, O)) || {N, K} <- Peers],
          ?assertEqual([], dotfiles(Dir))
      end) end},
     {"add_peer validates input",
      fun() -> with_dir(fun(B) ->
          Dir = filename:join(B, "auth"),
          O = #{authorized_dirs => [Dir], node_name => <<"me@h">>},
          ?assertEqual({error, invalid_name}, noisegate_keys:add_peer(<<"../a@h">>, new_pub(), O)),
          ?assertEqual({error, invalid_name}, noisegate_keys:add_peer(<<>>, new_pub(), O)),
          ?assertEqual({error, invalid_key}, noisegate_keys:add_peer(<<"a@h">>, <<1, 2, 3>>, O)),
          ?assertEqual({error, invalid_key}, noisegate_keys:add_peer(<<"a@h">>, <<>>, O)),
          ?assertNot(filelib:is_dir(Dir))
      end) end},
     {"fingerprint format and stability",
      fun() ->
          K = <<0:256>>,
          F = noisegate_keys:fingerprint(K),
          ?assertEqual(F, noisegate_keys:fingerprint(K)),
          ?assertMatch(<<"SHA256:", _/binary>>, F),
          ?assertEqual(7 + 43, byte_size(F)),
          ?assertNotEqual(F, noisegate_keys:fingerprint(<<1:256>>))
      end},
     {"authorized_line round-trips through the loader",
      fun() -> with_dir(fun(B) ->
          {Dir, O} = auth_opts(B),
          K = new_pub(),
          Line = noisegate_keys:authorized_line(<<"a@h">>, K),
          ?assertMatch(<<"a@h ", _/binary>>, Line),
          ?assertEqual($\n, binary:last(Line)),
          write_pub(Dir, "a.pub", Line),
          ?assertEqual(allowed, noisegate_keys:check_peer(<<"a@h">>, K, O))
      end) end}].

settings_test_() ->
    [{"dir and authorized_dirs defaults and overrides",
      fun() ->
          ?assertEqual("/k", noisegate_keys:node_key_dir(<<"a@h">>, #{dir => "/k"})),
          ?assertEqual(["/k/authorized.d"], noisegate_keys:authorized_dirs(<<"a@h">>, #{dir => "/k"})),
          ?assertEqual(["/x", "/y"],
                       noisegate_keys:authorized_dirs(<<"a@h">>, #{dir => "/k", authorized_dirs => "/x::/y"})),
          ?assertEqual(["/x", "/y"],
                       noisegate_keys:authorized_dirs(<<"a@h">>, #{authorized_dirs => ["/x", "/y"]})),
          ?assertEqual(filename:join(filename:basedir(user_config, "noisegate"), "a@h"),
                       noisegate_keys:node_key_dir(a@h, #{})),
          ?assertError(badarg, noisegate_keys:node_key_dir(<<"../a">>, #{}))
      end}].

%%% list_peers/1, ensure_dirs/2, add_peer/3 comment

list_peers_test_() ->
    [{"lists entries with the same rules as check_peer; reports skipped files",
      fun() -> with_dir(fun(B) ->
          {Dir, O} = auth_opts(B),
          K1 = new_pub(), K2 = new_pub(),
          write_pub(Dir, "a.pub", <<"a@h ", (base64:encode(K1))/binary, " my  comment\n">>),
          write_pub(Dir, "b.pub", noisegate_keys:authorized_line(<<"b@h">>, K2)),
          write_pub(Dir, ".dot.pub", noisegate_keys:authorized_line(<<"c@h">>, K2)),
          write_pub(Dir, "notpub.txt", noisegate_keys:authorized_line(<<"c@h">>, K2)),
          write_pub(Dir, "bad.pub", <<"nonsense\n">>),
          write_pub(Dir, "big.pub", binary:copy(<<"x">>, 5000)),
          Loose = write_pub(Dir, "loose.pub", noisegate_keys:authorized_line(<<"d@h">>, K2)),
          ok = file:change_mode(Loose, 8#666),
          Real = write_pub(B, "real.pub", noisegate_keys:authorized_line(<<"e@h">>, K2)),
          ok = file:make_symlink(Real, filename:join(Dir, "link.pub")),
          {ok, Entries, Skips} = noisegate_keys:list_peers(O),
          ?assertMatch([#{name := <<"a@h">>, key := K1, comment := <<"my comment">>, dir := Dir},
                        #{name := <<"b@h">>, key := K2, comment := <<>>}],
                       Entries),
          [#{fingerprint := Fp, file := File}, _] = Entries,
          ?assertEqual(binary_to_list(noisegate_keys:fingerprint(K1)), Fp),
          ?assertEqual(filename:join(Dir, "a.pub"), File),
          Reasons = maps:from_list([{filename:basename(F), R} || #{file := F, reason := R} <- Skips]),
          ?assertEqual(#{"bad.pub" => {malformed, missing_fields}, "big.pub" => too_large,
                         "loose.pub" => group_or_other_writable,
                         "link.pub" => symlink_refused}, Reasons),
          [?assertEqual(allowed, noisegate_keys:check_peer(N, K, O))
           || {N, K} <- [{<<"a@h">>, K1}, {<<"b@h">>, K2}]],
          [?assertEqual(unknown_name, noisegate_keys:check_peer(N, K2, O))
           || N <- [<<"c@h">>, <<"d@h">>, <<"e@h">>]]
      end) end},
     {"missing directory is empty; refused directories are errors",
      fun() -> with_dir(fun(B) ->
          Missing = filename:join(B, "nope"),
          ?assertEqual({ok, [], []}, noisegate_keys:list_peers(#{authorized_dirs => [Missing], node_name => <<"me@h">>})),
          {Dir, O} = auth_opts(B),
          ok = file:change_mode(Dir, 8#775),
          ?assertMatch({error, {refused_dir, Dir, group_or_other_writable}}, noisegate_keys:list_peers(O)),
          File = filename:join(B, "file"),
          ok = file:write_file(File, ""),
          ?assertMatch({error, {refused_dir, File, not_a_directory}},
                       noisegate_keys:list_peers(#{authorized_dirs => [File], node_name => <<"me@h">>}))
      end) end},
     {"several directories are concatenated in order",
      fun() -> with_dir(fun(B) ->
          D1 = filename:join(B, "d1"), D2 = filename:join(B, "d2"),
          mkdir(D1, 8#755), mkdir(D2, 8#755),
          write_pub(D1, "x.pub", noisegate_keys:authorized_line(<<"x@h">>, new_pub())),
          write_pub(D2, "y.pub", noisegate_keys:authorized_line(<<"y@h">>, new_pub())),
          {ok, [#{name := <<"x@h">>}, #{name := <<"y@h">>}], []} =
              noisegate_keys:list_peers(#{authorized_dirs => [D1, D2], node_name => <<"me@h">>})
      end) end}].

ensure_dirs_test_() ->
    [{"creates key dir 0700 and authorized dir 0755, creates no key",
      fun() -> with_dir(fun(B) ->
          O = keyopts(B),
          ?assertEqual(ok, noisegate_keys:ensure_dirs(<<"a@h">>, O)),
          Key = maps:get(dir, O),
          ?assertEqual(8#700, mode(Key)),
          ?assertEqual(8#755, mode(filename:join(Key, "authorized.d"))),
          ?assertEqual([], [N || N <- element(2, file:list_dir(Key)), N =/= "authorized.d"])
      end) end},
     {"existing directories are never loosened; invalid names rejected",
      fun() -> with_dir(fun(B) ->
          O = keyopts(B),
          Key = maps:get(dir, O),
          mkdir(Key, 8#750),
          ?assertEqual(ok, noisegate_keys:ensure_dirs(<<"a@h">>, O)),
          ?assertEqual(8#750, mode(Key)),
          ?assertEqual({error, invalid_node_name}, noisegate_keys:ensure_dirs(<<"../a">>, O#{dir => "/nonexistent/x"})),
          ?assertEqual({error, invalid_node_name}, noisegate_keys:ensure_dirs(<<>>, O))
      end) end}].

add_peer_comment_test_() ->
    [{"comment is stored as `name key comment`; format stays loadable",
      fun() -> with_dir(fun(B) ->
          {Dir, O} = auth_opts(B),
          K = new_pub(),
          {ok, P} = noisegate_keys:add_peer(<<"a@h">>, K, O#{comment => "build server"}),
          ?assertEqual({ok, <<"a@h ", (base64:encode(K))/binary, " build server\n">>}, file:read_file(P)),
          ?assertEqual({ok, P}, noisegate_keys:add_peer(<<"a@h">>, K, O#{comment => <<"build server">>})),
          ?assertEqual(allowed, noisegate_keys:check_peer(<<"a@h">>, K, O)),
          ?assertMatch({ok, [#{comment := <<"build server">>, dir := Dir}], []}, noisegate_keys:list_peers(O))
      end) end},
     {"no comment: file unchanged; multi-line comments rejected",
      fun() -> with_dir(fun(B) ->
          {Dir, O} = auth_opts(B),
          K = new_pub(),
          {ok, P} = noisegate_keys:add_peer(<<"a@h">>, K, O),
          ?assertEqual({ok, noisegate_keys:authorized_line(<<"a@h">>, K)}, file:read_file(P)),
          {ok, P2} = noisegate_keys:add_peer(<<"b@h">>, K, O#{comment => <<>>}),
          ?assertEqual({ok, noisegate_keys:authorized_line(<<"b@h">>, K)}, file:read_file(P2)),
          ?assertEqual({error, invalid_comment}, noisegate_keys:add_peer(<<"c@h">>, K, O#{comment => "a\nb"})),
          ?assertEqual({error, invalid_comment}, noisegate_keys:add_peer(<<"c@h">>, K, O#{comment => <<"a\rb">>})),
          ?assertEqual(2, length(element(2, file:list_dir(Dir))))
      end) end}].
