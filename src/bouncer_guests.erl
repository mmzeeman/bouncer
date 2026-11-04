-module(bouncer_guests).
-moduledoc """
Command line tool to manage the key directory and the authorized directories
("guests") of a node. A thin layer over `bouncer_keys`; it only edits files and
does not talk to a running node.

Built as an escript (`rebar3 escriptize`). Uses only `bouncer_keys`, `crypto`,
`logger` and the standard library. Secret key material is never printed.

Exit codes: 0 ok, 1 not found, 2 usage error, 3 error (I/O, permissions,
invalid key file), 4 fingerprint mismatch.
""".

-export([main/1, run/2]).

-define(PLACEHOLDER_NODE, <<"bouncer_guests@localhost">>).
-define(MAX_STDIN, 65536).

-type env() :: #{stdin => binary() | fun(() -> binary())}.
-export_type([env/0]).

%%% ------------------------------------------------------------------
%%% Entry points
%%% ------------------------------------------------------------------

-spec main([string()]) -> no_return().
main(Args) ->
    %% bouncer_keys logs every skipped file; the tool reports them itself.
    logger:set_primary_config(level, none),
    {Code, Out, Err} = run(Args, #{stdin => fun read_stdin/0}),
    io:put_chars(standard_io, Out),
    io:put_chars(standard_error, Err),
    erlang:halt(Code).

-doc "Runs a command line; returns the exit code and what to print.".
-spec run([string()], env()) -> {0..4, iodata(), iodata()}.
run(Args, Env) ->
    try
        dispatch(Args, Env)
    catch
        throw:{exit, Code, Out, Err} -> {Code, Out, Err};
        throw:{usage, Msg} -> {2, [], [Msg, "\n\n", usage()]};
        throw:{fail, Code, Msg} -> {Code, [], [Msg, "\n"]};
        Class:Reason ->
            {3, [], io_lib:format("internal error: ~p:~0tp~n", [Class, Reason])}
    end.

read_stdin() ->
    read_stdin(<<>>).

read_stdin(Acc) when byte_size(Acc) > ?MAX_STDIN ->
    Acc;
read_stdin(Acc) ->
    case io:get_line(standard_io, "") of
        eof -> Acc;
        {error, _} -> Acc;
        Line -> read_stdin(<<Acc/binary, (unicode:characters_to_binary(Line))/binary>>)
    end.

%%% ------------------------------------------------------------------
%%% Argument parsing
%%% ------------------------------------------------------------------

dispatch([], _Env) ->
    throw({usage, "missing command"});
dispatch(["-h" | _], _Env) -> {0, usage(), []};
dispatch(["--help" | _], _Env) -> {0, usage(), []};
dispatch(["help" | _], _Env) -> {0, usage(), []};
dispatch([Cmd | Rest], Env) ->
    Spec = spec(Cmd),
    P = parse(Rest, Spec, #{}, []),
    case maps:is_key(help, element(1, P)) of
        true -> {0, usage(), []};
        false -> command(Cmd, P, Env)
    end.

%% Valued options take an argument; the others are flags.
spec(Cmd) ->
    Global = #{"--dir" => {dir, value}, "--authorized-dir" => {authorized_dir, multi},
               "--node" => {node, value}, "-q" => {quiet, flag}, "--quiet" => {quiet, flag},
               "-h" => {help, flag}, "--help" => {help, flag}},
    Extra = case Cmd of
                "init" -> #{"--no-generate" => {no_generate, flag}};
                "add" -> #{"--comment" => {comment, value}, "--line" => {line, value},
                           "--fingerprint" => {fingerprint, value}};
                "remove" -> #{"--fingerprint" => {fingerprint, value}, "--all" => {all, flag}};
                "show" -> #{"--self" => {self, flag}};
                "list" -> #{};
                "check" -> #{};
                _ -> throw({usage, "unknown command: " ++ printable(Cmd)})
            end,
    maps:merge(Global, Extra).

parse([], _Spec, Opts, Pos) ->
    {Opts, lists:reverse(Pos)};
parse(["--" | Rest], _Spec, Opts, Pos) ->
    {Opts, lists:reverse(Pos) ++ Rest};
parse(["-" | Rest], Spec, Opts, Pos) ->
    parse(Rest, Spec, Opts, ["-" | Pos]);
parse([[$-, _ | _] = Arg | Rest], Spec, Opts, Pos) ->
    {Name, Inline} = split_inline(Arg),
    case maps:find(Name, Spec) of
        error ->
            throw({usage, "unknown option: " ++ printable(Name)});
        {ok, {Key, flag}} when Inline =:= none ->
            parse(Rest, Spec, Opts#{Key => true}, Pos);
        {ok, {_, flag}} ->
            throw({usage, "option takes no value: " ++ printable(Name)});
        {ok, {Key, Kind}} ->
            case value_of(Inline, Rest) of
                {ok, Value, Rest1} ->
                    parse(Rest1, Spec, put_opt(Kind, Key, Value, Opts), Pos);
                error ->
                    throw({usage, "option needs a value: " ++ printable(Name)})
            end
    end;
parse([Arg | Rest], Spec, Opts, Pos) ->
    parse(Rest, Spec, Opts, [Arg | Pos]).

split_inline("--" ++ _ = Arg) ->
    case string:split(Arg, "=") of
        [Name, Value] -> {Name, Value};
        [Name] -> {Name, none}
    end;
split_inline(Arg) ->
    {Arg, none}.

value_of(none, [V | Rest]) -> {ok, V, Rest};
value_of(none, []) -> error;
value_of(V, Rest) -> {ok, V, Rest}.

put_opt(multi, Key, Value, Opts) ->
    Opts#{Key => maps:get(Key, Opts, []) ++ [Value]};
put_opt(value, Key, Value, Opts) ->
    Opts#{Key => Value}.

%% Option values and arguments echoed in messages: no control characters.
printable(S) ->
    [case C < 32 orelse C =:= 127 of true -> $?; false -> C end || C <- S].

usage() ->
    "Usage: bouncer_guests <command> [options]\n"
    "\n"
    "Commands:\n"
    "  init --node NAME [--no-generate]   create the directories and the identity key,\n"
    "                                     print this node's authorized line and fingerprint\n"
    "  add NAME KEY [--comment TEXT] [--fingerprint FP]\n"
    "  add --line \"NAME KEY [comment]\" [--fingerprint FP]\n"
    "  add -                              read one line from stdin (output of init/show --self;\n"
    "                                     lines starting with # are ignored)\n"
    "  remove NAME [--fingerprint FP | --all]\n"
    "  show NAME                          authorized entries for NAME\n"
    "  show --self --node NAME            this node's own authorized line and fingerprint\n"
    "  list                               all authorized entries\n"
    "  check NAME FINGERPRINT             exit 0 if NAME has an entry with this fingerprint\n"
    "\n"
    "Options (all commands):\n"
    "  --dir DIR             node key directory (default: $BOUNCER_DIR, then the user config dir)\n"
    "  --authorized-dir DIR  authorized directory, repeatable; `add` writes to the first\n"
    "  --node NAME           this node's name (to locate the default key directory)\n"
    "  -q, --quiet           only print errors and the primary result value\n"
    "  -h, --help            this text\n"
    "\n"
    "Exit codes: 0 ok, 1 not found, 2 usage error, 3 error, 4 fingerprint mismatch.\n"
    "\n"
    "Revocation (remove) applies to NEW handshakes; established connections stay up\n"
    "until they are closed or the node restarts. This tool only edits files; it does\n"
    "not talk to a running node.\n".

%%% ------------------------------------------------------------------
%%% Commands
%%% ------------------------------------------------------------------

command("init", {O, Pos}, _Env) ->
    no_positional(Pos),
    Node = require_node(O),
    Opts = keys_opts(O, Node),
    case bouncer_keys:ensure_dirs(Node, Opts) of
        ok -> ok;
        {error, DirErr} -> fail(3, DirErr)
    end,
    Generate = not maps:is_key(no_generate, O),
    case bouncer_keys:load_or_generate(Node, Opts#{generate => Generate}) of
        {ok, Info} ->
            {0, identity_output(Node, Info, O), []};
        {error, {no_key, _}} when not Generate ->
            {0, quiet(O, ["no identity key present (not generated)\n"]), []};
        {error, R} ->
            fail(3, R)
    end;
command("add", {O, Pos}, Env) ->
    cmd_add(O, Pos, Env);
command("remove", {O, Pos}, _Env) ->
    cmd_remove(O, Pos);
command("show", {O, Pos}, _Env) ->
    case maps:is_key(self, O) of
        true -> no_positional(Pos), cmd_show_self(O);
        false -> cmd_show(O, Pos)
    end;
command("list", {O, Pos}, _Env) ->
    no_positional(Pos),
    cmd_list(O);
command("check", {O, Pos}, _Env) ->
    cmd_check(O, Pos).

no_positional([]) -> ok;
no_positional([A | _]) -> throw({usage, "unexpected argument: " ++ printable(A)}).

%%% init / show --self

identity_output(Node, Info, O) ->
    Line = string:trim(bouncer_keys:authorized_line(Node, bouncer_keys:public(Info)), trailing, "\n"),
    Fp = bouncer_keys:fingerprint(Info),
    case maps:is_key(quiet, O) of
        true -> [Line, "\n"];
        false -> [Line, "\n# fingerprint ", Fp, "\n"]
    end.

cmd_show_self(O) ->
    Node = require_node(O),
    case bouncer_keys:load_or_generate(Node, (keys_opts(O, Node))#{generate => false}) of
        {ok, Info} ->
            {0, identity_output(Node, Info, O), []};
        {error, {no_key, Path}} ->
            fail(1, io_lib:format("no identity key at ~ts; run `bouncer_guests init --node ~ts`",
                                  [Path, Node]));
        {error, R} ->
            fail(3, R)
    end.

%%% add

cmd_add(O, Pos, Env) ->
    {Name0, Key0, LineComment} = add_input(O, Pos, Env),
    Name = valid_name(Name0),
    Key = decode_key(Key0),
    Comment = comment(O, LineComment),
    Fp = bouncer_keys:fingerprint(Key),
    check_expected(O, Fp, Name),
    Opts = keys_opts(O, undefined),
    FirstDir = case bouncer_keys:authorized_dirs(node_for(O), Opts) of
                   [D | _] -> D;
                   [] -> fail(2, "no authorized directory")
               end,
    {Status, File} =
        case find_entry(Name, Key, FirstDir, Opts) of
            {ok, Existing} ->
                {"already present", Existing};
            none ->
                case bouncer_keys:add_peer(Name, Key, Opts#{comment => Comment}) of
                    {ok, Path} -> {"added", Path};
                    {error, invalid_comment} -> fail(2, "invalid comment");
                    {error, R} -> fail(3, R)
                end
        end,
    Out = case maps:is_key(quiet, O) of
              true -> [Fp, "\n"];
              false -> [Status, "\n", "name: ", Name, "\n", "fingerprint: ", Fp, "\n",
                        "file: ", File, "\n"]
          end,
    {0, Out, []}.

add_input(O, Pos, Env) ->
    case {maps:find(line, O), Pos} of
        {{ok, Line}, []} -> parse_line(Line);
        {{ok, _}, _} -> throw({usage, "add: --line cannot be combined with NAME KEY"});
        {error, ["-"]} -> parse_line(stdin_line(Env));
        {error, [N, K]} -> {N, K, none};
        {error, _} -> throw({usage, "add: expected NAME KEY, --line LINE, or -"})
    end.

parse_line(Line) ->
    Trimmed = string:trim(Line),
    case string:lexemes(Trimmed, " \t") of
        [N, K | C] ->
            {N, K, case C of [] -> none; _ -> lists:flatten(lists:join(" ", C)) end};
        _ ->
            throw({usage, "expected a line of the form: NAME KEY [comment]"})
    end.

stdin_line(Env) ->
    Bin = case maps:get(stdin, Env, <<>>) of
              F when is_function(F, 0) -> F();
              B -> B
          end,
    Str = case unicode:characters_to_list(Bin) of
              S when is_list(S) -> S;
              _ -> throw({usage, "stdin is not valid UTF-8"})
          end,
    Lines = [L || L <- string:split(Str, "\n", all),
                  string:trim(L) =/= "", hd(string:trim(L)) =/= $#],
    case Lines of
        [One] -> One;
        [] -> throw({usage, "no input line on stdin"});
        _ -> throw({usage, "expected exactly one line on stdin"})
    end.

comment(O, LineComment) ->
    C = case maps:find(comment, O) of
            {ok, V} -> V;
            error when LineComment =:= none -> "";
            error -> LineComment
        end,
    case lists:any(fun(Ch) -> Ch =:= $\n orelse Ch =:= $\r orelse Ch =:= 0 end, C) of
        true -> throw({usage, "a comment must be a single line"});
        false -> unicode:characters_to_binary(string:trim(C))
    end.

check_expected(O, Fp, Name) ->
    case maps:find(fingerprint, O) of
        error ->
            ok;
        {ok, Expected} ->
            case strip_prefix(Expected) =:= strip_prefix(binary_to_list(Fp)) of
                true ->
                    ok;
                false ->
                    throw({fail, 4, io_lib:format(
                        "fingerprint mismatch for ~ts: computed ~ts, expected ~ts; nothing written",
                        [Name, Fp, printable(Expected)])})
            end
    end.

find_entry(Name, Key, Dir, Opts) ->
    case bouncer_keys:list_peers(Opts) of
        {ok, Entries, _} ->
            case [F || #{name := N, key := K, dir := D, file := F} <- Entries,
                       N =:= Name, K =:= Key, D =:= Dir] of
                [F | _] -> {ok, F};
                [] -> none
            end;
        {error, R} ->
            fail(3, R)
    end.

%%% remove

cmd_remove(O, Pos) ->
    Name = case Pos of
               [N] -> valid_name(N);
               _ -> throw({usage, "remove: expected NAME"})
           end,
    case {maps:is_key(fingerprint, O), maps:is_key(all, O)} of
        {true, true} -> throw({usage, "remove: --fingerprint and --all are exclusive"});
        _ -> ok
    end,
    Opts = keys_opts(O, undefined),
    All = entries_for(Name, Opts),
    All =:= [] andalso fail(1, ["no entry for ", Name]),
    Targets =
        case maps:find(fingerprint, O) of
            {ok, Want} ->
                W = strip_prefix(Want),
                case [E || #{fingerprint := F} = E <- All, strip_prefix(F) =:= W] of
                    [] -> fail(1, ["no entry for ", Name, " with fingerprint ", printable(Want)]);
                    Sel -> Sel
                end;
            error ->
                case maps:is_key(all, O) orelse length(fingerprints(All)) =:= 1 of
                    true ->
                        All;
                    false ->
                        throw({exit, 2, [],
                               ["several keys for ", Name, "; use --fingerprint FP or --all:\n",
                                [["  ", F, "\n"] || F <- fingerprints(All)]]})
                end
        end,
    lists:foreach(fun(F) ->
                      case bouncer_keys:remove_peer(Name, F, Opts) of
                          ok -> ok;
                          {error, not_found} -> ok;
                          {error, R} -> fail(3, R)
                      end
                  end, fingerprints(Targets)),
    Out = case maps:is_key(quiet, O) of
              true -> [];
              false -> [["removed ", Name, "  ", F, "  ", File, "\n"]
                        || #{fingerprint := F, file := File} <- Targets]
          end,
    {0, Out, []}.

fingerprints(Entries) ->
    lists:usort([F || #{fingerprint := F} <- Entries]).

%%% show

cmd_show(O, Pos) ->
    Name = case Pos of
               [N] -> valid_name(N);
               _ -> throw({usage, "show: expected NAME or --self"})
           end,
    case entries_for(Name, keys_opts(O, undefined)) of
        [] ->
            fail(1, ["no entry for ", Name]);
        Entries ->
            case maps:is_key(quiet, O) of
                true ->
                    {0, [[F, "\n"] || F <- fingerprints(Entries)], []};
                false ->
                    Blocks = [["name: ", N, "\nfingerprint: ", F, "\nkey: ", base64:encode(K),
                               "\ncomment: ", C, "\nfile: ", File, "\ndirectory: ", D, "\n"]
                              || #{name := N, fingerprint := F, key := K, comment := C,
                                   file := File, dir := D} <- Entries],
                    {0, lists:join("\n", Blocks), []}
            end
    end.

%%% list

cmd_list(O) ->
    case bouncer_keys:list_peers(keys_opts(O, undefined)) of
        {ok, Entries, Skips} ->
            Sorted = lists:sort(fun(#{name := N1, fingerprint := F1, file := P1},
                                    #{name := N2, fingerprint := F2, file := P2}) ->
                                    {N1, F1, P1} =< {N2, F2, P2}
                                end, Entries),
            Out = [[N, "  ", F, "  ", File, "\n"] || #{name := N, fingerprint := F, file := File} <- Sorted],
            Err = case maps:is_key(quiet, O) of
                      true -> [];
                      false -> [["skipped ", File, ": ", skip_reason(R), "\n"]
                                || #{file := File, reason := R} <- Skips]
                  end,
            {0, Out, Err};
        {error, R} ->
            fail(3, R)
    end.

skip_reason(symlink_refused) -> "symlink refused";
skip_reason(too_large) -> "file too large";
skip_reason(group_or_other_writable) -> "writable by group/other";
skip_reason({malformed, Why}) -> io_lib:format("malformed entry (~p)", [Why]);
skip_reason(Other) -> io_lib:format("~0tp", [Other]).

%%% check

cmd_check(O, Pos) ->
    {Name, Want} = case Pos of
                       [N, F] -> {valid_name(N), strip_prefix(F)};
                       _ -> throw({usage, "check: expected NAME FINGERPRINT"})
                   end,
    case entries_for(Name, keys_opts(O, undefined)) of
        [] ->
            fail(1, ["no entry for ", Name]);
        Entries ->
            Fps = fingerprints(Entries),
            case lists:any(fun(F) -> strip_prefix(F) =:= Want end, Fps) of
                true ->
                    {0, quiet(O, "ok\n"), []};
                false ->
                    throw({exit, 4, [],
                           ["fingerprint mismatch for ", Name, "; actual fingerprints:\n",
                            [["  ", F, "\n"] || F <- Fps]]})
            end
    end.

%%% ------------------------------------------------------------------
%%% Helpers
%%% ------------------------------------------------------------------

quiet(O, Text) ->
    case maps:is_key(quiet, O) of
        true -> [];
        false -> Text
    end.

entries_for(Name, Opts) ->
    case bouncer_keys:list_peers(Opts) of
        {ok, Entries, _Skips} ->
            lists:sort(fun(#{fingerprint := A, file := PA}, #{fingerprint := B, file := PB}) ->
                           {A, PA} =< {B, PB}
                       end, [E || #{name := N} = E <- Entries, N =:= Name]);
        {error, R} ->
            fail(3, R)
    end.

strip_prefix("SHA256:" ++ Rest) -> Rest;
strip_prefix(Fp) -> Fp.

valid_name(Str) ->
    Bin = case unicode:characters_to_binary(Str) of
              B when is_binary(B) -> B;
              _ -> <<>>
          end,
    case bouncer_keys:valid_node_name(Bin) of
        true -> Bin;
        false -> throw({usage, "invalid node name: " ++ printable(Str)})
    end.

%% Exactly 32 bytes, in canonical padded base64.
decode_key(Str) ->
    Bin = unicode:characters_to_binary(Str),
    try base64:decode(Bin) of
        <<_:32/binary>> = Key ->
            case base64:encode(Key) =:= Bin of
                true -> Key;
                false -> throw({usage, "invalid key: not canonical base64"})
            end;
        _ ->
            throw({usage, "invalid key: expected base64 of exactly 32 bytes"})
    catch
        error:_ -> throw({usage, "invalid key: not base64"})
    end.

require_node(O) ->
    case maps:find(node, O) of
        {ok, N} -> valid_name(N);
        error -> throw({usage, "--node NAME is required"})
    end.

%% The node name is only used for default directories; without --node the
%% directories must be given explicitly (options or BOUNCER_* environment).
node_for(O) ->
    case maps:find(node, O) of
        {ok, _} ->
            require_node(O);
        error ->
            Explicit = maps:is_key(dir, O) orelse maps:is_key(authorized_dir, O)
                orelse env_set("BOUNCER_DIR")
                orelse env_set("BOUNCER_AUTHORIZED_DIRS"),
            Explicit orelse throw({usage, "need --node, --dir or --authorized-dir"}),
            ?PLACEHOLDER_NODE
    end.

env_set(Var) ->
    os:getenv(Var) =/= false andalso os:getenv(Var) =/= "".

keys_opts(O, Node) ->
    Base = case maps:find(dir, O) of
               {ok, D} -> #{dir => D};
               error -> #{}
           end,
    WithAuth = case maps:find(authorized_dir, O) of
                   {ok, Dirs} -> Base#{authorized_dirs => Dirs};
                   error -> Base
               end,
    WithAuth#{node_name => case Node of
                               undefined -> node_for(O);
                               _ -> Node
                           end}.

fail(Code, Reason) ->
    throw({fail, Code, format_reason(Reason)}).

format_reason({insecure_permissions, Path}) ->
    io_lib:format("insecure permissions on ~ts (must not be accessible by group/other)", [Path]);
format_reason({symlink_refused, Path}) ->
    io_lib:format("~ts is a symlink, refused", [Path]);
format_reason({not_regular_file, Path}) ->
    io_lib:format("~ts is not a regular file", [Path]);
format_reason({bad_key, Path}) ->
    io_lib:format("invalid key file ~ts", [Path]);
format_reason({mkdir_failed, Reason, Dir}) ->
    io_lib:format("cannot create directory ~ts: ~ts", [Dir, file:format_error(Reason)]);
format_reason({write_failed, Reason, Path}) ->
    io_lib:format("cannot write ~ts: ~ts", [Path, file:format_error(Reason)]);
format_reason({refused_dir, Dir, Why}) ->
    io_lib:format("directory ~ts refused: ~ts", [Dir, dir_reason(Why)]);
format_reason({conflict, Path}) ->
    io_lib:format("~ts exists with different content", [Path]);
format_reason(Reason) when is_list(Reason); is_binary(Reason) ->
    Reason;
format_reason(Reason) ->
    io_lib:format("~0tp", [Reason]).

dir_reason(group_or_other_writable) -> "writable by group/other";
dir_reason(not_a_directory) -> "not a directory";
dir_reason(Other) -> io_lib:format("~0tp", [Other]).
