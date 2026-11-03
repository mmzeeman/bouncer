-module(bouncer_keys).
-moduledoc """
Key management and peer authorization for the Noise (X25519) distribution carrier.

This module is called while the VM is still booting (from `listen/2`), so it is
made of pure functions and file I/O only: no processes, no ETS, no application
environment. Settings come from an `Opts` map, `-bouncer Key Value` init
arguments, `BOUNCER_*` environment variables, and defaults (in that order).

Node names and keys received from the network are untrusted: they are never
used to build file paths. Authorization is done by parsing the contents of the
`*.pub` files in the authorized directories.

Secret key material is never logged and never part of an error term.
""".

-include_lib("kernel/include/file.hrl").

-export([
    node_key_dir/2,
    authorized_dirs/2,
    load_or_generate/2,
    print_public/0,
    fingerprint/1,
    authorized_line/2,
    check_peer/3,
    add_peer/3,
    remove_peer/3,
    valid_node_name/1
]).

-export([public/1, secret/1, generated/1]).

-export_type([opts/0, node_name/0, key_info/0]).

-define(KEY_FILE, "id_x25519").
-define(AUTHORIZED_SUBDIR, "authorized.d").
-define(MAX_PUB_FILE, 4096).
-define(MAX_KEY_FILE, 1024).
-define(MAX_NAME, 255).

-type node_name() :: atom() | binary() | string().
-type opts() :: #{dir => file:filename(),
                  generate => boolean(),
                  authorized_dirs => [file:filename()] | string(),
                  keygen => fun(() -> {binary(), binary()}),
                  node_name => node_name()}.
%% The secret is only reachable through secret/1, so that printing or logging
%% a key_info() cannot leak it.
-opaque key_info() :: #{public := binary(),
                        secret := fun(() -> binary()),
                        fingerprint := binary(),
                        generated := boolean()}.

%%% ------------------------------------------------------------------
%%% Settings
%%% ------------------------------------------------------------------

-doc """
Directory holding the identity key of `NodeName`.

Uses the `dir` setting when present, otherwise
`filename:basedir(user_config, "bouncer")/NodeName`. Raises `badarg` when a
default path is needed and `NodeName` is not a valid node name.
""".
-spec node_key_dir(node_name(), opts()) -> file:filename().
node_key_dir(NodeName, Opts) ->
    case setting(dir, Opts) of
        {ok, Dir} ->
            to_list(Dir);
        error ->
            case name_to_binary(NodeName) of
                {ok, Bin} ->
                    case valid_node_name(Bin) of
                        true ->
                            filename:join(filename:basedir(user_config, "bouncer"),
                                          binary_to_list(Bin));
                        false ->
                            erlang:error(badarg)
                    end;
                error ->
                    erlang:error(badarg)
            end
    end.

-doc """
Authorized directories: the `authorized_dirs` setting (a list, or a
colon-separated string), defaulting to `<keydir>/authorized.d`.
""".
-spec authorized_dirs(node_name(), opts()) -> [file:filename()].
authorized_dirs(NodeName, Opts) ->
    case setting(authorized_dirs, Opts) of
        {ok, [H | _] = Str} when is_integer(H) ->
            split_dirs(Str);
        {ok, List} when is_list(List) ->
            [to_list(D) || D <- List, D =/= "", D =/= <<>>];
        {ok, Bin} when is_binary(Bin) ->
            split_dirs(binary_to_list(Bin));
        _ ->
            [filename:join(node_key_dir(NodeName, Opts), ?AUTHORIZED_SUBDIR)]
    end.

split_dirs(Str) ->
    [D || D <- string:split(Str, ":", all), D =/= ""].

generate_enabled(Opts) ->
    case setting(generate, Opts) of
        {ok, B} when is_boolean(B) ->
            B;
        {ok, "true"} ->
            true;
        {ok, "false"} ->
            false;
        {ok, Other} ->
            logger:warning("bouncer_keys: invalid value for generate: ~p, using true", [Other]),
            true;
        error ->
            true
    end.

setting(Key, Opts) ->
    case maps:find(Key, Opts) of
        {ok, _} = Found ->
            Found;
        error ->
            case flag(atom_to_list(Key)) of
                {ok, _} = Found ->
                    Found;
                error ->
                    env(Key)
            end
    end.

%% Each `-bouncer` occurrence is one Key/Value pair; also tolerate several pairs in one group.
flag(Key) ->
    case init:get_argument(bouncer) of
        {ok, Groups} ->
            case [V || G <- Groups, {K, V} <- pairs(G), K =:= Key] of
                [V | _] -> {ok, V};
                [] -> error
            end;
        error ->
            error
    end.

pairs([K, V | Rest]) -> [{K, V} | pairs(Rest)];
pairs(_) -> [].

env(Key) ->
    case os:getenv("BOUNCER_" ++ string:uppercase(atom_to_list(Key))) of
        false -> error;
        "" -> error;
        V -> {ok, V}
    end.

%% The local node name, needed for default directories by functions that
%% have no NodeName argument. TODO: confirm how check_peer/3, add_peer/3 and
%% remove_peer/3 should learn the local node name; for now: Opts `node_name`,
%% then node().
local_name(Opts) ->
    case maps:find(node_name, Opts) of
        {ok, N} ->
            N;
        error ->
            local_node_name()
    end.

local_node_name() ->
    case node() of
        nonode@nohost ->
            erlang:error(distribution_not_started);
        Node ->
            atom_to_list(Node)
    end.

dirs_for(Opts) ->
    try
        authorized_dirs(local_name(Opts), Opts)
    catch
        error:badarg ->
            logger:warning("bouncer_keys: cannot determine authorized directories"),
            []
    end.

%%% ------------------------------------------------------------------
%%% Identity key
%%% ------------------------------------------------------------------

-doc """
Loads the identity key of `NodeName`, generating and persisting it when
missing (unless generation is disabled).

Concurrent starters end up with the same key: the key file is published with
`file:make_link/2`, and the loser of the race reads the winner's key.
""".
-spec load_or_generate(node_name(), opts()) -> {ok, key_info()} | {error, term()}.
load_or_generate(NodeName, Opts) ->
    case name_to_binary(NodeName) of
        {ok, Bin} ->
            case valid_node_name(Bin) of
                true ->
                    load_or_generate_1(Bin, Opts);
                false ->
                    {error, invalid_node_name}
            end;
        error ->
            {error, invalid_node_name}
    end.

load_or_generate_1(Name, Opts) ->
    Dir = node_key_dir(Name, Opts),
    Path = filename:join(Dir, ?KEY_FILE),
    case read_key(Path) of
        {ok, Secret} ->
            {ok, key_info(Secret, false)};
        {error, _} = Error ->
            Error;
        missing ->
            case generate_enabled(Opts) of
                true ->
                    generate(Name, Dir, Path, Opts);
                false ->
                    {error, {no_key, Path}}
            end
    end.

generate(Name, Dir, Path, Opts) ->
    case mkdir_p(Dir, 8#700) of
        ok ->
            case run_keygen(maps:get(keygen, Opts, fun default_keygen/0)) of
                {ok, Secret} ->
                    publish_key(Name, Dir, Path, Secret);
                {error, _} = Error ->
                    Error
            end;
        {error, Reason} ->
            {error, {mkdir_failed, Reason, Dir}}
    end.

publish_key(Name, Dir, Path, Secret) ->
    case publish(Dir, Path, 8#600, [base64:encode(Secret), $\n]) of
        ok ->
            Info = key_info(Secret, true),
            Pub = public(Info),
            Fp = fingerprint(Info),
            logger:notice("bouncer_keys: generated new identity key ~ts~n"
                          "Add this line to the authorized directory of other nodes:~n~ts"
                          "Fingerprint: ~ts",
                          [Path, authorized_line(Name, Pub), Fp]),
            {ok, Info};
        {error, eexist} ->
            case read_key(Path) of
                {ok, Winner} ->
                    {ok, key_info(Winner, false)};
                missing ->
                    {error, {no_key, Path}};
                {error, _} = Error ->
                    Error
            end;
        {error, Reason} ->
            {error, {write_failed, Reason, Path}}
    end.

default_keygen() ->
    KP = enoise_keypair:new(dh25519),
    {enoise_keypair:pubkey(KP), enoise_keypair:seckey(KP)}.

%% The reason of a crashing keygen is deliberately dropped: it may contain key material.
run_keygen(Keygen) ->
    try Keygen() of
        {_Pub, <<_:32/binary>> = Secret} ->
            {ok, Secret};
        _ ->
            {error, bad_keygen}
    catch
        _:_ -> {error, keygen_failed}
    end.

key_info(Secret, Generated) ->
    KP = enoise_keypair:new(dh25519, Secret, undefined),
    Pub = enoise_keypair:pubkey(KP),
    #{public => Pub,
      secret => fun() -> Secret end,
      fingerprint => fingerprint(Pub),
      generated => Generated}.

read_key(Path) ->
    case file:read_link_info(Path) of
        {ok, #file_info{type = symlink}} ->
            {error, {symlink_refused, Path}};
        {ok, #file_info{type = regular, mode = Mode, size = Size}} ->
            if
                Mode band 8#077 =/= 0 ->
                    {error, {insecure_permissions, Path}};
                Size > ?MAX_KEY_FILE ->
                    {error, {bad_key, Path}};
                true ->
                    read_key_content(Path)
            end;
        {ok, _} ->
            {error, {not_regular_file, Path}};
        {error, enoent} ->
            missing;
        {error, Reason} ->
            {error, {Reason, Path}}
    end.

read_key_content(Path) ->
    case file:read_file(Path) of
        {ok, Bin} ->
            case decode_key(string:trim(Bin)) of
                {ok, Secret} ->
                    {ok, Secret};
                error -> {error,
                          {bad_key, Path}}
            end;
        {error, Reason} ->
            {error, {Reason, Path}}
    end.

decode_key(B64) ->
    try base64:decode(B64) of
        <<_:32/binary>> = Key ->
            {ok, Key};
        _ ->
            error
    catch
        _:_ -> error
    end.

-doc """
CLI helper: prints the authorized line of this node to stdout and the
fingerprint to stderr. Never generates a key. Halts with status 1 on error.
""".
-spec print_public() -> ok.
print_public() ->
    Name = local_node_name(),
    case load_or_generate(Name, #{generate => false}) of
        {ok, Info} ->
            Pub = public(Info),
            Fp = fingerprint(Info),
            io:put_chars(authorized_line(Name, Pub)),
            io:format(standard_error, "~ts~n", [Fp]);
        {error, Reason} ->
            fail("cannot load key: ~p", [Reason])
    end.

fail(Fmt, Args) ->
    io:format(standard_error, "bouncer_keys: " ++ Fmt ++ "~n", Args),
    erlang:halt(1).

%%% ------------------------------------------------------------------
%%% Public key helpers
%%% ------------------------------------------------------------------

-doc """
`SHA256:` followed by the unpadded base64 of the SHA-256 of the public key.
Accepts a bare public key or a `key_info()`.
""".
-spec fingerprint(binary() | key_info()) -> binary().
fingerprint(#{fingerprint := Fingerprint}) -> Fingerprint;
fingerprint(PublicKey) when is_binary(PublicKey) ->
    <<"SHA256:", (base64:encode(crypto:hash(sha256, PublicKey),
                                #{padding => false}))/binary>>.

%%% ------------------------------------------------------------------
%%% key_info() accessors
%%% ------------------------------------------------------------------

-doc "The public key (32 bytes).".
-spec public(key_info()) -> binary().
public(#{public := Public}) -> Public.

-doc "The secret key (32 bytes). Never log or print the result.".
-spec secret(key_info()) -> binary().
secret(#{secret := Secret}) -> Secret().

-doc "True when `load_or_generate/2` created this key.".
-spec generated(key_info()) -> boolean().
generated(#{generated := Generated}) -> Generated.

-doc "The line to put in an authorized directory file: `<name> <base64key>\\n`.".
-spec authorized_line(node_name(), binary()) -> binary().
authorized_line(NodeName, PublicKey) ->
    {ok, Name} = name_to_binary(NodeName),
    <<Name/binary, " ", (base64:encode(PublicKey))/binary, "\n">>.

-doc """
Accepts a binary `name@host` of at most 255 bytes made of `[A-Za-z0-9_.-]`,
without `..` and without a leading `.` in either part. Creates no atoms.
""".
-spec valid_node_name(term()) -> boolean().
valid_node_name(Name) when is_binary(Name), byte_size(Name) =< ?MAX_NAME ->
    case binary:split(Name, <<"@">>, [global]) of
        [Left, Right] ->
            valid_part(Left) andalso valid_part(Right)
                andalso binary:match(Name, <<"..">>) =:= nomatch;
        _ ->
            false
    end;
valid_node_name(_) ->
    false.

valid_part(<<>>) -> false;
valid_part(<<$., _/binary>>) -> false;
valid_part(Part) -> valid_chars(Part).

valid_chars(<<>>) -> true;
valid_chars(<<C, Rest/binary>>) when C >= $a, C =< $z;
                                     C >= $A, C =< $Z;
                                     C >= $0, C =< $9;
                                     C =:= $_; C =:= $.; C =:= $- ->
    valid_chars(Rest);
valid_chars(_) ->
    false.

%%% ------------------------------------------------------------------
%%% Authorization
%%% ------------------------------------------------------------------

-doc """
Checks a peer announced during a handshake. Touches no files when `Name` is
not a valid node name. Reads the authorized directories fresh on every call.
""".
-spec check_peer(binary(), binary(), opts()) -> allowed | denied | unknown_name.
check_peer(Name, PublicKey, Opts) ->
    case valid_node_name(Name) of
        false ->
            unknown_name;
        true ->
            Entries = load_all(dirs_for(Opts)),
            case [K || {_Path, N, K} <- Entries, N =:= Name] of
                [] ->
                    unknown_name;
                Keys ->
                    case matches(PublicKey, Keys) of
                        true -> allowed;
                        false -> denied
                    end
            end
    end.

matches(<<_:32/binary>> = Pub, Keys) ->
    %% hash_equals is evaluated for every key (no short-circuit on the left operand)
    lists:foldl(fun(K, Acc) -> crypto:hash_equals(K, Pub) orelse Acc end, false, Keys);
matches(_, _) ->
    false.

-doc """
Authorizes a peer by writing `<name>.<hex>.pub` into the first authorized
directory. Idempotent for the same key.
""".
-spec add_peer(binary(), binary(), opts()) -> {ok, file:filename()} | {error, term()}.
add_peer(Name, PublicKey, Opts) ->
    case {valid_node_name(Name), is_binary(PublicKey) andalso byte_size(PublicKey) =:= 32} of
        {false, _} ->
            {error, invalid_name};
        {_, false} ->
            {error, invalid_key};
        {true, true} ->
            case dirs_for(Opts) of
                [] ->
                    {error, no_authorized_dir};
                [Dir | _] ->
                    add_peer_in(Dir, Name, PublicKey)
            end
    end.

add_peer_in(Dir, Name, Pub) ->
    case mkdir_p(Dir, 8#755) of
        ok ->
            Prefix = binary:encode_hex(binary:part(crypto:hash(sha256, Pub), 0, 6), lowercase),
            Final = filename:join(Dir, binary_to_list(<<Name/binary, ".", Prefix/binary, ".pub">>)),
            Line = authorized_line(Name, Pub),
            case publish(Dir, Final, 8#644, Line) of
                ok ->
                    {ok, Final};
                {error, eexist} ->
                    case file:read_file(Final) of
                        {ok, Line} -> {ok, Final};
                        {ok, _} -> {error, {conflict, Final}};
                        {error, Reason} -> {error, {Reason, Final}}
                    end;
                {error, Reason} ->
                    {error, {write_failed, Reason, Final}}
            end;
        {error, Reason} ->
            {error, {mkdir_failed, Reason, Dir}}
    end.

-doc "Deletes the files of `Name` whose key has fingerprint `Fingerprint`.".
-spec remove_peer(binary(), string() | binary(), opts()) -> ok | {error, term()}.
remove_peer(Name, Fingerprint, Opts) ->
    Fp = unicode:characters_to_binary(Fingerprint),
    Matching = [P || {P, N, K} <- load_all(dirs_for(Opts)),
                     N =:= Name, fingerprint(K) =:= Fp],
    Results = [file:delete(P) || P <- Matching],
    case {Matching, [R || {error, _} = R <- Results]} of
        {[], _} -> {error, not_found};
        {_, []} -> ok;
        {_, [Error | _]} -> Error
    end.

%%% ------------------------------------------------------------------
%%% Loader
%%% ------------------------------------------------------------------

load_all(Dirs) ->
    lists:append([load_dir(D) || D <- Dirs]).

load_dir(Dir) ->
    case file:read_file_info(Dir) of
        {ok, #file_info{type = directory, mode = Mode}} ->
            case Mode band 8#022 =/= 0 of
                true ->
                    warn(Dir, "directory writable by group/other, refused"),
                    [];
                false ->
                    list_dir(Dir)
            end;
        {ok, _} ->
            warn(Dir, "not a directory"),
            [];
        {error, enoent} ->
            [];
        {error, Reason} ->
            warn(Dir, io_lib:format("cannot read directory: ~p", [Reason])),
            []
    end.

list_dir(Dir) ->
    case file:list_dir(Dir) of
        {ok, Names} ->
            lists:append([load_file(Dir, N) || N <- lists:sort(Names)]);
        {error, Reason} ->
            warn(Dir, io_lib:format("cannot list directory: ~p", [Reason])),
            []
    end.

load_file(_Dir, [$. | _]) ->
    [];
load_file(Dir, Name) ->
    case filename:extension(Name) of
        ".pub" -> load_pub(filename:join(Dir, Name));
        _ -> []
    end.

load_pub(Path) ->
    case file:read_link_info(Path) of
        {ok, #file_info{type = symlink}} ->
            warn(Path, "symlink refused"),
            [];
        {ok, #file_info{type = regular, size = Size, mode = Mode}} ->
            if
                Size > ?MAX_PUB_FILE ->
                    warn(Path, "file too large, skipped"),
                    [];
                Mode band 8#022 =/= 0 ->
                    warn(Path, "file writable by group/other, refused"),
                    [];
                true ->
                    read_pub(Path)
            end;
        {ok, _} ->
            [];
        {error, Reason} ->
            warn(Path, io_lib:format("cannot stat: ~p", [Reason])),
            []
    end.

read_pub(Path) ->
    case file:read_file(Path) of
        {ok, Bin} when byte_size(Bin) =< ?MAX_PUB_FILE ->
            case parse_entry(Bin) of
                {ok, Name, Key} ->
                    [{Path, Name, Key}];
                {error, Why} ->
                    warn(Path, io_lib:format("malformed entry: ~p", [Why])),
                    []
            end;
        {ok, _} ->
            warn(Path, "file too large, skipped"),
            [];
        {error, Reason} ->
            warn(Path, io_lib:format("cannot read: ~p", [Reason])),
            []
    end.

parse_entry(Bin) ->
    Lines = [L || L <- binary:split(Bin, <<"\n">>, [global]), not blank(L)],
    case Lines of
        [Line] ->
            case binary:split(Line, [<<" ">>, <<"\t">>, <<"\r">>], [global, trim_all]) of
                [Name, B64 | _Comment] ->
                    case valid_node_name(Name) of
                        false ->
                            {error, invalid_name};
                        true ->
                            case decode_key(B64) of
                                {ok, Key} -> {ok, Name, Key};
                                error -> {error, invalid_key}
                            end
                    end;
                _ ->
                    {error, missing_fields}
            end;
        _ ->
            {error, not_one_line}
    end.

blank(Line) ->
    re:run(Line, <<"^[ \t\r]*$">>, [{capture, none}]) =:= match.

warn(Path, Msg) ->
    logger:warning("bouncer_keys: ~ts: ~ts", [Path, Msg]).

%%% ------------------------------------------------------------------
%%% File helpers
%%% ------------------------------------------------------------------

%% Creates Dir (and missing parents); only a newly created Dir gets Mode.
mkdir_p(Dir, Mode) ->
    case file:make_dir(Dir) of
        ok ->
            file:change_mode(Dir, Mode);
        {error, eexist} ->
            case filelib:is_dir(Dir) of
                true -> ok;
                false -> {error, eexist}
            end;
        {error, enoent} ->
            case filename:dirname(Dir) of
                Dir ->
                    {error, enoent};
                Parent ->
                    case mkdir_p(Parent, 8#755) of
                        ok -> mkdir_p(Dir, Mode);
                        {error, _} = Error -> Error
                    end
            end;
        {error, _} = Error ->
            Error
    end.

%% Writes Content to a temp file in Dir (mode set before any content is
%% written), then hard-links it to Final. Fails with eexist if Final exists.
publish(Dir, Final, Mode, Content) ->
    Tmp = filename:join(Dir, tmp_name()),
    case file:open(Tmp, [write, exclusive, raw, binary]) of
        {ok, Fd} ->
            Written = write_synced(Fd, Tmp, Mode, Content),
            _ = file:close(Fd),
            Result = case Written of
                         ok -> file:make_link(Tmp, Final);
                         {error, _} = Error -> Error
                     end,
            _ = file:delete(Tmp),
            Result;
        {error, _} = Error ->
            Error
    end.

write_synced(Fd, Tmp, Mode, Content) ->
    case file:change_mode(Tmp, Mode) of
        ok ->
            case file:write(Fd, Content) of
                ok -> file:sync(Fd);
                {error, _} = Error -> Error
            end;
        {error, _} = Error ->
            Error
    end.

tmp_name() ->
    ".bouncer-tmp-" ++ os:getpid() ++ "-"
        ++ binary_to_list(binary:encode_hex(crypto:strong_rand_bytes(8), lowercase)).

to_list(B) when is_binary(B) -> binary_to_list(B);
to_list(L) when is_list(L) -> L.

name_to_binary(N) when is_binary(N) -> {ok, N};
name_to_binary(N) when is_atom(N) -> {ok, atom_to_binary(N, utf8)};
name_to_binary(N) when is_list(N) ->
    try {ok, unicode:characters_to_binary(N)} of
        {ok, B} when is_binary(B) -> {ok, B};
        _ -> error
    catch
        _:_ -> error
    end;
name_to_binary(_) ->
    error.
