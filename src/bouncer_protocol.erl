%% Pure wire-format helpers for the bouncer Noise handshake.
-module(bouncer_protocol).

-ifdef(TEST).
-export([unpad/2]).
-endif.

-export([
    hello_header/1,
    hello/2,
    parse_hello_header/2,
    parse_reply_header/1,
    parse_msg3_prefix/1,
    reply_ok/1,
    reply_reject/1,
    msg3_frame/1,
    prologue/2,
    encode_name/1,
    decode_name/1,
    noise_name/1,
    suite_id/1,
    suite_atom/1,
    known_suites/0,
    limits/0
]).

%% Transport framing (see the TRANSPORT FRAMING section at the bottom).
-export([
    new_sender/2,
    sender_policy/1,
    tx_start/1,
    tx_packet/1,
    tx_next/2,
    tx_tick/1,

    new_receiver/2,
    receiver_policy/1,
    rx_start/1,
    rx_feed/2
]).

-export_type([
    sender/0,
    receiver/0,
    pending/0,
    sender_policy/0,
    receiver_policy/0,
    rx_event/0,
    rx_error/0,
    policy_error/0
]).

-define(HELLO_MAGIC, <<"BNCR">>).
-define(VERSION, 1).
-define(HELLO_HEADER_SIZE, 8).
-define(MSG1_LENGTH, 32).
-define(MAX_FRAME_LENGTH, 16#ffff).
-define(MIN_NAME_LENGTH, 3).
-define(MAX_NAME_LENGTH, 255).

-type suite() :: chachapoly_blake2b | aesgcm_sha512 | aesgcm_sha256 | aesgcm_blake2b.

-spec known_suites() -> [suite()].
known_suites() -> [chachapoly_blake2b, aesgcm_sha512, aesgcm_sha256, aesgcm_blake2b].

-spec suite_id(suite()) -> 1..4.
suite_id(chachapoly_blake2b) -> 1;
suite_id(aesgcm_sha512) -> 2;
suite_id(aesgcm_sha256) -> 3;
suite_id(aesgcm_blake2b) -> 4.

-spec suite_atom(1..4) -> suite().
suite_atom(1) -> chachapoly_blake2b;
suite_atom(2) -> aesgcm_sha512;
suite_atom(3) -> aesgcm_sha256;
suite_atom(4) -> aesgcm_blake2b.

-spec noise_name(suite()) -> binary().
noise_name(chachapoly_blake2b) -> <<"Noise_XX_25519_ChaChaPoly_BLAKE2b">>;
noise_name(aesgcm_sha512) -> <<"Noise_XX_25519_AESGCM_SHA512">>;
noise_name(aesgcm_sha256) -> <<"Noise_XX_25519_AESGCM_SHA256">>;
noise_name(aesgcm_blake2b) -> <<"Noise_XX_25519_AESGCM_BLAKE2b">>.

-spec hello_header(1..4) -> <<_:64>>.
hello_header(SuiteId) ->
    _ = suite_atom(SuiteId),
    <<?HELLO_MAGIC/binary, ?VERSION:8, SuiteId:8, ?MSG1_LENGTH:16>>.

-spec hello(1..4, binary()) -> binary().
hello(SuiteId, Msg1) when is_binary(Msg1), byte_size(Msg1) =:= ?MSG1_LENGTH ->
    <<(hello_header(SuiteId))/binary, Msg1/binary>>.

-spec parse_hello_header(binary(), [byte()]) ->
          {ok, suite(), 32} | {reject, 1} | {reject, 2} | {error, bad_hello_header}.
parse_hello_header(<<"BNCR", ?VERSION:8, SuiteId:8, Msg1Len:16>>, AcceptedIds)
  when SuiteId >= 1 andalso SuiteId =< 4
       andalso is_list(AcceptedIds) ->
    case lists:member(SuiteId, AcceptedIds) of
        false ->
            {reject, 2};
        true when Msg1Len =:= ?MSG1_LENGTH ->
            {ok, suite_atom(SuiteId), Msg1Len};
        true ->
            {error, bad_hello_header}
    end;
parse_hello_header(<<"BNCR", Version:8, _SuiteId:8, _Msg1Len:16>>, _AcceptedIds)
  when Version =/= ?VERSION ->
    {reject, 1};
parse_hello_header(<<"BNCR", ?VERSION:8, _SuiteId:8, _Msg1Len:16>>, AcceptedIds)
  when is_list(AcceptedIds) ->
    %% Unsupported suite id.
    {reject, 2};
parse_hello_header(_, _) ->
    {error, bad_hello_header}.

%% Parses the eight-byte responder header. Successful message lengths must be
%% within the message-2 bounds in `limits/0`; rejection statuses must have length
%% zero.
-spec parse_reply_header(binary()) ->
          {ok, 1..16#ffff} |
          {error, unsupported_version | unsupported_suite | bad_reply_header}.
parse_reply_header(<<"BNCR", ?VERSION:8, 0:8, Msg2Len:16>>) ->
    {Min, Max} = maps:get(msg2_length, limits()),
    case Msg2Len >= Min andalso Msg2Len =< Max of
        true -> {ok, Msg2Len};
        false -> {error, bad_reply_header}
    end;
parse_reply_header(<<"BNCR", ?VERSION:8, Status:8, 0:16>>)
  when Status =:= 1 ->
    {error, unsupported_version};
parse_reply_header(<<"BNCR", ?VERSION:8, Status:8, 0:16>>)
  when Status =:= 2 ->
    {error, unsupported_suite};
parse_reply_header(_) ->
    {error, bad_reply_header}.

%% Parses the two-byte message-3 length prefix, requiring the length to fit the
%% message-3 bounds in `limits/0`.
-spec parse_msg3_prefix(binary()) -> {ok, 1..16#ffff} | {error, bad_msg3_length}.
parse_msg3_prefix(<<Len:16>>) ->
    {Min, Max} = maps:get(msg3_length, limits()),
    case Len >= Min andalso Len =< Max of
        true -> {ok, Len};
        false -> {error, bad_msg3_length}
    end;
parse_msg3_prefix(_) ->
    {error, bad_msg3_length}.

-spec reply_ok(binary()) -> binary().
reply_ok(Msg2) when is_binary(Msg2), byte_size(Msg2) =< ?MAX_FRAME_LENGTH ->
    <<?HELLO_MAGIC/binary, ?VERSION:8, 0:8, (byte_size(Msg2)):16, Msg2/binary>>.

-spec reply_reject(1 | 2) -> binary().
reply_reject(Status) when Status =:= 1; Status =:= 2 ->
    <<?HELLO_MAGIC/binary, ?VERSION:8, Status:8, 0:16>>.

-spec msg3_frame(binary()) -> binary().
msg3_frame(Msg3) when is_binary(Msg3), byte_size(Msg3) =< ?MAX_FRAME_LENGTH ->
    <<(byte_size(Msg3)):16, Msg3/binary>>.

-spec prologue(binary(), binary()) -> binary().
prologue(<<_:?HELLO_HEADER_SIZE/binary>> = HelloHeader, Target)
  when is_binary(Target),
       byte_size(Target) >= ?MIN_NAME_LENGTH, byte_size(Target) =< ?MAX_NAME_LENGTH ->
    <<"bouncer/1", 0, HelloHeader/binary, (byte_size(Target)):16, Target/binary>>.

-spec encode_name(binary()) -> binary().
encode_name(Name)  when is_binary(Name),
                        byte_size(Name) >= ?MIN_NAME_LENGTH,
                        byte_size(Name) =< ?MAX_NAME_LENGTH ->
    <<(byte_size(Name)):16, Name/binary>>.

%% Decodes a length-prefixed node name. Rejects malformed/trailing data and
%% returns the name as a binary without creating an atom.
-spec decode_name(binary()) -> {ok, binary()} | {error, bad_name | bad_payload}.
decode_name(<<Len:16, Name:Len/binary>>) ->
    case bouncer_keys:valid_node_name(Name) of
        true -> {ok, Name};
        false -> {error, bad_name}
    end;
decode_name(_) ->
    {error, bad_payload}.

%% Empty-payload XX messages are 32, 96, and 64 bytes; the name payload is
%% encrypted in messages 2 and 3, adding its two-byte length and name bytes.
-spec limits() -> map().
limits() ->
    #{hello_header_bytes => ?HELLO_HEADER_SIZE,
      min_name_length => ?MIN_NAME_LENGTH,
      max_name_length => ?MAX_NAME_LENGTH,
      msg1_length => {?MSG1_LENGTH, ?MSG1_LENGTH},
      msg2_length => {96 + 2 + ?MIN_NAME_LENGTH, 96 + 2 + ?MAX_NAME_LENGTH},
      msg3_length => {64 + 2 + ?MIN_NAME_LENGTH, 64 + 2 + ?MAX_NAME_LENGTH}}.

%%% ==================================================================
%%% TRANSPORT FRAMING
%%% ==================================================================
%%
%% Pure functions only: no sockets, no processes, no application env, no
%% reading of `-bouncer` flags or OS env. Settings from those layers are
%% handed in by the caller as maps (see sender_policy/1).
%%
%% What the fetched enoise source (aeternity/enoise master, 24413c2) offers:
%%
%%  * Encrypt: `enoise_cipher_state:encrypt_with_ad(CS, AD, Plain)` returns
%%    `{ok, CS1, CipherText}` where CipherText = ciphertext ++ 16-byte tag.
%%    The nonce counter is inside CS and increments by one per call, so the
%%    new state must be kept.
%%  * Decrypt: `enoise_cipher_state:decrypt_with_ad(CS, AD, CipherText)`
%%    returns `{ok, CS1, Plain}` or `{error, decrypt_failed}`. On failure the
%%    old state is unchanged; we never reuse it, the receiver is dead. A cipher
%%    state without a key passes data through unchanged, so we refuse such a
%%    state in new_sender/2 and new_receiver/2.
%%  * Rekey: `enoise_cipher_state:rekey/1` EXISTS (Noise Rekey(): the new key
%%    is the first 32 bytes of ENCRYPT(k, 2^64-1, "", zeros(32)); the nonce is
%%    kept). BUT it is broken for 'AESGCM': enoise_crypto:rekey/2 only truncates
%%    for 'ChaChaPoly', so with AESGCM (our default suite) the new key is 48
%%    bytes long (ciphertext + tag) and the next encrypt crashes with badarg.
%%    That is why my personal enoise fork, with the fix for rekey, is used.
%%
%% What the OTP docs and source say about packet boundaries
%% (erts/doc/guides/alt_dist.md, erlang:dist_ctrl_get_data/1,
%% dist_ctrl_put_data/2, erts/emulator/beam/dist.c):
%%
%%  * The guide only says data must be delivered "as is" and in the "exact
%%    same order"; it does not say whether boundaries matter.
%%  * dist.c answers it: dist_ctrl_get_data/1 hands out ONE distribution
%%    message (packet) per call, and dist_ctrl_put_data/2 passes exactly the
%%    data of one call to erts_net_message(), which decodes it as one complete
%%    message (an empty call is a tick). So the receiving side NEEDS the same
%%    packet boundaries the sending side got. The `last` flag marks them: one
%%    {packet, iodata()} event is one dist_ctrl_put_data/2 call.
%%
%% Frame format (all integers big-endian):
%%
%%   wire:       <<CipherLen:16, Ciphertext:CipherLen/binary>>, 17..65535
%%   plaintext:  <<Flags:8, Rest/binary>>   (Rest = Payload, or when `pad` is
%%               set <<PadLen:16, Payload/binary, 0:PadLen/unit:8>>)
%%   AEAD:       the 2-byte length prefix is the associated data, so a
%%               tampered prefix is a decrypt_failed instead of a desync.
%%   Flags:      bit 0 last, 1 tick, 2 comp, 3 pad, 4 rekey, 5-7 reserved (0).
%%
%% Future idea (NOT implemented): reserved bits 5-7 could be redefined as a
%% `stream` flag whose payload starts with a stream id, to multiplex several
%% dist packet streams and let ticks/small packets overtake a big one. Today a
%% receiver closes on any reserved bit, so it needs a new protocol version.
%%
%% Compression security: compression MUST stay off (the default) for any
%% traffic where attacker-chosen data is mixed with secrets in one compressed
%% chunk (CRIME/BREACH class length oracle). Padding only hides lengths
%% partially and does not fix that. The receiver does not accept compressed
%% frames unless accept_compression is set.

-define(TAG_LEN, 16).
-define(MIN_CIPHER_LEN, 17).
-define(MAX_PLAINTEXT, 65519).
-define(MAX_PAYLOAD, 65518).
-define(DEFAULT_CHUNK_SIZE, 16384).
-define(DEFAULT_PADDING, none).
-define(DEFAULT_REKEY_BYTES, 1073741824).
-define(DEFAULT_MAX_PACKET, 67108864).

-define(F_LAST, 2#00000001).
-define(F_TICK, 2#00000010).
-define(F_COMP, 2#00000100).
-define(F_PAD, 2#00001000).
-define(F_REKEY, 2#00010000).
-define(F_RESERVED, 2#11100000).

-type padding()     :: none | {bucket, 1..65519} | {fixed, 4..65519}.
-type compression() :: none | {zlib, 0..65518}.
-type flags()       :: byte(). % bit 0 last, 1 tick, 2 comp, 3 pad, 4 rekey, 5-7 reserved (0)
-type rekey_limit() :: {frames, pos_integer()} | {bytes, pos_integer()} | {ms, pos_integer()}.
-type rekey_after() :: never | [rekey_limit(), ...].

-type sender_policy() :: #{chunk_size := 1..65518,
                           padding := padding(),
                           compression := compression(),
                           rekey_after := rekey_after(),
                           clock := fun(() -> integer())}.
-type receiver_policy() :: #{max_packet := pos_integer(),
                             accept_compression := boolean(),
                             max_bytes_without_rekey := pos_integer() | infinity}.
-type policy_error() :: {invalid_setting, Key :: atom(), Value :: term(),
                         Allowed :: string()}.

-type rx_error() :: decrypt_failed | bad_length | reserved_flags | tick_with_payload
                  | bad_padding | compression_not_accepted | bad_compression
                  | packet_too_large | rekey_required | rekey_unsupported.
-type rx_event() :: {packet, iodata()} | tick.

-record(tx, {
    cs          :: enoise_cipher_state:state(),
    chunk       :: pos_integer(),
    padding     :: padding(),
    compression :: compression(),
    zstream     :: undefined | zlib:zstream(),
    frames_limit = infinity :: pos_integer() | infinity,
    bytes_limit = infinity  :: pos_integer() | infinity,
    ms_limit = infinity     :: pos_integer() | infinity,
    has_ms = false          :: boolean(),
    clock       :: fun(() -> integer()),
    frames = 0  :: non_neg_integer(),
    bytes = 0   :: non_neg_integer(),
    t0          :: integer()
}).

-record(pending, {
    rest :: iodata() | {iovec, [binary()]},
    size :: pos_integer()
}).

-record(rx, {
    cs                 :: enoise_cipher_state:state(),
    %% Newest fragment first; before the length is known, buf holds one header byte.
    buf = []           :: [binary()],
    buf_size = 0       :: non_neg_integer(),
    expected = undefined :: undefined | 17..65535,
    acc = []           :: [iodata()],
    acc_size = 0       :: non_neg_integer(),
    max_packet         :: pos_integer(),
    accept_compression :: boolean(),
    zstream            :: undefined | zlib:zstream(),
    max_bytes          :: pos_integer() | infinity,
    since = 0          :: non_neg_integer(),
    dead = false       :: false | {true, rx_error()}
}).

-opaque sender() :: #tx{}.
-opaque receiver() :: #rx{}.
-opaque pending() :: #pending{}.

%%
%% Policies
%%

%% Validates sender settings and fills in defaults.
%% 
%% `Layers` is one settings map or a list of maps, highest precedence first
%% (the caller passes Opts, then `-bouncer` flags, then env, which gives the
%% precedence Opts > flag > env > default; this function reads none of them
%% itself). A value is either the native term or the string form used by flags and
%% env. Unknown keys are ignored.
%% 
%% | Key           | Native                                        | String                       | Default          |
%% |---------------|-----------------------------------------------|------------------------------|------------------|
%% | `chunk_size`  | `1..65518`                                    | `"16384"`                    | `65518`          |
%% | `padding`     | `none`, `{bucket, N}`, `{fixed, N}`           | `"none"`, `"bucket:512"`, `"fixed:4096"` | `"bucket:1400"` |
%% | `compression` | `none`, `{zlib, MinSize}`                     | `"none"`, `"zlib:256"`       | `none`           |
%% | `rekey_after` | `never` or list of `{frames,N}`/`{bytes,B}`/`{ms,T}` | `"never"`, `"bytes:1073741824,ms:3600000"` | `[{bytes, 1073741824}]` |
%% | `clock`       | `fun(() -> integer())` in ms (Opts only, for tests) | -                      | monotonic time   |
%% 
%% With padding the usable chunk size shrinks so that every frame fits: for
%% `{fixed, N}` a chunk is at most `N - 3` bytes, for `{bucket, N}` at most
%% `(65519 div N) * N - 3`.
-spec sender_policy([map()] | map()) -> {ok, sender_policy()} | {error, policy_error()}.
sender_policy(Layers) ->
    try
        {ok, #{chunk_size => setting(chunk_size, Layers, ?DEFAULT_CHUNK_SIZE, fun parse_chunk_size/1),
               padding => setting(padding, Layers, ?DEFAULT_PADDING, fun parse_padding/1),
               compression => setting(compression, Layers, none, fun parse_compression/1),
               rekey_after => setting(rekey_after, Layers, [{bytes, ?DEFAULT_REKEY_BYTES}],
                                      fun parse_rekey_after/1),
               clock => setting(clock, Layers, fun default_clock/0, fun parse_clock/1)}}
    catch
        throw:{invalid_setting, _, _, _} = Error -> {error, Error}
    end.

%% Validates receiver settings and fills in defaults (see `sender_policy/1` for
%% the layering).
%% 
%% | Key                       | Native / string                   | Default    |
%% |---------------------------|-----------------------------------|------------|
%% | `max_packet`              | positive integer                  | `67108864` |
%% | `accept_compression`      | `true` / `false`                  | `false`    |
%% | `max_bytes_without_rekey` | positive integer or `infinity`    | `infinity` |
-spec receiver_policy([map()] | map()) -> {ok, receiver_policy()} | {error, policy_error()}.
receiver_policy(Layers) ->
    try
        {ok, #{max_packet => setting(max_packet, Layers, ?DEFAULT_MAX_PACKET, fun parse_max_packet/1),
               accept_compression => setting(accept_compression, Layers, false, fun parse_bool/1),
               max_bytes_without_rekey => setting(max_bytes_without_rekey, Layers, infinity,
                                                  fun parse_max_bytes/1)}}
    catch
        throw:{invalid_setting, _, _, _} = Error -> {error, Error}
    end.

setting(Key, Layers, Default, Parse) when is_map(Layers) ->
    setting(Key, [Layers], Default, Parse);
setting(Key, Layers, Default, Parse) ->
    case [V || L <- Layers, {ok, V} <- [maps:find(Key, L)]] of
        [Value | _] ->
            case Parse(Value) of
                {ok, Parsed} -> Parsed;
                {error, Allowed} -> throw({invalid_setting, Key, Value, Allowed})
            end;
        [] ->
            Default
    end.

parse_chunk_size(V) ->
    case to_int(V) of
        N when is_integer(N), N >= 1, N =< ?MAX_PAYLOAD -> {ok, N};
        _ -> {error, "an integer from 1 to 65518"}
    end.

parse_padding(none) ->
    {ok, none};
parse_padding({bucket, N})
  when is_integer(N), N >= 1, N =< ?MAX_PLAINTEXT ->
    {ok, {bucket, N}};
parse_padding({fixed, N})
  when is_integer(N), N >= 4, N =< ?MAX_PLAINTEXT ->
    {ok, {fixed, N}};
parse_padding(V)
  when is_list(V); is_binary(V) ->
    case string:split(to_string(V), ":") of
        ["none"] -> {ok, none};
        ["bucket", N] -> parse_padding({bucket, to_int(N)});
        ["fixed", N] -> parse_padding({fixed, to_int(N)});
        _ -> padding_error()
    end;
parse_padding(_) ->
    padding_error().

padding_error() ->
    {error, "none | {bucket, 1..65519} | {fixed, 4..65519} (strings: none, bucket:N, fixed:N)"}.

parse_compression(none) ->
    {ok, none};
parse_compression({zlib, N})
  when is_integer(N), N >= 0, N =< ?MAX_PAYLOAD ->
    {ok, {zlib, N}};
parse_compression(V)
  when is_list(V); is_binary(V) ->
    case string:split(to_string(V), ":") of
        ["none"] -> {ok, none};
        ["zlib", N] -> parse_compression({zlib, to_int(N)});
        _ -> compression_error()
    end;
parse_compression(_) ->
    compression_error().

compression_error() ->
    {error, "none | {zlib, MinSize 0..65518} (strings: none, zlib:MinSize)"}.

parse_rekey_after(never) ->
    {ok, never};
parse_rekey_after([_ | _] = L)
  when is_tuple(hd(L)) ->
    case lists:all(fun rekey_limit_ok/1, L) of
        true -> {ok, L};
        false -> rekey_error()
    end;
parse_rekey_after(V)
  when is_list(V); is_binary(V) ->
    case to_string(V) of
        "never" ->
            {ok, never};
        Str ->
            Limits = [case string:split(P, ":") of
                          [K, N] when K =:= "frames"; K =:= "bytes"; K =:= "ms" ->
                              {list_to_atom(K), to_int(N)};
                          _ ->
                              {invalid, P}
                      end || P <- string:split(Str, ",", all)],
            case lists:all(fun rekey_limit_ok/1, Limits) of
                true -> {ok, Limits};
                false -> rekey_error()
            end
    end;
parse_rekey_after(_) ->
    rekey_error().

rekey_limit_ok({K, N}) when K =:= frames; K =:= bytes; K =:= ms ->
    is_integer(N) andalso N >= 1;
rekey_limit_ok(_) ->
    false.

rekey_error() ->
    {error, "never | non-empty list of {frames, N} | {bytes, B} | {ms, T} with positive integers "
            "(strings: never, or e.g. bytes:1073741824,ms:3600000)"}.

parse_clock(F) when is_function(F, 0) -> {ok, F};
parse_clock(_) -> {error, "a fun/0 returning milliseconds"}.

default_clock() ->
    erlang:monotonic_time(millisecond).

parse_max_packet(V) ->
    case to_int(V) of
        N when is_integer(N), N >= 1 -> {ok, N};
        _ -> {error, "a positive integer"}
    end.

parse_max_bytes(infinity)       -> {ok, infinity};
parse_max_bytes("infinity")     -> {ok, infinity};
parse_max_bytes(<<"infinity">>) -> {ok, infinity};
parse_max_bytes(V) ->
    case to_int(V) of
        N when is_integer(N), N >= 1 -> {ok, N};
        _ -> {error, "a positive integer or infinity"}
    end.

parse_bool(true) -> {ok, true};
parse_bool(false) -> {ok, false};
parse_bool(V) when is_list(V); is_binary(V) ->
    case to_string(V) of
        "true" -> {ok, true};
        "false" -> {ok, false};
        _ -> {error, "true | false"}
    end;
parse_bool(_) ->
    {error, "true | false"}.

%%
%% Sender
%%

%% Creates a sender around the transmit cipher state of a finished handshake.
%% 
%% `Policy` is a settings map as accepted by `sender_policy/1` (an already
%% validated policy is accepted too). Raises `badarg` for an invalid policy or a
%% cipher state without a key.
-spec new_sender(enoise_cipher_state:state(), map()) -> sender().
new_sender(CS, Policy) when is_map(Policy) ->
    ok = check_keyed(CS),
    #{chunk_size := Chunk,
      padding := Padding,
      compression := Compression,
      rekey_after := RekeyAfter,
      clock := Clock} = ok_policy(sender_policy(Policy)),

    #tx{cs = CS,
        chunk = effective_chunk(Chunk, Padding),
        padding = Padding,
        compression = Compression,
        zstream = undefined, % must be initialized via tx_start
        frames_limit = limit(frames, RekeyAfter),
        bytes_limit = limit(bytes, RekeyAfter),
        ms_limit = limit(ms, RekeyAfter),
        has_ms = is_list(RekeyAfter) andalso lists:keymember(ms, 1, RekeyAfter),
        clock = Clock,
        t0 = Clock()}.

%% Smallest configured limit of a kind; the atom `infinity` is greater than any
%% integer in term order, so comparing against it is always false.
limit(_Kind, never) ->
    infinity;
limit(Kind, Limits) ->
    lists:min([infinity | [N || {K, N} <- Limits, K =:= Kind]]).

%% Creates a receiver around the receive cipher state of a finished handshake.
%% `Policy` is a settings map as accepted by `receiver_policy/1`.
-spec new_receiver(enoise_cipher_state:state(), map()) -> receiver().
new_receiver(CS, Policy) when is_map(Policy) ->
    ok = check_keyed(CS),
    #{max_packet := MaxPacket,
      accept_compression := Accept,
      max_bytes_without_rekey := MaxBytes} = ok_policy(receiver_policy(Policy)),

    #rx{cs = CS,
        max_packet = MaxPacket,
        accept_compression = Accept,
        max_bytes = MaxBytes}.

ok_policy({ok, Policy}) -> Policy;
ok_policy({error, Error}) -> erlang:error({badarg, Error}).

check_keyed(CS) ->
    case enoise_cipher_state:has_key(CS) of
        true -> ok;
        false -> erlang:error(badarg)
    end.

%% Largest chunk for which every frame still fits in 65519 plaintext bytes.
effective_chunk(Chunk, none) -> Chunk;
effective_chunk(Chunk, {fixed, N}) -> min(Chunk, N - 3);
effective_chunk(Chunk, {bucket, N}) -> min(Chunk, (?MAX_PLAINTEXT div N) * N - 3).

%% Initialization steps which must be done in the controlling process of the socket.
%% It must be called at the start of the writing process. This initializes the
%% zstream in the controlling process.
-spec tx_start(sender()) -> sender().
tx_start(#tx{ compression = {zlib, _}}=Tx) ->
    Z = zlib:open(),
    ok = zlib:deflateInit(Z, default, deflated, -15, 8, default),
    Tx#tx{ zstream = Z };
tx_start(#tx{ compression = none }=Tx) ->
    Tx.

%% Starts sending one dist packet. Packets are never empty (an empty dist packet
%% is a tick, use `tx_tick/1`); an empty packet raises `badarg`.
-spec tx_packet(iodata()) -> pending().
tx_packet(Packet) ->
    case iolist_size(Packet) of
        0 -> erlang:error(badarg);
        Size -> #pending{rest = Packet, size = Size}
    end.

%% Produces one frame of the packet. The caller may do other work (including
%% `tx_tick/1`) between calls, but must put the frames of one packet on the wire
%% contiguously and finish a packet before starting the next. The frame of the
%% final chunk carries the `last` flag. A frame carries the `rekey` flag when one
%% of the `rekey_after` limits has been reached; the returned sender then already
%% uses the new key.
-spec tx_next(sender(), pending()) ->
          {iolist(), sender(), more, pending()} | {iolist(), sender(), done}.
tx_next(#tx{chunk = Chunk} = S, #pending{rest = Rest, size = Size}) ->
    case Size > Chunk of
        true ->
            {Part, Tail} = split_packet(Rest, Chunk),
            {Frame, S1} = tx_data(S, Part, 0),
            {Frame, S1, more, #pending{rest = Tail, size = Size - Chunk}};
        false ->
            {Frame, S1} = tx_data(S, pending_data(Rest), ?F_LAST),
            {Frame, S1, done}
    end.

split_packet(Rest, Chunk) when is_binary(Rest) ->
    <<Part:Chunk/binary, Tail/binary>> = Rest,
    {Part, Tail};
split_packet({iovec, Iovec}, Chunk) ->
    split_iovec(Iovec, Chunk, []);
split_packet(Rest, Chunk) ->
    split_iovec(erlang:iolist_to_iovec(Rest), Chunk, []).

split_iovec([Bin | Rest], Size, Acc) when byte_size(Bin) < Size ->
    split_iovec(Rest, Size - byte_size(Bin), [Bin | Acc]);
split_iovec([Bin | Rest], Size, Acc) ->
    <<Part:Size/binary, Tail/binary>> = Bin,
    Remaining = case Tail of
                    <<>> -> Rest;
                    _ -> [Tail | Rest]
                end,
    {lists:reverse([Part | Acc]), {iovec, Remaining}}.

pending_data({iovec, Iovec}) -> Iovec;
pending_data(Data) -> Data.

%% Produces a keepalive frame. It is padded like data frames, so with padding
%% enabled it is indistinguishable from data by length. May be called between the
%% frames of a packet.
-spec tx_tick(sender()) -> {iolist(), sender()}.
tx_tick(S) ->
    emit(S, ?F_TICK, <<>>).

tx_data(S, Chunk, Flags) ->
    {Flags1, Payload} = maybe_compress(S, Chunk, Flags),
    emit(S, Flags1, Payload).

maybe_compress(#tx{compression = {zlib, MinSize}, zstream = Z}, Chunk, Flags)
  when is_integer(MinSize) ->
    ChunkSize = iolist_size(Chunk),
    case ChunkSize >= MinSize of
        true -> compress(Z, Chunk, ChunkSize, Flags);
        false -> {Flags, Chunk}
    end;
maybe_compress(_, Chunk, Flags) ->
    {Flags, Chunk}.

compress(Z, Chunk, ChunkSize, Flags) ->
    Compressed = deflate_raw(Z, Chunk),
    case iolist_size(Compressed) < ChunkSize of
        true -> {Flags bor ?F_COMP, Compressed};
        false -> {Flags, Chunk}
    end.

deflate_raw(Z, Data) ->
    ok = zlib:deflateReset(Z),
    zlib:deflate(Z, Data, finish).

emit(#tx{padding = Padding} = S, Flags0, Payload) ->
    {Flags1, Body} = pad(Padding, Flags0, Payload),

    CipherLen = 1 + iolist_size(Body) + ?TAG_LEN,

    Now = rekey_clock(S),
    IsRekeyDue = rekey_due(S, CipherLen, Now),

    Flags = case IsRekeyDue of
                true  ->
                    Flags1 bor ?F_REKEY;
                false ->
                    Flags1
            end,

    BinCipherLen = <<CipherLen:16>>,
    {ok, CS1, Cipher} = enoise_cipher_state:encrypt_with_ad_iolist(S#tx.cs, BinCipherLen, [Flags, Body]),
    Frame = [BinCipherLen, Cipher],

    case IsRekeyDue of
        true ->
            {Frame, S#tx{cs = enoise_cipher_state:rekey(CS1),
                         frames = 0,
                         bytes = 0,
                         t0 = Now}};
        false ->
            {Frame, S#tx{cs = CS1,
                         frames = S#tx.frames + 1,
                         bytes = S#tx.bytes + CipherLen}}
    end.

rekey_clock(#tx{has_ms = true, clock = Clock}) ->
    Clock();
rekey_clock(#tx{}) ->
    0.

rekey_due(#tx{frames_limit = FL, bytes_limit = BL, ms_limit = ML, frames = Frames, bytes = Bytes, t0 = T0}, Len, Now) ->
    Frames + 1 >= FL orelse Bytes + Len >= BL orelse Now - T0 >= ML.

%%
%% Receiver
%%

%% Initialize the reader from the controlling process.
-spec rx_start(receiver()) -> receiver().
rx_start(#rx{accept_compression = true}=Rx) ->
    Z = zlib:open(),
    ok = zlib:inflateInit(Z, -15),
    Rx#rx{zstream = Z};
rx_start(#rx{accept_compression = false}=Rx) ->
    Rx.

%% Feeds received bytes (any split of the byte stream) to the receiver.
%%
%% Returns the events completed by these bytes in order: `{packet, Iodata}` for
%% each fully reassembled dist packet (pass it to one `dist_ctrl_put_data/2`
%% call) and `tick`. Partial frames are buffered. Ticks may arrive between the
%% frames of a packet.
%% 
%% On any violation it returns `{error, Reason, Dead}`; the connection must then
%% be closed. `Dead` refuses all further input with the same error (events decoded
%% earlier in the same call are dropped). The state before the failing call must
%% not be reused either: its cipher state is behind.
%% 
%% `Reason`: `decrypt_failed` (bad tag, key or tampering), `bad_length` (cipher
%% length below 17, or a data frame without payload), `reserved_flags`,
%% `tick_with_payload` (also a tick with `last` or `comp`), `bad_padding` (PadLen
%% too large or nonzero padding bytes), `compression_not_accepted`,
%% `bad_compression` (invalid deflate data, or more than 65518 bytes inflated),
%% `packet_too_large` (checked after every frame, while reassembling),
%% `rekey_required` (`max_bytes_without_rekey` exceeded) and `rekey_unsupported`.
-spec rx_feed(receiver(), binary()) ->
          {ok, [rx_event()], receiver()} | {error, rx_error(), receiver()}.
rx_feed(#rx{dead = {true, Reason}} = R, Bytes) when is_binary(Bytes) ->
    {error, Reason, R};
rx_feed(R, Bytes) when is_binary(Bytes) ->
    rx_loop(R, Bytes, []).

%%
rx_loop(R, <<>>, Evs) ->
    {ok, lists:reverse(Evs), R};
rx_loop(#rx{expected = undefined, buf = [<<High>>]} = R, <<Low, Rest/binary>>, Evs) ->
    rx_header(R#rx{buf = [], buf_size = 0}, (High bsl 8) bor Low, Rest, Evs);
rx_loop(#rx{expected = undefined} = R, <<Len:16, Rest/binary>>, Evs) ->
    rx_header(R, Len, Rest, Evs);
rx_loop(#rx{expected = undefined} = R, <<Byte>>, Evs) ->
    {ok, lists:reverse(Evs), R#rx{buf = [<<Byte>>], buf_size = 1}};
rx_loop(#rx{expected = Len, buf = Buf, buf_size = Size} = R, Bytes, Evs) ->
    Needed = Len - Size,
    BytesSize = iolist_size(Bytes),
    case BytesSize >= Needed of
        true ->
            <<Part:Needed/binary, Tail/binary>> = Bytes,
            Cipher = case Buf of
                         [] -> Part;
                         _ -> iolist_to_binary(lists:reverse([Part | Buf]))
                     end,
            rx_complete(R#rx{buf = [], buf_size = 0, expected = undefined},
                        Len, Cipher, Tail, Evs);
        false ->
            {ok, lists:reverse(Evs),
             R#rx{buf = [Bytes | Buf], buf_size = Size + BytesSize}}
    end.

rx_header(R, Len, _Bytes, _Evs) when Len < ?MIN_CIPHER_LEN ->
    rx_fail(R, bad_length);
rx_header(R, Len, Bytes, Evs) when byte_size(Bytes) >= Len ->
    <<Cipher:Len/binary, Tail/binary>> = Bytes,
    rx_complete(R, Len, Cipher, Tail, Evs);
rx_header(R, Len, <<>>, Evs) ->
    {ok, lists:reverse(Evs), R#rx{expected = Len}};
rx_header(R, Len, Bytes, Evs) ->
    {ok, lists:reverse(Evs),
     R#rx{buf = [Bytes], buf_size = iolist_size(Bytes), expected = Len}}.

rx_complete(R, Len, Cipher, Tail, Evs) ->
    case rx_frame(R, Len, Cipher) of
        {ok, none, R1} -> rx_loop(R1, Tail, Evs);
        {ok, Ev, R1} -> rx_loop(R1, Tail, [Ev | Evs]);
        {error, Reason} -> rx_fail(R, Reason)
    end.

%%
rx_fail(R, Reason) ->
    {error, Reason, R#rx{dead = {true, Reason}, buf = [], buf_size = 0,
                         expected = undefined, acc = [], acc_size = 0}}.

%%
rx_frame(#rx{max_bytes = Max, since = Since}, Len, _) when Max =/= infinity, Since + Len > Max ->
    {error, rekey_required};
rx_frame(#rx{cs = CS} = R, Len, Cipher) ->
    case enoise_cipher_state:decrypt_with_ad(CS, <<Len:16>>, Cipher) of
        {ok, CS1, <<Flags, Rest/binary>>} ->
            rx_flags(R#rx{cs = CS1}, Len, Flags, Rest);
        _ ->
            {error, decrypt_failed}
    end.

%%
rx_flags(_, _, Flags, _) when Flags band ?F_RESERVED =/= 0 ->
    {error, reserved_flags};
rx_flags(R, Len, Flags, Rest) ->
    case unpad(Flags, Rest) of
        {ok, Payload} ->
            case rx_payload(R, Flags, Payload) of
                {ok, Ev, R1} ->
                    rx_rekey(R1, Len, Flags, Ev);
                {error, _} = Error ->
                    Error
            end;
        {error, _} = Error ->
            Error
    end.

%%
rx_payload(R, Flags, Payload) when Flags band ?F_TICK =/= 0 ->
    case Payload =:= <<>> andalso Flags band (?F_LAST bor ?F_COMP) =:= 0 of
        true ->
            {ok, tick, R};
        false ->
            {error, tick_with_payload}
    end;
rx_payload(_, _, <<>>) ->
    {error, bad_length};
rx_payload(R, Flags, Payload) when Flags band ?F_COMP =/= 0 ->
    case R#rx.accept_compression of
        false ->
            {error, compression_not_accepted};
        true ->
            case inflate_raw(R#rx.zstream, Payload) of
                {ok, Chunk, ChunkSize} ->
                    rx_data(R, Flags, Chunk, ChunkSize);
                {error, _} = Error ->
                    Error
            end
    end;
rx_payload(R, Flags, Payload) ->
    rx_data(R, Flags, Payload, byte_size(Payload)).

%%
rx_data(#rx{acc = Acc, acc_size = Size, max_packet = Max} = R, Flags, Chunk, ChunkSize) ->
    Size1 = Size + ChunkSize,
    if
        Size1 > Max ->
            {error, packet_too_large};
        Flags band ?F_LAST =/= 0 ->
            {ok, {packet, lists:reverse([Chunk | Acc])}, R#rx{acc = [], acc_size = 0}};
        true ->
            {ok, none, R#rx{acc = [Chunk | Acc], acc_size = Size1}}
    end.

%
rx_rekey(R, _Len, Flags, Ev) when Flags band ?F_REKEY =/= 0 ->
    CS = enoise_cipher_state:rekey(R#rx.cs),
    {ok, Ev, R#rx{cs = CS, since = 0}};
rx_rekey(#rx{since = Since} = R, Len, _Flags, Ev) ->
    {ok, Ev, R#rx{since = Since + Len}}.

%%
%% Helpers
%%

to_string(V) when is_binary(V) -> unicode:characters_to_list(V);
to_string(V) -> V.

to_int(N) when is_integer(N) -> N;
to_int(V) when is_list(V); is_binary(V) ->
    case catch string:to_integer(to_string(V)) of
        {N, ""} when is_integer(N) -> N;
        _ -> error
    end;
to_int(_) -> error.

%% Total plaintext is 1 (flags) + 2 (PadLen) + Payload + PadLen.
-spec pad(padding(), flags(), iodata()) -> {flags(), iodata()}.
pad(none, Flags, Payload) ->
    {Flags, Payload};
pad({bucket, N}, Flags, Payload) ->
    Base = 3 + iolist_size(Payload),
    padded(Flags, Payload, ((Base + N - 1) div N) * N - Base);
pad({fixed, N}, Flags, Payload) ->
    padded(Flags, Payload, N - 3 - iolist_size(Payload)).

padded(Flags, Payload, PadLen) ->
    {Flags bor ?F_PAD, [<<PadLen:16>>, Payload, <<0:(PadLen * 8)>>]}.


-spec unpad(flags(), iodata()) -> {ok, binary()} | {error, bad_padding}.
unpad(Flags, Rest) when Flags band ?F_PAD =:= 0 ->
    {ok, Rest};
unpad(_, Rest) when is_binary(Rest) ->
    unpad1(Rest);
unpad(_, Rest) when is_list(Rest) ->
    unpad1(iolist_to_binary(Rest)).

unpad1(<<PadLen:16, Body/binary>>) when PadLen =< byte_size(Body) ->
    PayloadLen = byte_size(Body) - PadLen,
    <<Payload:PayloadLen/binary, Padding:PadLen/binary>> = Body,
    case 3 + PayloadLen + PadLen =< ?MAX_PLAINTEXT andalso Padding =:= <<0:(PadLen * 8)>> of
        true ->
            {ok, Payload};
        false ->
            {error, bad_padding}
    end;
unpad1(B) when is_binary(B) ->
    {error, bad_padding}.

inflate_raw(Z, Data) ->
    try
        ok = zlib:inflateReset(Z),
        Out = zlib:inflate(Z, Data),
        OutSize = iolist_size(Out),
        if
            OutSize > ?MAX_PAYLOAD ->
                {error, bad_compression};
            OutSize =:= 0 ->
                {error, bad_compression};
            true ->
                {ok, Out, OutSize}
        end
    catch
        error:_ -> {error, bad_compression}
    end.
