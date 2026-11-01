%% Pure wire-format helpers for the bouncer Noise handshake.
-module(bouncer_protocol).

-export([
    hello_header/1,
    hello/2,
    parse_hello_header/2,
    reply_ok/1,
    reply_reject/1,
    msg3_frame/1,
    prologue/2,
    name_payload/1,
    noise_name/1,
    suite_id/1,
    suite_atom/1,
    known_suites/0,
    limits/0
]).

%% Transport framing (see the TRANSPORT FRAMING section at the bottom).
-export([
    sender_policy/1,
    receiver_policy/1,
    new_sender/2,
    new_receiver/2,
    tx_packet/1,
    tx_next/2,
    tx_tick/1,
    rx_feed/2
]).

-export_type([sender/0, receiver/0, pending/0, sender_policy/0, receiver_policy/0,
              rx_event/0, rx_error/0, policy_error/0]).

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

-spec name_payload(binary()) -> binary().
name_payload(Name) when is_binary(Name),
                        byte_size(Name) >= ?MIN_NAME_LENGTH,
                        byte_size(Name) =< ?MAX_NAME_LENGTH ->
    <<(byte_size(Name)):16, Name/binary>>.

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
-define(DEFAULT_REKEY_BYTES, 1073741824).
-define(DEFAULT_MAX_PACKET, 67108864).

-define(F_LAST, 2#00000001).
-define(F_TICK, 2#00000010).
-define(F_COMP, 2#00000100).
-define(F_PAD, 2#00001000).
-define(F_REKEY, 2#00010000).
-define(F_RESERVED, 2#11100000).

-type padding() :: none | {bucket, 1..65519} | {fixed, 4..65519}.
-type compression() :: none | {zlib, 0..65518}.
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

-record(tx, {cs :: enoise_cipher_state:state(),
             chunk :: pos_integer(),
             padding :: padding(),
             compression :: compression(),
             rekey_after :: rekey_after(),
             clock :: fun(() -> integer()),
             frames = 0 :: non_neg_integer(),
             bytes = 0 :: non_neg_integer(),
             t0 :: integer()}).
-record(pending, {rest :: binary()}).
-record(rx, {cs :: enoise_cipher_state:state(),
             buf = <<>> :: binary(),
             acc = [] :: [binary()],
             acc_size = 0 :: non_neg_integer(),
             max_packet :: pos_integer(),
             accept_compression :: boolean(),
             max_bytes :: pos_integer() | infinity,
             since = 0 :: non_neg_integer(),
             dead = false :: false | {true, rx_error()}}).

-opaque sender() :: #tx{}.
-opaque receiver() :: #rx{}.
-opaque pending() :: #pending{}.

%%% ------------------------------------------------------------------
%%% Policies
%%% ------------------------------------------------------------------

-doc """
Validates sender settings and fills in defaults.

`Layers` is one settings map or a list of maps, highest precedence first
(the caller passes Opts, then `-bouncer` flags, then env, which gives the
precedence Opts > flag > env > default; this function reads none of them
itself). A value is either the native term or the string form used by flags and
env. Unknown keys are ignored.

| Key           | Native                                        | String                       | Default          |
|---------------|-----------------------------------------------|------------------------------|------------------|
| `chunk_size`  | `1..65518`                                    | `"16384"`                    | `16384`          |
| `padding`     | `none`, `{bucket, N}`, `{fixed, N}`           | `"none"`, `"bucket:512"`, `"fixed:4096"` | `none` |
| `compression` | `none`, `{zlib, MinSize}`                     | `"none"`, `"zlib:256"`       | `none`           |
| `rekey_after` | `never` or list of `{frames,N}`/`{bytes,B}`/`{ms,T}` | `"never"`, `"bytes:1073741824,ms:3600000"` | `[{bytes, 1073741824}]` |
| `clock`       | `fun(() -> integer())` in ms (Opts only, for tests) | -                      | monotonic time   |

With padding the usable chunk size shrinks so that every frame fits: for
`{fixed, N}` a chunk is at most `N - 3` bytes, for `{bucket, N}` at most
`(65519 div N) * N - 3`.
""".
-spec sender_policy([map()] | map()) -> {ok, sender_policy()} | {error, policy_error()}.
sender_policy(Layers) ->
    try
        {ok, #{chunk_size => setting(chunk_size, Layers, ?DEFAULT_CHUNK_SIZE, fun parse_chunk_size/1),
               padding => setting(padding, Layers, none, fun parse_padding/1),
               compression => setting(compression, Layers, none, fun parse_compression/1),
               rekey_after => setting(rekey_after, Layers, [{bytes, ?DEFAULT_REKEY_BYTES}],
                                      fun parse_rekey_after/1),
               clock => setting(clock, Layers, fun default_clock/0, fun parse_clock/1)}}
    catch
        throw:{invalid_setting, _, _, _} = Error -> {error, Error}
    end.

-doc """
Validates receiver settings and fills in defaults (see `sender_policy/1` for
the layering).

| Key                       | Native / string                   | Default    |
|---------------------------|-----------------------------------|------------|
| `max_packet`              | positive integer                  | `67108864` |
| `accept_compression`      | `true` / `false`                  | `false`    |
| `max_bytes_without_rekey` | positive integer or `infinity`    | `infinity` |
""".
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

parse_padding(none) -> {ok, none};
parse_padding({bucket, N}) when is_integer(N), N >= 1, N =< ?MAX_PLAINTEXT -> {ok, {bucket, N}};
parse_padding({fixed, N}) when is_integer(N), N >= 4, N =< ?MAX_PLAINTEXT -> {ok, {fixed, N}};
parse_padding(V) when is_list(V); is_binary(V) ->
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

parse_compression(none) -> {ok, none};
parse_compression({zlib, N}) when is_integer(N), N >= 0, N =< ?MAX_PAYLOAD -> {ok, {zlib, N}};
parse_compression(V) when is_list(V); is_binary(V) ->
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
parse_rekey_after([_ | _] = L) when is_tuple(hd(L)) ->
    case lists:all(fun rekey_limit_ok/1, L) of
        true -> {ok, L};
        false -> rekey_error()
    end;
parse_rekey_after(V) when is_list(V); is_binary(V) ->
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

parse_max_bytes(infinity) -> {ok, infinity};
parse_max_bytes("infinity") -> {ok, infinity};
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

to_string(V) when is_binary(V) -> unicode:characters_to_list(V);
to_string(V) -> V.

to_int(N) when is_integer(N) -> N;
to_int(V) when is_list(V); is_binary(V) ->
    case catch string:to_integer(to_string(V)) of
        {N, ""} when is_integer(N) -> N;
        _ -> error
    end;
to_int(_) -> error.

%%% ------------------------------------------------------------------
%%% Sender
%%% ------------------------------------------------------------------

-doc """
Creates a sender around the transmit cipher state of a finished handshake.

`Policy` is a settings map as accepted by `sender_policy/1` (an already
validated policy is accepted too). Raises `badarg` for an invalid policy or a
cipher state without a key.
""".
-spec new_sender(enoise_cipher_state:state(), map()) -> sender().
new_sender(CS, Policy) when is_map(Policy) ->
    ok = check_keyed(CS),
    #{chunk_size := Chunk, padding := Padding, compression := Compression,
      rekey_after := RekeyAfter, clock := Clock} = ok_policy(sender_policy(Policy)),
    #tx{cs = CS, chunk = effective_chunk(Chunk, Padding), padding = Padding,
        compression = Compression, rekey_after = RekeyAfter, clock = Clock,
        t0 = Clock()}.

-doc """
Creates a receiver around the receive cipher state of a finished handshake.
`Policy` is a settings map as accepted by `receiver_policy/1`.
""".
-spec new_receiver(enoise_cipher_state:state(), map()) -> receiver().
new_receiver(CS, Policy) when is_map(Policy) ->
    ok = check_keyed(CS),
    #{max_packet := MaxPacket, accept_compression := Accept,
      max_bytes_without_rekey := MaxBytes} = ok_policy(receiver_policy(Policy)),
    #rx{cs = CS, max_packet = MaxPacket, accept_compression = Accept, max_bytes = MaxBytes}.

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

-doc """
Starts sending one dist packet. Packets are never empty (an empty dist packet
is a tick, use `tx_tick/1`); an empty packet raises `badarg`.
""".
-spec tx_packet(iodata()) -> pending().
tx_packet(Packet) ->
    case iolist_to_binary(Packet) of
        <<>> -> erlang:error(badarg);
        Bin -> #pending{rest = Bin}
    end.

-doc """
Produces one frame of the packet. The caller may do other work (including
`tx_tick/1`) between calls, but must put the frames of one packet on the wire
contiguously and finish a packet before starting the next. The frame of the
final chunk carries the `last` flag. A frame carries the `rekey` flag when one
of the `rekey_after` limits has been reached; the returned sender then already
uses the new key.
""".
-spec tx_next(sender(), pending()) ->
          {iodata(), sender(), more, pending()} | {iodata(), sender(), done}.
tx_next(#tx{chunk = Chunk} = S, #pending{rest = Rest}) when byte_size(Rest) > Chunk ->
    <<Part:Chunk/binary, Tail/binary>> = Rest,
    {Frame, S1} = tx_data(S, Part, 0),
    {Frame, S1, more, #pending{rest = Tail}};
tx_next(S, #pending{rest = Rest}) ->
    {Frame, S1} = tx_data(S, Rest, ?F_LAST),
    {Frame, S1, done}.

-doc """
Produces a keepalive frame. It is padded like data frames, so with padding
enabled it is indistinguishable from data by length. May be called between the
frames of a packet.
""".
-spec tx_tick(sender()) -> {iodata(), sender()}.
tx_tick(S) ->
    emit(S, ?F_TICK, <<>>).

tx_data(S, Chunk, Flags) ->
    {Flags1, Payload} = maybe_compress(S#tx.compression, Chunk, Flags),
    emit(S, Flags1, Payload).

maybe_compress({zlib, MinSize}, Chunk, Flags) when byte_size(Chunk) >= MinSize ->
    Compressed = deflate_raw(Chunk),
    case byte_size(Compressed) < byte_size(Chunk) of
        true -> {Flags bor ?F_COMP, Compressed};
        false -> {Flags, Chunk}
    end;
maybe_compress(_, Chunk, Flags) ->
    {Flags, Chunk}.

deflate_raw(Data) ->
    Z = zlib:open(),
    try
        ok = zlib:deflateInit(Z, default, deflated, -15, 8, default),
        iolist_to_binary(zlib:deflate(Z, Data, finish))
    after
        zlib:close(Z)
    end.

emit(#tx{padding = Padding} = S, Flags0, Payload) ->
    {Flags1, Body} = pad(Padding, Flags0, Payload),
    Len = 1 + byte_size(Body) + ?TAG_LEN,
    Now = rekey_clock(S),
    Rekey = rekey_due(S, Len, Now),
    Flags = case Rekey of
                true -> Flags1 bor ?F_REKEY;
                false -> Flags1
            end,
    {ok, CS1, Cipher} = encrypt(S#tx.cs, <<Len:16>>, <<Flags, Body/binary>>),
    Len = byte_size(Cipher),
    Frame = [<<Len:16>>, Cipher],
    case Rekey of
        true ->
            {Frame, S#tx{cs = enoise_cipher_state:rekey(CS1), frames = 0, bytes = 0, t0 = Now}};
        false ->
            {Frame, S#tx{cs = CS1, frames = S#tx.frames + 1, bytes = S#tx.bytes + Len}}
    end.

%% enoise only ever returns {ok, _, _} here; a failure would be a bug.
encrypt(CS, AD, Plain) ->
    {ok, _, _} = enoise_cipher_state:encrypt_with_ad(CS, AD, Plain).

%% Total plaintext is 1 (flags) + 2 (PadLen) + Payload + PadLen.
pad(none, Flags, Payload) ->
    {Flags, Payload};
pad({bucket, N}, Flags, Payload) ->
    Base = 3 + byte_size(Payload),
    padded(Flags, Payload, ((Base + N - 1) div N) * N - Base);
pad({fixed, N}, Flags, Payload) ->
    padded(Flags, Payload, N - 3 - byte_size(Payload)).

padded(Flags, Payload, PadLen) ->
    {Flags bor ?F_PAD, <<PadLen:16, Payload/binary, 0:(PadLen * 8)>>}.

rekey_clock(#tx{rekey_after = RekeyAfter, clock = Clock}) when is_list(RekeyAfter) ->
    case lists:keymember(ms, 1, RekeyAfter) of
        true -> Clock();
        false -> 0
    end;
rekey_clock(_) ->
    0.

rekey_due(#tx{rekey_after = never}, _, _) ->
    false;
rekey_due(#tx{rekey_after = Limits, frames = Frames, bytes = Bytes, t0 = T0}, Len, Now) ->
    lists:any(fun({frames, N}) -> Frames + 1 >= N;
                 ({bytes, B}) -> Bytes + Len >= B;
                 ({ms, T}) -> Now - T0 >= T
              end, Limits).

%%% ------------------------------------------------------------------
%%% Receiver
%%% ------------------------------------------------------------------

-doc """
Feeds received bytes (any split of the byte stream) to the receiver.

Returns the events completed by these bytes in order: `{packet, Iodata}` for
each fully reassembled dist packet (pass it to one `dist_ctrl_put_data/2`
call) and `tick`. Partial frames are buffered. Ticks may arrive between the
frames of a packet.

On any violation it returns `{error, Reason, Dead}`; the connection must then
be closed. `Dead` refuses all further input with the same error (events decoded
earlier in the same call are dropped). The state before the failing call must
not be reused either: its cipher state is behind.

`Reason`: `decrypt_failed` (bad tag, key or tampering), `bad_length` (cipher
length below 17, or a data frame without payload), `reserved_flags`,
`tick_with_payload` (also a tick with `last` or `comp`), `bad_padding` (PadLen
too large or nonzero padding bytes), `compression_not_accepted`,
`bad_compression` (invalid deflate data, or more than 65518 bytes inflated),
`packet_too_large` (checked after every frame, while reassembling),
`rekey_required` (`max_bytes_without_rekey` exceeded) and `rekey_unsupported`.
""".
-spec rx_feed(receiver(), binary()) ->
          {ok, [rx_event()], receiver()} | {error, rx_error(), receiver()}.
rx_feed(#rx{dead = {true, Reason}} = R, Bytes) when is_binary(Bytes) ->
    {error, Reason, R};
rx_feed(#rx{buf = <<>>} = R, Bytes) when is_binary(Bytes) ->
    rx_loop(R#rx{buf = Bytes}, []);
rx_feed(#rx{buf = Buf} = R, Bytes) when is_binary(Bytes) ->
    rx_loop(R#rx{buf = <<Buf/binary, Bytes/binary>>}, []).

rx_loop(#rx{buf = <<Len:16, _/binary>>} = R, _Evs) when Len < ?MIN_CIPHER_LEN ->
    rx_fail(R, bad_length);
rx_loop(#rx{buf = <<Len:16, Rest/binary>>} = R, Evs) when byte_size(Rest) >= Len ->
    <<Cipher:Len/binary, Tail/binary>> = Rest,
    case rx_frame(R#rx{buf = Tail}, Len, Cipher) of
        {ok, none, R1} -> rx_loop(R1, Evs);
        {ok, Ev, R1} -> rx_loop(R1, [Ev | Evs]);
        {error, Reason} -> rx_fail(R, Reason)
    end;
rx_loop(R, Evs) ->
    {ok, lists:reverse(Evs), R}.

rx_fail(R, Reason) ->
    {error, Reason, R#rx{dead = {true, Reason}, buf = <<>>, acc = [], acc_size = 0}}.

rx_frame(#rx{max_bytes = Max, since = Since}, Len, _) when Max =/= infinity, Since + Len > Max ->
    {error, rekey_required};
rx_frame(#rx{cs = CS} = R, Len, Cipher) ->
    case enoise_cipher_state:decrypt_with_ad(CS, <<Len:16>>, Cipher) of
        {ok, CS1, <<Flags, Rest/binary>>} ->
            rx_flags(R#rx{cs = CS1}, Len, Flags, Rest);
        _ ->
            {error, decrypt_failed}
    end.

rx_flags(_, _, Flags, _) when Flags band ?F_RESERVED =/= 0 ->
    {error, reserved_flags};
rx_flags(R, Len, Flags, Rest) ->
    case unpad(Flags, Rest) of
        {ok, Payload} ->
            case rx_payload(R, Flags, Payload) of
                {ok, Ev, R1} -> rx_rekey(R1, Len, Flags, Ev);
                {error, _} = Error -> Error
            end;
        {error, _} = Error ->
            Error
    end.

unpad(Flags, Rest) when Flags band ?F_PAD =:= 0 ->
    {ok, Rest};
unpad(_, <<PadLen:16, Body/binary>>) when PadLen =< byte_size(Body) ->
    PayloadLen = byte_size(Body) - PadLen,
    <<Payload:PayloadLen/binary, Padding:PadLen/binary>> = Body,
    case 3 + PayloadLen + PadLen =< ?MAX_PLAINTEXT andalso Padding =:= <<0:(PadLen * 8)>> of
        true -> {ok, Payload};
        false -> {error, bad_padding}
    end;
unpad(_, _) ->
    {error, bad_padding}.

rx_payload(R, Flags, Payload) when Flags band ?F_TICK =/= 0 ->
    case Payload =:= <<>> andalso Flags band (?F_LAST bor ?F_COMP) =:= 0 of
        true -> {ok, tick, R};
        false -> {error, tick_with_payload}
    end;
rx_payload(_, _, <<>>) ->
    {error, bad_length};
rx_payload(R, Flags, Payload) when Flags band ?F_COMP =/= 0 ->
    case R#rx.accept_compression of
        false ->
            {error, compression_not_accepted};
        true ->
            case inflate_raw(Payload) of
                {ok, Chunk} -> rx_data(R, Flags, Chunk);
                {error, _} = Error -> Error
            end
    end;
rx_payload(R, Flags, Payload) ->
    rx_data(R, Flags, Payload).

rx_data(#rx{acc = Acc, acc_size = Size, max_packet = Max} = R, Flags, Chunk) ->
    Size1 = Size + byte_size(Chunk),
    if
        Size1 > Max ->
            {error, packet_too_large};
        Flags band ?F_LAST =/= 0 ->
            {ok, {packet, lists:reverse([Chunk | Acc])}, R#rx{acc = [], acc_size = 0}};
        true ->
            {ok, none, R#rx{acc = [Chunk | Acc], acc_size = Size1}}
    end.

rx_rekey(R, _Len, Flags, Ev) when Flags band ?F_REKEY =/= 0 ->
    CS = enoise_cipher_state:rekey(R#rx.cs),
    {ok, Ev, R#rx{cs = CS, since = 0}};
rx_rekey(#rx{since = Since} = R, Len, _Flags, Ev) ->
    {ok, Ev, R#rx{since = Since + Len}}.

%% Raw deflate, hard output limit enforced while inflating: safeInflate/2
%% yields at most one fixed-size output buffer (16 KiB in OTP 27) per call and
%% we stop as soon as the running total passes 65518, so a deflate bomb is
%% never materialised.
inflate_raw(Data) ->
    Z = zlib:open(),
    try
        ok = zlib:inflateInit(Z, -15),
        inflate_loop(Z, zlib:safeInflate(Z, Data), 0, [])
    catch
        error:_ -> {error, bad_compression}
    after
        zlib:close(Z)
    end.

inflate_loop(Z, {Status, Out}, Size, Acc) ->
    OutSize = iolist_size(Out),
    Size1 = Size + OutSize,
    if
        Size1 > ?MAX_PAYLOAD ->
            {error, bad_compression};
        Status =:= finished ->
            %% `finished` only means the input is used up; inflateEnd/1 raises
            %% data_error unless the deflate stream itself was complete. (Bytes
            %% after the end of the stream are not detectable and ignored; the
            %% frame is authenticated, so this is not an attack surface.)
            ok = zlib:inflateEnd(Z),
            case iolist_to_binary(lists:reverse([Out | Acc])) of
                <<>> -> {error, bad_compression};
                Chunk -> {ok, Chunk}
            end;
        OutSize =:= 0 ->
            %% not finished and no progress: truncated stream
            {error, bad_compression};
        true ->
            inflate_loop(Z, zlib:safeInflate(Z, <<>>), Size1, [Out | Acc])
    end.
