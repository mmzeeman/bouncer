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
          {ok, suite(), 32} | {reject, 2} | {error, bad_hello_header}.
parse_hello_header(<<"BNCR", ?VERSION:8, SuiteId:8, Msg1Len:16>>, AcceptedIds) ->
    case SuiteId >= 1 andalso SuiteId =< 4 of
        false ->
            {reject, 2};
        true when not is_list(AcceptedIds) ->
            {error, bad_hello_header};
        true ->
            case lists:member(SuiteId, AcceptedIds) of
                false ->
                    {reject, 2};
                true when Msg1Len =:= ?MSG1_LENGTH ->
                    {ok, suite_atom(SuiteId), Msg1Len};
                true ->
                    {error, bad_hello_header}
            end
    end;
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
