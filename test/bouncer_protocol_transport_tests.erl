%% Tests for the TRANSPORT FRAMING section of bouncer_protocol, using real
%% enoise cipher states from a loopback handshake.
-module(bouncer_protocol_transport_tests).

-include_lib("eunit/include/eunit.hrl").

-define(P, bouncer_protocol).
-define(CHACHA, "Noise_XX_25519_ChaChaPoly_BLAKE2b").
-define(AESGCM, "Noise_XX_25519_AESGCM_SHA512").
-define(SUITES, [?CHACHA, ?AESGCM]).

-define(LAST, 1).
-define(TICK, 2).
-define(COMP, 4).
-define(PAD, 8).
-define(REKEY, 16).

%%% ------------------------------------------------------------------
%%% Helpers
%%% ------------------------------------------------------------------

%% Returns the transmit cipher state of the initiator and the receive cipher
%% state of the responder: a one directional channel.
handshake(Name) ->
    Opts = fun() -> [{noise, Name}, {s, enoise_keypair:new(dh25519)}] end,
    {ok, I} = enoise:handshake(Opts(), initiator),
    {ok, R} = enoise:handshake(Opts(), responder),
    hs_run(I, R).

hs_run(I, R) ->
    case {enoise_hs_state:next_message(I), enoise_hs_state:next_message(R)} of
        {out, in} ->
            {ok, send, Msg, I1} = enoise:step_handshake(I, {send, <<>>}),
            {ok, rcvd, _, R1} = enoise:step_handshake(R, {rcvd, Msg}),
            hs_run(I1, R1);
        {in, out} ->
            {ok, send, Msg, R1} = enoise:step_handshake(R, {send, <<>>}),
            {ok, rcvd, _, I1} = enoise:step_handshake(I, {rcvd, Msg}),
            hs_run(I1, R1);
        {done, done} ->
            {ok, done, #{tx := Tx}} = enoise:step_handshake(I, done),
            {ok, done, #{rx := Rx}} = enoise:step_handshake(R, done),
            {Tx, Rx}
    end.

pair(Name, SPolicy, RPolicy) ->
    {Tx, Rx} = handshake(Name),
    {new_sender(Tx, SPolicy), new_receiver(Rx, RPolicy)}.

bin(IoData) -> iolist_to_binary(IoData).

%% All frames of one packet.
send(S, Packet) ->
    send_loop(S, ?P:tx_packet(Packet), []).

send_loop(S, Pending, Acc) ->
    case ?P:tx_next(S, Pending) of
        {F, S1, more, P1} -> send_loop(S1, P1, [bin(F) | Acc]);
        {F, S1, done} -> {lists:reverse([bin(F) | Acc]), S1}
    end.

tick(S) ->
    {F, S1} = ?P:tx_tick(S),
    {bin(F), S1}.

feed(R, Bytes) ->
    {ok, Evs, R1} = ?P:rx_feed(R, Bytes),
    {events(Evs), R1}.

events(Evs) ->
    [case E of {packet, IO} -> {packet, bin(IO)}; tick -> tick end || E <- Evs].

%% Feed in random splits, collect all events.
feed_split(R, Bytes, Seed) ->
    _ = rand:seed(exsss, Seed),
    feed_split_loop(R, Bytes, []).

feed_split_loop(R, <<>>, Acc) ->
    {lists:append(lists:reverse(Acc)), R};
feed_split_loop(R, Bytes, Acc) ->
    N = min(byte_size(Bytes), rand:uniform(700)),
    <<Part:N/binary, Rest/binary>> = Bytes,
    {Evs, R1} = feed(R, Part),
    feed_split_loop(R1, Rest, [Evs | Acc]).

feed_bytewise(R, Bytes) ->
    lists:foldl(fun(B, {Acc, RAcc}) ->
                        {Evs, R1} = feed(RAcc, <<B>>),
                        {Acc ++ Evs, R1}
                end, {[], R}, binary_to_list(Bytes)).

%% Raw cipher state access (the proxy/crafting side of the tests).
raw_decrypt(CS, <<Len:16, Cipher/binary>>) when byte_size(Cipher) =:= Len ->
    case enoise_cipher_state:decrypt_with_ad(CS, <<Len:16>>, Cipher) of
        {ok, CS1, <<Flags, Rest/binary>>} -> {ok, CS1, Flags, Rest};
        {error, _} = E -> E
    end.

craft(CS, Flags, Rest) ->
    Plain = <<Flags, Rest/binary>>,
    Len = byte_size(Plain) + 16,
    {ok, CS1, Cipher} = enoise_cipher_state:encrypt_with_ad(CS, <<Len:16>>, Plain),
    {<<Len:16, Cipher/binary>>, CS1}.

%% Noise Rekey(): new key, same nonce counter.
raw_rekey(CS) ->
    enoise_cipher_state:rekey(CS).

%% Independent AEAD implementation on plain OTP crypto, to check enoise against.
-define(MAX_NONCE, 16#FFFFFFFFFFFFFFFF).

otp_cipher(?AESGCM) -> aes_256_gcm;
otp_cipher(?CHACHA) -> chacha20_poly1305.

otp_nonce(?AESGCM, N) -> <<0:32, N:64/big>>;
otp_nonce(?CHACHA, N) -> <<0:32, N:64/little>>.

otp_encrypt(Name, Key, N, AD, Plain) ->
    {C, T} = crypto:crypto_one_time_aead(otp_cipher(Name), Key, otp_nonce(Name, N),
                                         Plain, AD, 16, true),
    {C, T}.

otp_decrypt(Name, Key, N, AD, <<Len:16, Rest/binary>> = Frame) when byte_size(Rest) =:= Len ->
    _ = Frame,
    CLen = Len - 16,
    <<C:CLen/binary, T:16/binary>> = Rest,
    crypto:crypto_one_time_aead(otp_cipher(Name), Key, otp_nonce(Name, N), C, AD, T, false).

%% Noise Rekey(): first 32 bytes of ENCRYPT(k, 2^64-1, "", zeros(32)).
otp_rekey(Name, Key) ->
    {C, _Tag} = otp_encrypt(Name, Key, ?MAX_NONCE, <<>>, <<0:256>>),
    32 = byte_size(C),
    C.

%% Flags of every frame of a stream, following rekeys.
stream_flags(CS, <<>>) ->
    _ = CS,
    [];
stream_flags(CS, <<Len:16, _/binary>> = Stream) ->
    <<Frame:(Len + 2)/binary, Rest/binary>> = Stream,
    {ok, CS1, Flags, _} = raw_decrypt(CS, Frame),
    CS2 = case Flags band ?REKEY of 0 -> CS1; _ -> raw_rekey(CS1) end,
    [Flags | stream_flags(CS2, Rest)].

frame_lens(<<>>) -> [];
frame_lens(<<Len:16, _:Len/binary, Rest/binary>>) -> [Len | frame_lens(Rest)].

data(random, N) -> crypto:strong_rand_bytes(N);
data(compressible, N) -> binary:part(binary:copy(<<"the quick brown fox ">>, N div 20 + 1), 0, N).

deflate_raw(Data) ->
    Z = zlib:open(),
    ok = zlib:deflateInit(Z, default, deflated, -15, 8, default),
    Out = bin(zlib:deflate(Z, Data, finish)),
    ok = zlib:deflateEnd(Z),
    zlib:close(Z),
    Out.

%%% ------------------------------------------------------------------
%%% enoise facts the section relies on
%%% ------------------------------------------------------------------

enoise_rekey_matches_noise_spec_test_() ->
    [{Name, fun() ->
        {Tx, _} = handshake(Name),
        Key = enoise_cipher_state:key(Tx),
        Expected = otp_rekey(Name, Key),
        Rekeyed = enoise_cipher_state:rekey(Tx),
        ?assertEqual(32, byte_size(enoise_cipher_state:key(Rekeyed))),
        ?assertEqual(Expected, enoise_cipher_state:key(Rekeyed)),
        %% the nonce counter continues: after 3 frames the next one uses nonce 3
        {_, Tx3} = lists:foldl(fun(_, {_, CS}) ->
                                       {ok, CS1, C} = enoise_cipher_state:encrypt_with_ad(CS, <<>>, <<"x">>),
                                       {C, CS1}
                               end, {none, Tx}, lists:seq(1, 3)),
        {ok, _, Cipher} = enoise_cipher_state:encrypt_with_ad(enoise_cipher_state:rekey(Tx3), <<>>, <<"y">>),
        {C3, T3} = otp_encrypt(Name, Expected, 3, <<>>, <<"y">>),
        ?assertEqual(<<C3/binary, T3/binary>>, Cipher)
    end} || Name <- ?SUITES].

zlib_is_not_port_based_test() ->
    Z = zlib:open(),
    ?assert(is_reference(Z)),
    zlib:close(Z).

%%% ------------------------------------------------------------------
%%% Round trips
%%% ------------------------------------------------------------------

empty_packet_is_invalid_test() ->
    {S, _} = pair(?AESGCM, #{}, #{}),
    ?assertError(badarg, ?P:tx_packet(<<>>)),
    ?assertError(badarg, ?P:tx_packet([<<>>, []])),
    _ = S.

roundtrip_sizes_test_() ->
    Sizes = [1, 16384, 65518, 65519, 65520, 1000000, 10000000],
    [{timeout, 120, {lists:flatten(io_lib:format("~s ~p bytes", [Name, N])), fun() ->
        {S, R} = pair(Name, #{}, #{}),
        Packet = data(random, N),
        {Frames, _} = send(S, Packet),
        {Evs, _} = feed(R, bin(Frames)),
        ?assertEqual([{packet, Packet}], Evs)
    end}} || Name <- ?SUITES, N <- Sizes].

roundtrip_iodata_test() ->
    {S, R} = pair(?AESGCM, #{}, #{}),
    {Frames, _} = send(S, [<<"he">>, [<<"llo">>, $ ], "world"]),
    ?assertEqual([{packet, <<"hello world">>}], element(1, feed(R, bin(Frames)))).

multiframe_iodata_test_() ->
    Packets = [[<<>>, [1, 2, <<3, 4, 5>>], <<>>, [6 | <<7, 8, 9>>]],
               [<<"abcdefgh">>, <<>>, <<"ijklmnop">>, <<"q">>],
               [binary:copy(<<42>>, 32), [], [<<1>>, binary:copy(<<43>>, 33)]],
               [binary:copy(<<10>>, 8) | binary:copy(<<11>>, 40)]],
    [fun() ->
        {S, R} = pair(Name, #{chunk_size => 8, compression => Compression},
                      #{accept_compression => true}),
        Expected = bin(Packet),
        {Frames, _} = send(S, Packet),
        ?assertEqual((byte_size(Expected) + 7) div 8, length(Frames)),
        ?assertEqual([{packet, Expected}], element(1, feed(R, bin(Frames))))
     end || Name <- ?SUITES, Compression <- [none, {zlib, 0}], Packet <- Packets].

iodata_tick_between_chunks_test() ->
    {S, R} = pair(?AESGCM, #{chunk_size => 8}, #{}),
    Packet = [<<"abc">>, [<<"defghijk">> | <<"lmnop">>], <<"qrstuv">>],
    {First, S1, more, Pending} = ?P:tx_next(S, ?P:tx_packet(Packet)),
    {Tick, S2} = tick(S1),
    {Rest, _} = send_loop(S2, Pending, []),
    ?assertEqual([tick, {packet, bin(Packet)}],
                 element(1, feed(R, bin([First, Tick, Rest])))).

compressed_multiframe_iodata_test() ->
    {Tx, Rx} = handshake(?AESGCM),
    S = new_sender(Tx, #{chunk_size => 256, compression => {zlib, 0}}),
    R = new_receiver(Rx, #{accept_compression => true}),
    Packet = [binary:copy(<<"a">>, 300), [binary:copy(<<"b">>, 300)]],
    {Frames, _} = send(S, Packet),
    Wire = bin(Frames),
    ?assert(lists:all(fun(Flags) -> Flags band ?COMP =/= 0 end,
                      stream_flags(Tx, Wire))),
    ?assertEqual([{packet, bin(Packet)}], element(1, feed(R, Wire))).

roundtrip_chunk_size_extremes_test_() ->
    [{lists:flatten(io_lib:format("chunk ~p size ~p", [C, N])), fun() ->
        {S, R} = pair(?CHACHA, #{chunk_size => C}, #{}),
        Packet = data(random, N),
        {Frames, _} = send(S, Packet),
        {Evs, _} = feed(R, bin(Frames)),
        ?assertEqual([{packet, Packet}], Evs)
    end} || {C, N} <- [{1, 1}, {1, 50}, {2, 3}, {65518, 65518}, {65518, 65519}, {65518, 200000}]].

chunk_size_and_last_flag_test_() ->
    [fun() ->
        {Tx, _} = handshake(Name),
        S = new_sender(Tx, #{chunk_size => 1000}),
        {Frames, _} = send(S, data(random, 4500)),
        ?assertEqual(5, length(Frames)),
        Flags = stream_flags(Tx, bin(Frames)),
        ?assertEqual([0, 0, 0, 0, ?LAST], Flags),
        ?assertEqual([1017, 1017, 1017, 1017, 517], frame_lens(bin(Frames)))
    end || Name <- ?SUITES].

default_chunk_size_is_16384_test() ->
    {Tx, _} = handshake(?AESGCM),
    S = new_sender(Tx, #{}),
    {Frames, _} = send(S, data(random, 16385)),
    ?assertEqual([16384 + 17, 1 + 17], frame_lens(bin(Frames))).

single_chunk_packet_has_last_test() ->
    {Tx, _} = handshake(?AESGCM),
    {Frames, _} = send(new_sender(Tx, #{}), <<"x">>),
    ?assertEqual([?LAST], stream_flags(Tx, bin(Frames))).

%%% ------------------------------------------------------------------
%%% Partial reads, several frames, ticks
%%% ------------------------------------------------------------------

byte_by_byte_test_() ->
    [fun() ->
        {S, R} = pair(Name, #{chunk_size => 700}, #{}),
        P1 = data(random, 2000),
        P2 = data(random, 1),
        {F1, S1} = send(S, P1),
        {T, S2} = tick(S1),
        {F2, _} = send(S2, P2),
        {Evs, _} = feed_bytewise(R, bin([F1, T, F2])),
        ?assertEqual([{packet, P1}, tick, {packet, P2}], Evs)
    end || Name <- ?SUITES].

random_splits_test_() ->
    [fun() ->
        {S, R} = pair(?AESGCM, #{chunk_size => 1500}, #{}),
        Packets = [data(random, N) || N <- [10, 3000, 1500, 1501, 7777]],
        {Wire, _} = lists:foldl(fun(P, {Acc, SAcc}) ->
                                        {Fs, S1} = send(SAcc, P),
                                        {[Acc, Fs], S1}
                                end, {[], S}, Packets),
        {Evs, _} = feed_split(R, bin(Wire), {Seed, 2, 3}),
        ?assertEqual([{packet, P} || P <- Packets], Evs)
    end || Seed <- lists:seq(1, 25)].

several_frames_one_buffer_with_ticks_test() ->
    {S, R} = pair(?AESGCM, #{chunk_size => 100}, #{}),
    {A, S1} = send(S, data(random, 250)),
    {T1, S2} = tick(S1),
    {T2, S3} = tick(S2),
    {B, _} = send(S3, <<"b">>),
    {Evs, _} = feed(R, bin([A, T1, T2, B])),
    ?assertMatch([{packet, _}, tick, tick, {packet, <<"b">>}], Evs).

tick_between_chunks_of_one_packet_test() ->
    {S, R} = pair(?AESGCM, #{chunk_size => 100}, #{}),
    Packet = data(random, 250),
    P0 = ?P:tx_packet(Packet),
    {F1, S1, more, P1} = ?P:tx_next(S, P0),
    {T, S2} = ?P:tx_tick(S1),
    {F2, S3, more, P2} = ?P:tx_next(S2, P1),
    {F3, _, done} = ?P:tx_next(S3, P2),
    {Evs, _} = feed(R, bin([F1, T, F2, F3])),
    ?assertEqual([tick, {packet, Packet}], Evs).

feed_empty_binary_test() ->
    {_, R} = pair(?AESGCM, #{}, #{}),
    ?assertMatch({ok, [], _}, ?P:rx_feed(R, <<>>)).

%%% ------------------------------------------------------------------
%%% Ticks and malformed flags
%%% ------------------------------------------------------------------

tick_roundtrip_test_() ->
    [fun() ->
        {S, R} = pair(Name, #{}, #{}),
        {T, S1} = tick(S),
        {T2, _} = tick(S1),
        ?assertEqual(17 + 2, byte_size(T)),
        {Evs, _} = feed(R, <<T/binary, T2/binary>>),
        ?assertEqual([tick, tick], Evs)
    end || Name <- ?SUITES].

tick_with_payload_test() ->
    {Tx, Rx} = handshake(?AESGCM),
    {F, _} = craft(Tx, ?TICK, <<"x">>),
    ?assertMatch({error, tick_with_payload, _},
                 ?P:rx_feed(new_receiver(Rx, #{}), F)).

tick_with_comp_or_last_flag_test_() ->
    [fun() ->
        {Tx, Rx} = handshake(?AESGCM),
        {F, _} = craft(Tx, Flag bor ?TICK, <<>>),
        ?assertMatch({error, tick_with_payload, _},
                     ?P:rx_feed(new_receiver(Rx, #{accept_compression => true}), F))
    end || Flag <- [?COMP, ?LAST, ?COMP bor ?LAST]].

tick_with_rekey_flag_is_fine_test() ->
    {Tx, Rx} = handshake(?AESGCM),
    {F, Tx1} = craft(Tx, ?TICK bor ?REKEY, <<>>),
    {F2, _} = craft(raw_rekey(Tx1), ?LAST, <<"after">>),
    ?assertEqual([tick, {packet, <<"after">>}],
                 element(1, feed(new_receiver(Rx, #{}), <<F/binary, F2/binary>>))).

reserved_bits_test_() ->
    [{lists:flatten(io_lib:format("bit ~p", [Bit])), fun() ->
        {Tx, Rx} = handshake(?AESGCM),
        {F, _} = craft(Tx, ?LAST bor (1 bsl Bit), <<"data">>),
        ?assertMatch({error, reserved_flags, _}, ?P:rx_feed(new_receiver(Rx, #{}), F))
    end} || Bit <- [5, 6, 7]].

data_frame_without_payload_test() ->
    {Tx, Rx} = handshake(?AESGCM),
    {F, _} = craft(Tx, ?LAST, <<>>),
    ?assertMatch({error, bad_length, _}, ?P:rx_feed(new_receiver(Rx, #{}), F)).

cipher_length_below_17_test() ->
    {_, Rx} = handshake(?AESGCM),
    R = new_receiver(Rx, #{}),
    ?assertMatch({error, bad_length, _}, ?P:rx_feed(R, <<16:16>>)),
    ?assertMatch({error, bad_length, _}, ?P:rx_feed(R, <<0:16, 1, 2, 3>>)),
    ?assertMatch({ok, [], _}, ?P:rx_feed(R, <<17:16>>)),
    ?assertMatch({ok, [], _}, ?P:rx_feed(R, <<65535:16>>)).

%%% ------------------------------------------------------------------
%%% Padding
%%% ------------------------------------------------------------------

padding_bucket_test_() ->
    [fun() ->
        {S, R} = pair(Name, #{padding => {bucket, 512}, chunk_size => 2000}, #{}),
        Sizes = [1, 2, 100, 509, 510, 511, 2000, 2001, 5000],
        {Wire, S1, Packets} = lists:foldl(fun(N, {W, SAcc, Ps}) ->
                                                   P = data(random, N),
                                                   {Fs, S1} = send(SAcc, P),
                                                   {[W, Fs], S1, [P | Ps]}
                                           end, {[], S, []}, Sizes),
        {T, _} = tick(S1),
        WireBin = bin([Wire, T]),
        [?assertEqual(0, (L - 16) rem 512) || L <- frame_lens(WireBin)],
        {Evs, _} = feed(R, WireBin),
        ?assertEqual([{packet, P} || P <- lists:reverse(Packets)] ++ [tick], Evs)
    end || Name <- ?SUITES].

padding_bucket_exact_lengths_test() ->
    {S, _} = pair(?AESGCM, #{padding => {bucket, 512}}, #{}),
    %% plaintext = 1 flags + 2 padlen + payload, rounded to 512
    {F1, S1} = send(S, data(random, 509)),
    {F2, S2} = send(S1, data(random, 510)),
    {T, _} = tick(S2),
    ?assertEqual([512 + 16, 1024 + 16], frame_lens(bin([F1, F2]))),
    ?assertEqual([512 + 16], frame_lens(T)).

padding_fixed_test_() ->
    [fun() ->
        {S, R} = pair(Name, #{padding => {fixed, 4096}, chunk_size => 16384}, #{}),
        Sizes = [1, 100, 4092, 4093, 4094, 10000, 30000],
        {Wire, S1, Packets} = lists:foldl(fun(N, {W, SAcc, Ps}) ->
                                                   P = data(random, N),
                                                   {Fs, S1} = send(SAcc, P),
                                                   {[W, Fs], S1, [P | Ps]}
                                           end, {[], S, []}, Sizes),
        {T, _} = tick(S1),
        WireBin = bin([Wire, T]),
        ?assertEqual([4096 + 16], lists:usort(frame_lens(WireBin))),
        {Evs, _} = feed(R, WireBin),
        ?assertEqual([{packet, P} || P <- lists:reverse(Packets)] ++ [tick], Evs)
    end || Name <- ?SUITES].

padding_fixed_small_and_large_n_test_() ->
    [{lists:flatten(io_lib:format("fixed ~p", [N])), fun() ->
        {S, R} = pair(?AESGCM, #{padding => {fixed, N}}, #{}),
        Packet = data(random, 1000),
        {Fs, S1} = send(S, Packet),
        {T, _} = tick(S1),
        ?assertEqual([N + 16], lists:usort(frame_lens(bin([Fs, T])))),
        ?assertEqual([{packet, Packet}, tick], element(1, feed(R, bin([Fs, T]))))
    end} || N <- [4, 5, 64, 65519]].

padding_bucket_large_n_test_() ->
    [{lists:flatten(io_lib:format("bucket ~p", [N])), fun() ->
        {S, R} = pair(?AESGCM, #{padding => {bucket, N}}, #{}),
        Packet = data(random, 70000),
        {Fs, S1} = send(S, Packet),
        {T, _} = tick(S1),
        [?assertEqual(0, (L - 16) rem N) || L <- frame_lens(bin([Fs, T]))],
        [?assert(L - 16 =< 65519) || L <- frame_lens(bin([Fs, T]))],
        ?assertEqual([{packet, Packet}, tick], element(1, feed(R, bin([Fs, T]))))
    end} || N <- [1, 3, 4, 1000, 32760, 40000, 65519]].

padded_frames_always_accepted_test() ->
    {Tx, Rx} = handshake(?AESGCM),
    {F, _} = craft(Tx, ?LAST bor ?PAD, <<5:16, "hello", 0, 0, 0, 0, 0>>),
    ?assertMatch({ok, [{packet, _}], _}, ?P:rx_feed(new_receiver(Rx, #{}), F)).

bad_padding_test_() ->
    Cases = [{"PadLen larger than body", ?LAST bor ?PAD, <<6:16, "hello">>},
             {"PadLen = body + 1", ?LAST bor ?PAD, <<1:16>>},
             {"no PadLen", ?LAST bor ?PAD, <<7>>},
             {"empty rest", ?LAST bor ?PAD, <<>>},
             {"nonzero padding", ?LAST bor ?PAD, <<2:16, "hi", 0, 1>>},
             {"padded tick with payload", ?TICK bor ?PAD, <<1:16, "x", 0>>}],
    [{Title, fun() ->
        {Tx, Rx} = handshake(?AESGCM),
        {F, _} = craft(Tx, Flags, Rest),
        Expected = case Title of "padded tick with payload" -> tick_with_payload; _ -> bad_padding end,
        {error, Reason, _} = ?P:rx_feed(new_receiver(Rx, #{}), F),
        ?assertEqual(Expected, Reason)
    end} || {Title, Flags, Rest} <- Cases].

padded_frame_whose_padding_fills_everything_test() ->
    {Tx, Rx} = handshake(?AESGCM),
    {F, _} = craft(Tx, ?TICK bor ?PAD, <<65516:16, 0:(65516 * 8)>>),
    ?assertEqual(65535 + 2, byte_size(F)),
    ?assertMatch({ok, [tick], _}, ?P:rx_feed(new_receiver(Rx, #{}), F)).

max_unpadded_payload_test() ->
    {Tx, Rx} = handshake(?AESGCM),
    Payload = data(random, 65518),
    {F, _} = craft(Tx, ?LAST, Payload),
    ?assertEqual(65535 + 2, byte_size(F)),
    ?assertMatch({ok, [{packet, _}], _}, ?P:rx_feed(new_receiver(Rx, #{}), F)).

%%% ------------------------------------------------------------------
%%% Compression
%%% ------------------------------------------------------------------

compression_sets_flag_and_shrinks_test_() ->
    [fun() ->
        {Tx, Rx} = handshake(Name),
        S = new_sender(Tx, #{compression => {zlib, 256}}),
        R = new_receiver(Rx, #{accept_compression => true}),
        Packet = data(compressible, 16384),
        {Frames, _} = send(S, Packet),
        [Frame] = Frames,
        ?assertEqual([?LAST bor ?COMP], stream_flags(Tx, Frame)),
        ?assert(byte_size(Frame) < 16384 div 4),
        ?assertEqual([{packet, Packet}], element(1, feed(R, Frame)))
    end || Name <- ?SUITES].

incompressible_is_sent_plain_test() ->
    {Tx, Rx} = handshake(?AESGCM),
    S = new_sender(Tx, #{compression => {zlib, 1}}),
    Packet = data(random, 16384),
    {[Frame], _} = send(S, Packet),
    ?assertEqual([?LAST], stream_flags(Tx, Frame)),
    ?assertEqual(16384 + 1 + 16 + 2, byte_size(Frame)),
    ?assertEqual([{packet, Packet}],
                 element(1, feed(new_receiver(Rx, #{accept_compression => true}), Frame))).

min_size_is_respected_test() ->
    {Tx, _} = handshake(?AESGCM),
    S = new_sender(Tx, #{compression => {zlib, 256}, chunk_size => 1000}),
    {F255, S1} = send(S, data(compressible, 255)),
    {F256, S2} = send(S1, data(compressible, 256)),
    {F2100, _} = send(S2, data(compressible, 2100)),
    %% 255 is below the minimum, 256 is not; 2100 = 1000 + 1000 + 100 where
    %% the short last chunk is below the minimum.
    ?assertEqual([?LAST, ?LAST bor ?COMP, ?COMP, ?COMP, ?LAST],
                 stream_flags(Tx, bin([F255, F256, F2100]))).

short_last_chunk_below_min_is_plain_test() ->
    {Tx, _} = handshake(?AESGCM),
    S = new_sender(Tx, #{compression => {zlib, 256}, chunk_size => 1000}),
    {Frames, _} = send(S, data(compressible, 2100)),
    ?assertEqual([?COMP, ?COMP, ?LAST], stream_flags(Tx, bin(Frames))).

compression_not_accepted_test() ->
    {Tx, Rx} = handshake(?AESGCM),
    S = new_sender(Tx, #{compression => {zlib, 1}}),
    {[Frame], _} = send(S, data(compressible, 4000)),
    ?assertMatch({error, compression_not_accepted, _},
                 ?P:rx_feed(new_receiver(Rx, #{}), Frame)),
    ?assertMatch({error, compression_not_accepted, _},
                 ?P:rx_feed(new_receiver(Rx, #{accept_compression => false}), Frame)),
    ?assertMatch({ok, [{packet, _}], _},
                 ?P:rx_feed(new_receiver(Rx, #{accept_compression => true}), Frame)).

compressed_with_default_receiver_ok_when_plain_test() ->
    {S, R} = pair(?AESGCM, #{compression => {zlib, 1}}, #{}),
    {Frames, _} = send(S, data(random, 100)),
    ?assertMatch({[{packet, _}], _}, feed(R, bin(Frames))).

inflate_exactly_at_limit_is_accepted_test() ->
    {Tx, Rx} = handshake(?AESGCM),
    Chunk = binary:copy(<<0>>, 65518),
    {F, _} = craft(Tx, ?LAST bor ?COMP, deflate_raw(Chunk)),
    ?assertEqual({[{packet, Chunk}], ok},
                 setelement(2, feed(new_receiver(Rx, #{accept_compression => true}), F), ok)).

inflate_over_limit_is_bad_compression_test() ->
    {Tx, Rx} = handshake(?AESGCM),
    {F, _} = craft(Tx, ?LAST bor ?COMP, deflate_raw(binary:copy(<<0>>, 65519))),
    ?assertMatch({error, bad_compression, _},
                 ?P:rx_feed(new_receiver(Rx, #{accept_compression => true}), F)).

bad_deflate_data_test_() ->
    Cases = [{"garbage", crypto:strong_rand_bytes(100)},
             {"one zero byte", <<0>>},
             {"zlib header (not raw)", zlib:compress(<<"hello hello hello hello">>)}],
    [{Title, {timeout, 10, fun() ->
        {Tx, Rx} = handshake(?AESGCM),
        {F, _} = craft(Tx, ?LAST bor ?COMP, Payload),
        R = new_receiver(Rx, #{accept_compression => true}),
        ?assertMatch({error, bad_compression, _}, ?P:rx_feed(R, F))
    end}} || {Title, Payload} <- Cases].

% Disabled, because nodes are trusted anyway, they can also send arbitrary commands
%inflate_bomb_memory_stays_bounded_test_() ->
%    {timeout, 120, fun() ->
%        Bomb = deflate_raw(binary:copy(<<0>>, 32 * 1024 * 1024)),
%        ?assert(byte_size(Bomb) < 65000),
%        {Tx, Rx} = handshake(?AESGCM),
%        {F, _} = craft(Tx, ?LAST bor ?COMP, Bomb),
%        R = new_receiver(Rx, #{accept_compression => true}),
%        Control = fun() ->
%                          Z = zlib:open(),
%                          ok = zlib:inflateInit(Z, -15),
%                          Out = bin(zlib:inflate(Z, Bomb)),
%                          zlib:close(Z),
%                          byte_size(Out)
%                  end,
%        {ControlPeak, ControlSize} = peak_binary_memory(Control),
%        ?assertEqual(32 * 1024 * 1024, ControlSize),
%        ?assert(ControlPeak > 16 * 1024 * 1024),
%        {Peak, Result} = peak_binary_memory(fun() -> ?P:rx_feed(R, F) end),
%        ?assertMatch({error, bad_compression, _}, Result),
%        ?assert(Peak < 4 * 1024 * 1024)
%    end}.

%% Peak growth of the VM-wide binary memory while running Fun.
%peak_binary_memory(Fun) ->
%    erlang:garbage_collect(),
%    Base = erlang:memory(binary),
%    Parent = self(),
%    Ref = make_ref(),
%    Sampler = spawn_link(fun() -> sample_loop(Base, Parent, Ref) end),
%    Result = Fun(),
%    Final = erlang:memory(binary),
%    Sampler ! {stop, Ref},
%    receive {peak, Ref, Peak} -> {max(Peak, Final) - Base, Result} end.

%sample_loop(Peak, Parent, Ref) ->
%    receive
%        {stop, Ref} -> Parent ! {peak, Ref, Peak}
%    after 0 ->
%        sample_loop(max(Peak, erlang:memory(binary)), Parent, Ref)
%    end.

%%% ------------------------------------------------------------------
%%% Rekey
%%% ------------------------------------------------------------------

rekey_stays_in_sync_over_10_rekeys_test_() ->
    [fun() ->
        {Tx, Rx} = handshake(Name),
        S = new_sender(Tx, #{rekey_after => [{frames, 3}], chunk_size => 100}),
        R = new_receiver(Rx, #{}),
        Packets = [data(random, 250) || _ <- lists:seq(1, 12)],
        {Wire, S1} = lists:foldl(fun(P, {W, SAcc}) ->
                                         {Fs, S1} = send(SAcc, P),
                                         {T, S2} = tick(S1),
                                         {[W, Fs, T], S2}
                                 end, {[], S}, Packets),
        _ = S1,
        WireBin = bin(Wire),
        Flags = stream_flags(Tx, WireBin),
        ?assertEqual(48, length(Flags)),
        ?assertEqual(16, length([F || F <- Flags, F band ?REKEY =/= 0])),
        {Evs, R1} = feed(R, WireBin),
        ?assertEqual(lists:append([[{packet, P}, tick] || P <- Packets]), Evs),
        %% and keep going afterwards
        {More, _} = send(S1, <<"still in sync">>),
        ?assertEqual([{packet, <<"still in sync">>}], element(1, feed(R1, bin(More))))
    end || Name <- ?SUITES].

rekey_continues_nonce_and_matches_otp_crypto_test_() ->
    [{Name, fun() ->
        {Tx, _} = handshake(Name),
        K = enoise_cipher_state:key(Tx),
        K2 = otp_rekey(Name, K),
        ?assertEqual(32, byte_size(K2)),
        ?assertNotEqual(K, K2),
        Total = 5,
        S = new_sender(Tx, #{rekey_after => [{frames, 3}]}),
        {Frames, _} = lists:foldl(fun(I, {Acc, SAcc}) ->
                                          {[F], S1} = send(SAcc, <<"packet-", (integer_to_binary(I))/binary>>),
                                          {Acc ++ [F], S1}
                                  end, {[], S}, lists:seq(1, Total)),
        lists:foreach(fun({I, <<Len:16, _/binary>> = F}) ->
            N = I - 1,
            Key = case I =< 3 of true -> K; false -> K2 end,
            {Flags, Rest} = case otp_decrypt(Name, Key, N, <<Len:16>>, F) of
                                <<Fl, R/binary>> -> {Fl, R};
                                Other -> erlang:error({decrypt_failed, I, Other})
                            end,
            ?assertEqual(<<"packet-", (integer_to_binary(I))/binary>>, Rest),
            ?assertEqual(case I of 3 -> ?LAST bor ?REKEY; _ -> ?LAST end, Flags)
        end, lists:zip(lists:seq(1, Total), Frames)),
        %% a nonce reset to 0 (or the old key) must not decrypt the frames after the rekey
        <<L4:16, _/binary>> = F4 = lists:nth(4, Frames),
        ?assertEqual(error, otp_decrypt(Name, K2, 0, <<L4:16>>, F4)),
        ?assertEqual(error, otp_decrypt(Name, K, 3, <<L4:16>>, F4))
    end} || Name <- ?SUITES].

rekey_frame_uses_old_key_and_next_needs_new_key_test_() ->
    [{Name, fun() ->
        {Tx, _} = handshake(Name),
        S = new_sender(Tx, #{rekey_after => [{frames, 1}]}),
        {[F1], S1} = send(S, <<"one">>),
        {[F2], _} = send(S1, <<"two">>),
        {ok, Old, Flags, _} = raw_decrypt(Tx, F1),
        ?assertEqual(?LAST bor ?REKEY, Flags),
        %% Old key, correct nonce: must fail.
        ?assertEqual({error, decrypt_failed}, raw_decrypt(Old, F2)),
        ?assertMatch({ok, _, ?LAST bor ?REKEY, <<"two">>}, raw_decrypt(raw_rekey(Old), F2))
    end} || Name <- ?SUITES].

rekey_flag_stripped_by_proxy_test_() ->
    [fun() ->
        {Tx, Rx} = handshake(Name),
        S = new_sender(Tx, #{rekey_after => [{frames, 1}]}),
        R = new_receiver(Rx, #{}),
        {[F1], S1} = send(S, <<"one">>),
        {[F2], _} = send(S1, <<"two">>),
        {ok, _, Flags, Rest} = raw_decrypt(Tx, F1),
        {Stripped, _} = craft(Tx, Flags band (bnot ?REKEY), Rest),
        {[{packet, <<"one">>}], R1} = feed(R, Stripped),
        ?assertMatch({error, decrypt_failed, _}, ?P:rx_feed(R1, F2))
    end || Name <- ?SUITES].

rekey_required_when_peer_never_rekeys_test() ->
    {S, R} = pair(?AESGCM, #{rekey_after => never}, #{max_bytes_without_rekey => 1000}),
    {F1, S1} = send(S, data(random, 500)),
    {F2, _} = send(S1, data(random, 500)),
    {ok, [{packet, _}], R1} = ?P:rx_feed(R, bin(F1)),
    ?assertMatch({error, rekey_required, _}, ?P:rx_feed(R1, bin(F2))).

max_bytes_without_rekey_met_by_rekeying_sender_test() ->
    {S, R} = pair(?AESGCM, #{rekey_after => [{bytes, 300}], chunk_size => 100},
                  #{max_bytes_without_rekey => 1000}),
    Packets = [data(random, 250) || _ <- lists:seq(1, 40)],
    {Wire, _} = lists:foldl(fun(P, {W, SAcc}) ->
                                    {Fs, S1} = send(SAcc, P),
                                    {[W, Fs], S1}
                            end, {[], S}, Packets),
    {Evs, _} = feed(R, bin(Wire)),
    ?assertEqual([{packet, P} || P <- Packets], Evs).

rekey_frames_limit_test() ->
    {Tx, _} = handshake(?AESGCM),
    S = new_sender(Tx, #{rekey_after => [{frames, 3}], chunk_size => 10}),
    {Wire, _} = send(S, data(random, 100)),
    Flags = stream_flags(Tx, bin(Wire)),
    ?assertEqual(10, length(Flags)),
    Expected = [(case I rem 3 of 0 -> ?REKEY; _ -> 0 end) bor (case I of 10 -> ?LAST; _ -> 0 end)
                || I <- lists:seq(1, 10)],
    ?assertEqual(Expected, Flags).

rekey_bytes_limit_test() ->
    {Tx, _} = handshake(?AESGCM),
    %% every tick frame is 17 bytes of ciphertext
    S = new_sender(Tx, #{rekey_after => [{bytes, 17 * 4}]}),
    {Wire, _} = lists:foldl(fun(_, {W, SAcc}) ->
                                    {T, S1} = tick(SAcc),
                                    {[W, T], S1}
                            end, {[], S}, lists:seq(1, 10)),
    Flags = stream_flags(Tx, bin(Wire)),
    ?assertEqual([4, 8], [I || {I, F} <- lists:zip(lists:seq(1, 10), Flags), F band ?REKEY =/= 0]).

rekey_ms_limit_with_injected_clock_test() ->
    {Tx, Rx} = handshake(?AESGCM),
    put(test_clock, 0),
    Clock = fun() -> get(test_clock) end,
    S0 = new_sender(Tx, #{rekey_after => [{ms, 1000}], clock => Clock}),
    R0 = new_receiver(Rx, #{}),
    Times = [0, 500, 999, 1000, 1500, 1999, 2000, 2001],
    {Wire, _} = lists:foldl(fun(T, {W, SAcc}) ->
                                    put(test_clock, T),
                                    {Tk, S1} = tick(SAcc),
                                    {[W, Tk], S1}
                            end, {[], S0}, Times),
    WireBin = bin(Wire),
    Flags = stream_flags(Tx, WireBin),
    ?assertEqual([4, 7], [I || {I, F} <- lists:zip(lists:seq(1, 8), Flags), F band ?REKEY =/= 0]),
    ?assertEqual(lists:duplicate(8, tick), element(1, feed(R0, WireBin))),
    erase(test_clock).

rekey_any_limit_triggers_test() ->
    {Tx, _} = handshake(?AESGCM),
    S = new_sender(Tx, #{rekey_after => [{frames, 100}, {bytes, 17 * 2}, {ms, 100000}]}),
    {A, S1} = tick(S),
    {B, _} = tick(S1),
    ?assertEqual([?TICK, ?TICK bor ?REKEY], stream_flags(Tx, bin([A, B]))).

default_rekey_after_is_one_gib_test() ->
    {ok, #{rekey_after := RekeyAfter}} = ?P:sender_policy(#{}),
    ?assertEqual([{bytes, 1073741824}], RekeyAfter).

rekey_never_test() ->
    {Tx, _} = handshake(?AESGCM),
    S = new_sender(Tx, #{rekey_after => never, chunk_size => 10}),
    {Wire, _} = send(S, data(random, 1000)),
    ?assertEqual([0], lists:usort([F band ?REKEY || F <- stream_flags(Tx, bin(Wire))])).

%%% ------------------------------------------------------------------
%%% max_packet
%%% ------------------------------------------------------------------

max_packet_test() ->
    Run = fun(N) ->
                  {S, R} = pair(?AESGCM, #{}, #{max_packet => 100000}),
                  {Frames, _} = send(S, data(random, N)),
                  ?P:rx_feed(R, bin(Frames))
          end,
    ?assertMatch({ok, [{packet, _}], _}, Run(99999)),
    ?assertMatch({ok, [{packet, _}], _}, Run(100000)),
    ?assertMatch({error, packet_too_large, _}, Run(100001)).

max_packet_checked_while_reassembling_test() ->
    {S, R} = pair(?AESGCM, #{chunk_size => 10000}, #{max_packet => 50000}),
    {Frames, _} = send(S, data(random, 1000000)),
    ?assertEqual(100, length(Frames)),
    {Fed, Result} = feed_frames_until_error(R, Frames, 0),
    ?assertMatch({error, packet_too_large, _}, Result),
    %% 5 chunks of 10000 fit, the 6th crosses the limit
    ?assertEqual(6, Fed).

feed_frames_until_error(_, [], N) ->
    {N, done};
feed_frames_until_error(R, [F | Rest], N) ->
    case ?P:rx_feed(R, F) of
        {ok, [], R1} -> feed_frames_until_error(R1, Rest, N + 1);
        {error, _, _} = E -> {N + 1, E}
    end.

max_packet_counts_inflated_size_test() ->
    {S, R} = pair(?AESGCM, #{compression => {zlib, 1}, chunk_size => 16384},
                  #{max_packet => 40000, accept_compression => true}),
    {Frames, _} = send(S, data(compressible, 100000)),
    ?assert(lists:sum([byte_size(F) || F <- Frames]) < 40000),
    ?assertMatch({error, packet_too_large, _}, ?P:rx_feed(R, bin(Frames))).

max_packet_is_per_packet_test() ->
    {S, R} = pair(?AESGCM, #{}, #{max_packet => 30000}),
    Packets = [data(random, 30000) || _ <- lists:seq(1, 5)],
    {Wire, _} = lists:foldl(fun(P, {W, SAcc}) -> {Fs, S1} = send(SAcc, P), {[W, Fs], S1} end,
                            {[], S}, Packets),
    ?assertEqual([{packet, P} || P <- Packets], element(1, feed(R, bin(Wire)))).

%%% ------------------------------------------------------------------
%%% Tampering
%%% ------------------------------------------------------------------

flip(Bin, Pos) ->
    <<Pre:Pos/binary, B, Post/binary>> = Bin,
    <<Pre/binary, (B bxor 1), Post/binary>>.

stream_for_tamper(Name) ->
    {S, R} = pair(Name, #{chunk_size => 200}, #{}),
    {Frames, S1} = send(S, data(random, 1000)),
    {Frames2, _} = send(S1, data(random, 1000)),
    {bin([Frames, Frames2]), R}.

tamper_ciphertext_test_() ->
    [{lists:flatten(io_lib:format("~s byte ~p", [Name, Pos])), fun() ->
        {Stream, R} = stream_for_tamper(Name),
        {error, Reason, Dead} = ?P:rx_feed(R, flip(Stream, Pos)),
        ?assertEqual(decrypt_failed, Reason),
        {error, decrypt_failed, _} = ?P:rx_feed(Dead, <<>>),
        {error, decrypt_failed, _} = ?P:rx_feed(Dead, Stream)
    end} || Name <- ?SUITES, Pos <- [2, 3, 100, 216, 217]].

tamper_length_prefix_test_() ->
    [{lists:flatten(io_lib:format("~s ~p", [Name, Pos])), fun() ->
        {Stream, R} = stream_for_tamper(Name),
        {error, Reason, Dead} = ?P:rx_feed(R, flip(Stream, Pos)),
        ?assert(lists:member(Reason, [decrypt_failed, bad_length])),
        {error, Reason, _} = ?P:rx_feed(Dead, <<>>),
        {error, Reason, _} = ?P:rx_feed(Dead, Stream)
    end} || Name <- ?SUITES, Pos <- [0, 1]].

tamper_length_prefix_to_small_test() ->
    {_, R} = stream_for_tamper(?AESGCM),
    ?assertMatch({error, bad_length, _}, ?P:rx_feed(R, <<0, 5, 1, 2, 3, 4, 5, 6>>)).

delete_byte_inside_frame_test_() ->
    [fun() ->
        {Stream, R} = stream_for_tamper(Name),
        <<Pre:50/binary, _, Post/binary>> = Stream,
        {error, Reason, Dead} = ?P:rx_feed(R, <<Pre/binary, Post/binary>>),
        ?assert(lists:member(Reason, [decrypt_failed, bad_length])),
        {error, Reason, _} = ?P:rx_feed(Dead, Stream)
    end || Name <- ?SUITES].

truncation_at_end_is_incomplete_not_an_error_test() ->
    %% The caller sees EOF; the receiver cannot know more bytes are missing.
    {Stream, R} = stream_for_tamper(?AESGCM),
    Cut = byte_size(Stream) - 5,
    <<Short:Cut/binary, Tail/binary>> = Stream,
    {ok, Evs, R1} = ?P:rx_feed(R, Short),
    ?assertMatch([{packet, _}], Evs),
    ?assertMatch({ok, [{packet, _}], _}, ?P:rx_feed(R1, Tail)).

reordered_frames_fail_test() ->
    {S, R} = pair(?AESGCM, #{chunk_size => 100}, #{}),
    {[F1, F2, _F3], _} = send(S, data(random, 250)),
    ?assertMatch({error, decrypt_failed, _}, ?P:rx_feed(R, <<F2/binary, F1/binary>>)).

replayed_frame_fails_test() ->
    {S, R} = pair(?AESGCM, #{}, #{}),
    {[F1], _} = send(S, <<"x">>),
    {[{packet, <<"x">>}], R1} = feed(R, F1),
    ?assertMatch({error, decrypt_failed, _}, ?P:rx_feed(R1, F1)).

error_receiver_stays_dead_even_with_valid_data_test() ->
    {S, R} = pair(?AESGCM, #{}, #{}),
    {[F1], S1} = send(S, <<"x">>),
    {[F2], _} = send(S1, <<"y">>),
    {error, decrypt_failed, Dead} = ?P:rx_feed(R, flip(F1, 5)),
    ?assertMatch({error, decrypt_failed, _}, ?P:rx_feed(Dead, F1)),
    ?assertMatch({error, decrypt_failed, _}, ?P:rx_feed(Dead, F2)),
    ?assertMatch({error, decrypt_failed, _}, ?P:rx_feed(Dead, <<>>)).

%%% ------------------------------------------------------------------
%%% Fuzz
%%% ------------------------------------------------------------------

fuzz_random_bytes_test_() ->
    {timeout, 120, fun() ->
        {_, Rx} = handshake(?AESGCM),
        _ = rand:seed(exsss, {42, 42, 42}),
        lists:foreach(fun(I) ->
            R = new_receiver(Rx, #{accept_compression => (I rem 2 =:= 0), max_packet => 1000}),
            Size = rand:uniform(400) - 1,
            Junk0 = rand:bytes(Size),
            %% half of the cases get a plausible length prefix so decryption is reached
            Junk = case I rem 3 of
                       0 -> <<(17 + rand:uniform(Size + 1) - 1):16, Junk0/binary>>;
                       _ -> Junk0
                   end,
            check_fuzz_result(?P:rx_feed(R, Junk))
        end, lists:seq(1, 3000))
    end}.

fuzz_split_feeding_test_() ->
    {timeout, 120, fun() ->
        {_, Rx} = handshake(?CHACHA),
        _ = rand:seed(exsss, {7, 7, 7}),
        lists:foreach(fun(_) ->
            R0 = new_receiver(Rx, #{}),
            Parts = [rand:bytes(rand:uniform(50)) || _ <- lists:seq(1, 10)],
            lists:foldl(fun(Part, RAcc) ->
                                case ?P:rx_feed(RAcc, Part) of
                                    {ok, [], R1} -> R1;
                                    {error, Reason, Dead} ->
                                        ?assert(is_atom(Reason)),
                                        Dead
                                end
                        end, R0, Parts)
        end, lists:seq(1, 500))
    end}.

fuzz_mutated_valid_streams_test_() ->
    {timeout, 120, fun() ->
        _ = rand:seed(exsss, {9, 8, 7}),
        lists:foreach(fun(I) ->
            Name = lists:nth(I rem 2 + 1, ?SUITES),
            {S, R} = pair(Name, #{chunk_size => 300, padding => {bucket, 64},
                                  compression => {zlib, 10}},
                          #{accept_compression => true, max_packet => 5000}),
            {Frames, _} = send(S, data(compressible, rand:uniform(2000))),
            Stream = bin(Frames),
            Pos = rand:uniform(byte_size(Stream)) - 1,
            Mutated = flip_bits(Stream, Pos, rand:uniform(255)),
            check_fuzz_result(?P:rx_feed(R, Mutated))
        end, lists:seq(1, 300))
    end}.

flip_bits(Bin, Pos, Mask) ->
    <<Pre:Pos/binary, B, Post/binary>> = Bin,
    <<Pre/binary, (B bxor Mask), Post/binary>>.

check_fuzz_result({ok, Evs, _}) -> ?assert(is_list(Evs));
check_fuzz_result({error, Reason, _}) ->
    ?assert(lists:member(Reason, [decrypt_failed, bad_length, reserved_flags, tick_with_payload,
                                  bad_padding, compression_not_accepted, bad_compression,
                                  packet_too_large, rekey_required, rekey_unsupported])).

%%% ------------------------------------------------------------------
%%% Combinations of all modes
%%% ------------------------------------------------------------------

combination_test_() ->
    Paddings = [none, {bucket, 512}, {fixed, 4096}],
    Compressions = [none, {zlib, 64}],
    Rekeys = [never, [{frames, 3}], [{bytes, 5000}, {frames, 50}]],
    Sizes = [1, 63, 64, 3999, 4000, 4001, 9000, 65518, 65519, 70000],
    [{lists:flatten(io_lib:format("~s ~p ~p ~p", [Name, Padding, Compression, Rekey])),
      {timeout, 60, fun() -> combination(Name, Padding, Compression, Rekey, Sizes) end}}
     || Name <- ?SUITES, Padding <- Paddings, Compression <- Compressions, Rekey <- Rekeys].

combination(Name, Padding, Compression, Rekey, Sizes) ->
    {S0, R0} = pair(Name, #{padding => Padding, compression => Compression,
                             rekey_after => Rekey, chunk_size => 4000},
                    #{accept_compression => true}),
    Inputs = [{Kind, N} || N <- Sizes, Kind <- [random, compressible]],
    {Wire, Expected, _} =
        lists:foldl(fun({Kind, N}, {W, E, SAcc}) ->
                            P = data(Kind, N),
                            {Frames, Evs, S1} = send_with_tick(SAcc, P),
                            {[W, Frames], E ++ Evs, S1}
                    end, {[], [], S0}, Inputs),
    WireBin = bin(Wire),
    case Padding of
        {bucket, B} -> [?assertEqual(0, (L - 16) rem B) || L <- frame_lens(WireBin)];
        {fixed, F} -> ?assertEqual([F + 16], lists:usort(frame_lens(WireBin)));
        none -> ok
    end,
    ?assertEqual(Expected, element(1, feed_split(R0, WireBin, {5, 6, 7}))),
    ?assertEqual(Expected, element(1, feed(R0, WireBin))).

%% Sends a packet with a keepalive tick between its first and second frame
%% (after the only frame for a one-frame packet). Returns the wire bytes and
%% the events the receiver must produce for them.
send_with_tick(S, Packet) ->
    case ?P:tx_next(S, ?P:tx_packet(Packet)) of
        {F, S1, done} ->
            {T, S2} = tick(S1),
            {[bin(F), T], [{packet, Packet}, tick], S2};
        {F, S1, more, P1} ->
            {T, S2} = tick(S1),
            {Rest, S3} = finish(S2, P1, []),
            {[bin(F), T, Rest], [tick, {packet, Packet}], S3}
    end.

finish(S, Pending, Acc) ->
    case ?P:tx_next(S, Pending) of
        {F, S1, more, P1} -> finish(S1, P1, [bin(F) | Acc]);
        {F, S1, done} -> {lists:reverse([bin(F) | Acc]), S1}
    end.

%%% ------------------------------------------------------------------
%%% Policies and settings
%%% ------------------------------------------------------------------

sender_policy_defaults_test() ->
    {ok, P} = ?P:sender_policy(#{}),
    ?assertMatch(#{chunk_size := 16384, padding := none, compression := none,
                   rekey_after := [{bytes, 1073741824}]}, P),
    ?assertEqual({ok, P}, ?P:sender_policy([#{}, #{}])).

receiver_policy_defaults_test() ->
    ?assertEqual({ok, #{max_packet => 67108864, accept_compression => false,
                        max_bytes_without_rekey => infinity}},
                 ?P:receiver_policy(#{})).

policy_strings_as_in_flags_test() ->
    {ok, S} = ?P:sender_policy(#{chunk_size => "16384", padding => "bucket:512",
                                 compression => "zlib:256",
                                 rekey_after => "bytes:1073741824,ms:3600000"}),
    ?assertMatch(#{chunk_size := 16384, padding := {bucket, 512}, compression := {zlib, 256},
                   rekey_after := [{bytes, 1073741824}, {ms, 3600000}]}, S),
    {ok, S2} = ?P:sender_policy(#{padding => <<"fixed:4096">>, rekey_after => "never"}),
    ?assertMatch(#{padding := {fixed, 4096}, rekey_after := never}, S2),
    {ok, R} = ?P:receiver_policy(#{max_packet => "1000", accept_compression => "true",
                                   max_bytes_without_rekey => "infinity"}),
    ?assertEqual(#{max_packet => 1000, accept_compression => true,
                   max_bytes_without_rekey => infinity}, R),
    ?assertMatch({ok, #{accept_compression := false}},
                 ?P:receiver_policy(#{accept_compression => "false"})).

policy_precedence_test() ->
    %% Opts > flag > env > default
    Opts = #{chunk_size => 100},
    Flag = #{chunk_size => "200", padding => "bucket:64"},
    Env = #{chunk_size => "300", padding => "fixed:512", compression => "zlib:10"},
    ?assertMatch({ok, #{chunk_size := 100, padding := {bucket, 64}, compression := {zlib, 10}}},
                 ?P:sender_policy([Opts, Flag, Env])),
    ?assertMatch({ok, #{chunk_size := 200}}, ?P:sender_policy([#{}, Flag, Env])),
    ?assertMatch({ok, #{chunk_size := 300}}, ?P:sender_policy([#{}, #{}, Env])).

policy_unknown_keys_are_ignored_test() ->
    ?assertMatch({ok, _}, ?P:sender_policy(#{suite => aesgcm_sha512, whatever => 1})).

invalid_sender_settings_test_() ->
    Bad = [{chunk_size, 0}, {chunk_size, 65519}, {chunk_size, "abc"}, {chunk_size, -1},
           {chunk_size, 1.5}, {padding, bucket}, {padding, {bucket, 0}},
           {padding, {bucket, 65520}}, {padding, {fixed, 3}}, {padding, {fixed, 65520}},
           {padding, "bucket"}, {padding, "bucket:x"}, {padding, "rot13:1"},
           {compression, zlib}, {compression, {zlib, -1}}, {compression, {zlib, 65519}},
           {compression, "gzip:1"}, {compression, "zlib"},
           {rekey_after, []}, {rekey_after, always}, {rekey_after, [{frames, 0}]},
           {rekey_after, [{days, 1}]}, {rekey_after, "bytes"}, {rekey_after, "bytes:0"},
           {rekey_after, "frames:1,hours:2"}, {clock, 5}],
    [{lists:flatten(io_lib:format("~p", [{K, V}])), fun() ->
        {error, {invalid_setting, K, V, Allowed}} = ?P:sender_policy(#{K => V}),
        ?assert(is_list(Allowed) andalso length(Allowed) > 10),
        ?assertError({badarg, {invalid_setting, K, V, _}},
                     new_sender(element(1, handshake(?AESGCM)), #{K => V}))
    end} || {K, V} <- Bad].

invalid_receiver_settings_test_() ->
    Bad = [{max_packet, 0}, {max_packet, "x"}, {max_packet, infinity},
           {accept_compression, yes}, {accept_compression, "1"},
           {max_bytes_without_rekey, 0}, {max_bytes_without_rekey, "lots"}],
    [{lists:flatten(io_lib:format("~p", [{K, V}])), fun() ->
        ?assertMatch({error, {invalid_setting, K, V, [_ | _]}}, ?P:receiver_policy(#{K => V})),
        ?assertError({badarg, {invalid_setting, K, V, _}},
                     new_receiver(element(2, handshake(?AESGCM)), #{K => V}))
    end} || {K, V} <- Bad].

allowed_values_are_named_in_the_error_test() ->
    {error, {invalid_setting, padding, "x", Allowed}} = ?P:sender_policy(#{padding => "x"}),
    ?assertNotEqual(nomatch, string:find(Allowed, "bucket")),
    ?assertNotEqual(nomatch, string:find(Allowed, "fixed")).

validated_policy_is_accepted_again_test() ->
    {ok, P} = ?P:sender_policy(#{padding => "fixed:512", compression => "zlib:1"}),
    {Tx, _} = handshake(?AESGCM),
    S = new_sender(Tx, P),
    ?assertMatch(tx, element(1, S)).

unkeyed_cipher_state_is_refused_test() ->
    CS = enoise_cipher_state:init(empty, 'AESGCM'),
    ?assertError(badarg, new_sender(CS, #{})),
    ?assertError(badarg, new_receiver(CS, #{})).

%%% ------------------------------------------------------------------
%%% Purity
%%% ------------------------------------------------------------------

section_is_pure_test() ->
    Src = filename:join([code:lib_dir(bouncer), "src", "bouncer_protocol.erl"]),
    {ok, Bin} = file:read_file(Src),
    [_, Section] = binary:split(Bin, <<"%%% TRANSPORT FRAMING">>),
    Forbidden = [<<"gen_tcp">>, <<"gen_udp">>, <<"gen_sctp">>, <<"inet:">>, <<"socket:">>,
                 <<"spawn">>, <<"open_port">>, <<"erlang:send">>, <<" ! ">>, <<"receive\n">>,
                 <<"get_env">>, <<"getenv">>, <<"get_argument">>, <<"persistent_term">>,
                 <<"ets:">>, <<"application:">>, <<"gen_server">>],
    Code = strip_comments_and_docs(Section),
    [?assertEqual({X, nomatch}, {X, binary:match(Code, X)}) || X <- Forbidden].

strip_comments_and_docs(Bin) ->
    NoDocs = re:replace(Bin, "-doc \"\"\".*?\"\"\"\\.", "", [dotall, global, {return, binary}]),
    re:replace(NoDocs, "%[^\n]*", "", [global, {return, binary}]).

%%
%% Helpers
%%

new_sender(A, B) ->
    ?P:tx_start(?P:new_sender(A, B)).

new_receiver(A, B) ->
    ?P:rx_start(?P:new_receiver(A, B)).
