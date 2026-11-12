-module(noisegate_protocol_tests).

-include_lib("eunit/include/eunit.hrl").

suite_mapping_test_() ->
    [?_assertEqual([chachapoly_blake2b, aesgcm_sha512, aesgcm_sha256,
                    aesgcm_blake2b], noisegate_protocol:known_suites()),
     ?_assertEqual(chachapoly_blake2b, noisegate_protocol:suite_atom(1)),
     ?_assertEqual(aesgcm_sha512, noisegate_protocol:suite_atom(2)),
     ?_assertEqual(aesgcm_sha256, noisegate_protocol:suite_atom(3)),
     ?_assertEqual(aesgcm_blake2b, noisegate_protocol:suite_atom(4))].

noise_names_test_() ->
    [{atom_to_list(Suite), ?_assertEqual(Name, noisegate_protocol:noise_name(Suite))}
     || {Suite, Name} <- [
                          {chachapoly_blake2b, <<"Noise_XX_25519_ChaChaPoly_BLAKE2b">>},
                          {aesgcm_sha512, <<"Noise_XX_25519_AESGCM_SHA512">>},
                          {aesgcm_sha256, <<"Noise_XX_25519_AESGCM_SHA256">>},
                          {aesgcm_blake2b, <<"Noise_XX_25519_AESGCM_BLAKE2b">>}
                         ]].

hello_roundtrip_test_() ->
    [?_test(begin
                Id = noisegate_protocol:suite_id(Suite),
                Msg1 = binary:copy(<<Id>>, 32),
                Hello = noisegate_protocol:hello(Id, Msg1),
                Header = binary:part(Hello, 0, 8),
                ?assertEqual(noisegate_protocol:hello_header(Id), Header),
                ?assertEqual({ok, Suite, 32},
                             noisegate_protocol:parse_hello_header(Header, [Id])),
                ?assertEqual(Msg1, binary:part(Hello, 8, 32)),
                ?assert(is_binary(noisegate_protocol:noise_name(Suite)))
            end) || Suite <- noisegate_protocol:known_suites()].

unsupported_suite_test_() ->
    [?_assertEqual({reject, 2},
                   noisegate_protocol:parse_hello_header(noisegate_protocol:hello_header(Id), [2]))
     || Id <- [1, 3, 4]].

unknown_suite_test_() ->
    [?_assertEqual({reject, 2},
                   noisegate_protocol:parse_hello_header(
                     <<"BNCR", 1, Id, 32:16>>, [1, 2, 3, 4]))
     || Id <- [0, 5, 255]].


parse_header_test() ->
    %% version
    ?assertEqual({reject, 1}, noisegate_protocol:parse_hello_header(<<"BNCR", 0, 2, 32:16>>, [2])),
    ?assertEqual({reject, 1}, noisegate_protocol:parse_hello_header(<<"BNCR", 2, 2, 32:16>>, [2])),
    ?assertEqual({reject, 1}, noisegate_protocol:parse_hello_header(<<"BNCR", 255, 9, 0:16>>, [2])),
    %% suite
    ?assertEqual({reject, 2}, noisegate_protocol:parse_hello_header(<<"BNCR", 1, 0, 32:16>>, [2])),
    ?assertEqual({reject, 2}, noisegate_protocol:parse_hello_header(<<"BNCR", 1, 5, 32:16>>, [2])),
    ?assertEqual({reject, 2}, noisegate_protocol:parse_hello_header(<<"BNCR", 1, 1, 32:16>>, [2])),   % known, not accepted
    %% length
    ?assertEqual({ok, aesgcm_sha512, 32}, noisegate_protocol:parse_hello_header(<<"BNCR", 1, 2, 32:16>>, [2])),
    [?assertEqual({error, bad_hello_header}, noisegate_protocol:parse_hello_header(<<"BNCR", 1, 2, L:16>>, [2]))
     || L <- [0, 31, 33, 65535]],
    %% framing
    ?assertEqual({error, bad_hello_header}, noisegate_protocol:parse_hello_header(<<"XNCR", 1, 2, 32:16>>, [2])),
    ?assertEqual({error, bad_hello_header}, noisegate_protocol:parse_hello_header(<<"BNCR", 1, 2, 32>>, [2])),
    ?assertEqual({error, bad_hello_header}, noisegate_protocol:parse_hello_header(<<>>, [2])),
    %% accept list accepting an id outside 1..4 must not make that id valid
    ?assertEqual({reject, 2}, noisegate_protocol:parse_hello_header(<<"BNCR", 1, 9, 32:16>>, [9, 2])).

prologue_vector_test() ->
    Header = <<16#42, 16#4e, 16#43, 16#52, 1, 2, 0, 32>>,
    Expected = <<16#62, 16#6f, 16#75, 16#6e, 16#63, 16#65, 16#72, 16#2f, 16#31,
                 0, Header/binary, 0, 8, "bob@host">>,
    ?assertEqual(Expected, noisegate_protocol:prologue(Header, <<"bob@host">>)).

prologue_binds_header_and_target_test() ->
    Header = noisegate_protocol:hello_header(2),
    Target = <<"bob@host">>,
    Prologue = noisegate_protocol:prologue(Header, Target),
    [?assertNotEqual(Prologue, noisegate_protocol:prologue(flip_byte(Header, Index), Target)) || Index <- lists:seq(0, 7)],
    [?assertNotEqual(Prologue, noisegate_protocol:prologue(Header, flip_byte(Target, Index))) || Index <- lists:seq(0, byte_size(Target) - 1)].

hello_header_matches_prologue_input_test() ->
    lists:foreach(fun(Id) ->
                          Header = noisegate_protocol:hello_header(Id),
                          Hello = noisegate_protocol:hello(Id, binary:copy(<<0>>, 32)),
                          ?assertEqual(Header, binary:part(Hello, 0, 8))
                  end,
                  lists:seq(1, 4)).

wire_frames_test() ->
    Msg2 = <<1, 2, 3>>,
    ?assertEqual(<<"BNCR", 1, 0, 0, 3, Msg2/binary>>, noisegate_protocol:reply_ok(Msg2)),
    ?assertEqual(<<"BNCR", 1, 1, 0, 0>>, noisegate_protocol:reply_reject(1)),
    ?assertEqual(<<"BNCR", 1, 2, 0, 0>>, noisegate_protocol:reply_reject(2)),
    Msg3 = <<4, 5>>,
    ?assertEqual(<<0, 2, Msg3/binary>>, noisegate_protocol:msg3_frame(Msg3)),
    ?assertEqual(<<0, 8, "bob@host">>, noisegate_protocol:encode_name(<<"bob@host">>)).

reply_header_test() ->
    Limits = noisegate_protocol:limits(),
    {Msg2Min, Msg2Max} = maps:get(msg2_length, Limits),
    ?assertEqual({ok, Msg2Min},
                 noisegate_protocol:parse_reply_header(<<"BNCR", 1, 0, Msg2Min:16>>)),
    ?assertEqual({ok, Msg2Max},
                 noisegate_protocol:parse_reply_header(<<"BNCR", 1, 0, Msg2Max:16>>)),
    ?assertEqual({error, bad_reply_header},
                 noisegate_protocol:parse_reply_header(<<"BNCR", 1, 0, (Msg2Min - 1):16>>)),
    ?assertEqual({error, bad_reply_header},
                 noisegate_protocol:parse_reply_header(<<"BNCR", 1, 0, (Msg2Max + 1):16>>)),
    ?assertEqual({error, unsupported_version},
                 noisegate_protocol:parse_reply_header(<<"BNCR", 1, 1, 0:16>>)),
    ?assertEqual({error, unsupported_suite},
                 noisegate_protocol:parse_reply_header(<<"BNCR", 1, 2, 0:16>>)),
    [?assertEqual({error, bad_reply_header},
                  noisegate_protocol:parse_reply_header(Header))
     || Header <- [<<"BNCR", 1, 1, 1:16>>, <<"BNCR", 1, 2, 1:16>>,
                   <<"BNCR", 1, 3, 0:16>>, <<"XNCR", 1, 0, Msg2Min:16>>,
                   <<"BNCR", 2, 0, Msg2Min:16>>, <<>>]].

msg3_prefix_test() ->
    Limits = noisegate_protocol:limits(),
    {Min, Max} = maps:get(msg3_length, Limits),
    ?assertEqual({ok, Min}, noisegate_protocol:parse_msg3_prefix(<<Min:16>>)),
    ?assertEqual({ok, Max}, noisegate_protocol:parse_msg3_prefix(<<Max:16>>)),
    ?assertEqual({error, bad_msg3_length},
                 noisegate_protocol:parse_msg3_prefix(<<(Min - 1):16>>)),
    ?assertEqual({error, bad_msg3_length},
                 noisegate_protocol:parse_msg3_prefix(<<(Max + 1):16>>)),
    ?assertEqual({error, bad_msg3_length}, noisegate_protocol:parse_msg3_prefix(<<1>>)).

encode_name_test() ->
    Name = <<"node@host">>,
    Payload = noisegate_protocol:encode_name(Name),
    ?assertEqual(Payload, noisegate_protocol:encode_name(Name)),
    ?assertEqual({ok, Name}, noisegate_protocol:decode_name(Payload)),
    ?assertEqual({error, bad_payload},
                 noisegate_protocol:decode_name(<<3:16, "node@host">>)),
    ?assertEqual({error, bad_payload},
                 noisegate_protocol:decode_name(<<8:16, "node@host">>)),
    ?assertEqual({error, bad_name},
                 noisegate_protocol:decode_name(<<3:16, "bad">>)).

unpad_iodata_test() ->
    Rest = [<<4:16>>, [<<"he">>, <<"llo">>], <<0, 0, 0, 0>>],
    ?assertEqual({ok, <<"hello">>}, noisegate_protocol:unpad(8, Rest)),
    ?assertEqual({ok, <<"hello">>}, noisegate_protocol:unpad(8, iolist_to_binary(Rest))),
    ?assertEqual({ok, Rest}, noisegate_protocol:unpad(0, Rest)),
    ?assertEqual({error, bad_padding},
                 noisegate_protocol:unpad(8, [<<4:16>>, <<"hello">>, <<1, 0, 0, 0>>])),
    ?assertError(badarg, noisegate_protocol:unpad(8, [<<4:16>>, 256])).

limits_match_enoise_test_() ->
    [?_test(begin
        Limits = noisegate_protocol:limits(),
        lists:foreach(fun(Name) ->
            {Msg1, Msg2, Msg3} = enoise_flight_lengths(Suite, Name),
            ?assertEqual(32, byte_size(Msg1)),
            ?assertEqual(byte_size(Msg1), element(1, maps:get(msg1_length, Limits))),
            ?assertEqual(byte_size(Msg1), element(2, maps:get(msg1_length, Limits))),
            ?assertEqual(byte_size(Msg2), length_limit(msg2_length, Name, Limits)),
            ?assertEqual(byte_size(Msg3), length_limit(msg3_length, Name, Limits))
        end, [<<"a@b">>,
              <<(binary:copy(<<"a">>, 126))/binary, "@",
                (binary:copy(<<"b">>, 128))/binary>>])
    end) || Suite <- noisegate_protocol:known_suites()].

length_limit(Key, Name, Limits) ->
    {Min, Max} = maps:get(Key, Limits),
    case byte_size(Name) of
        3 -> Min;
        255 -> Max
    end.

enoise_flight_lengths(Suite, Name) ->
    SuiteId = noisegate_protocol:suite_id(Suite),
    Prologue = noisegate_protocol:prologue(noisegate_protocol:hello_header(SuiteId), Name),
    ProtocolName = noisegate_protocol:noise_name(Suite),
    Init = noise_state(ProtocolName, Prologue, initiator),
    Resp = noise_state(ProtocolName, Prologue, responder),
    NamePayload = noisegate_protocol:encode_name(Name),
    {ok, send, Msg1, Init1} = enoise:step_handshake(Init, {send, <<>>}),
    {ok, rcvd, <<>>, Resp1} = enoise:step_handshake(Resp, {rcvd, Msg1}),
    {ok, send, Msg2, Resp2} = enoise:step_handshake(Resp1, {send, NamePayload}),
    {ok, rcvd, NamePayload, Init2} = enoise:step_handshake(Init1, {rcvd, Msg2}),
    {ok, send, Msg3, Init3} = enoise:step_handshake(Init2, {send, NamePayload}),
    {ok, rcvd, NamePayload, Resp3} = enoise:step_handshake(Resp2, {rcvd, Msg3}),
    {ok, done, _} = enoise:step_handshake(Init3, done),
    {ok, done, _} = enoise:step_handshake(Resp3, done),
    {Msg1, Msg2, Msg3}.

noise_state(ProtocolName, Prologue, Role) ->
    Options = [{noise, ProtocolName},
               {s, enoise_keypair:new(dh25519)},
               {e, enoise_keypair:new(dh25519)},
               {prologue, Prologue}],
    {ok, State} = enoise:handshake(Options, Role),
    State.

flip_byte(Binary, Index) ->
    <<Prefix:Index/binary, Byte, Suffix/binary>> = Binary,
    <<Prefix/binary, (Byte bxor 1), Suffix/binary>>.
