%% enoise API verified against the pinned source:
%%   enoise:handshake([{noise, ProtocolName}, {prologue, Prologue}, {s, StaticKeypair}], Role)
%%     creates the XX handshake state for the protocol name, prologue, static
%%     keypair and role.
%%   enoise:step_handshake(State, {send, Payload}) writes a message and
%%     enoise:step_handshake(State, {rcvd, Message}) reads one and returns its
%%     payload.
%%   enoise_hs_state:remote_keys(State) returns the remote static keypair;
%%     enoise_keypair:pubkey/1 extracts its public key.
%%   enoise_hs_state:finalize(State) returns the two split cipher states.
%%     It assigns initiator tx=CS1, rx=CS2 and responder rx=CS1, tx=CS2.
%%     The loopback transport test verifies this.
-module(bouncer_hs).

-moduledoc """
Noise XX handshake over a passive raw gen_tcp socket.

On success the socket remains open immediately after the final handshake
flight, ready for transport framing. An initiator returns without waiting for
confirmation after sending message 3; if the responder rejects message 3,
the initiator observes the closed socket on its next read.
""".

-export([initiate/4, respond/4]).

-type suite() :: chachapoly_blake2b | aesgcm_sha512 | aesgcm_sha256 | aesgcm_blake2b.
-type result() :: #{send := enoise_cipher_state:state(),
                    recv := enoise_cipher_state:state(),
                    remote_name := binary(),
                    remote_key := binary(),
                    suite := suite()}.
-type opts() :: map().

-spec initiate(gen_tcp:socket(), binary(), bouncer_keys:key_info(), opts()) ->
          {ok, result()} | {error, term()}.
initiate(Socket, TargetName, Keys, Opts) when is_map(Opts) ->
    case setup_socket(Socket) of
        ok ->
            case handshake_deadline(Opts) of
                {ok, Deadline} ->
                    finish(Socket, initiate_handshake(Socket, TargetName, Keys, Opts, Deadline));
                {error, _} = Error ->
                    finish(Socket, Error)
            end;
        {error, _} = Error ->
            finish(Socket, Error)
    end;
initiate(Socket, _TargetName, _Keys, _Opts) ->
    gen_tcp:close(Socket),
    {error, bad_options}.

-spec respond(gen_tcp:socket(), binary(), bouncer_keys:key_info(), opts()) ->
          {ok, result()} | {error, term()}.
respond(Socket, OwnName, Keys, Opts) ->
    case bouncer_limit:acquire(Opts) of
        ok ->
            try
                case setup_socket(Socket) of
                    ok ->
                        case handshake_deadline(Opts) of
                            {ok, Deadline} ->
                                finish(Socket,
                                       respond_handshake(Socket, OwnName, Keys, Opts,
                                                         Deadline));
                            {error, _} = Error ->
                                finish(Socket, Error)
                        end;
                    {error, _} = Error ->
                        finish(Socket, Error)
                end
            after
                bouncer_limit:release()
            end;
        {error, busy} ->
            gen_tcp:close(Socket),
            {error, busy}
    end.

initiate_handshake(Socket, TargetName, Keys, Opts, Deadline) ->
    case valid_name(TargetName) andalso valid_name(maps:get(own_name, Opts, undefined)) of
        false ->
            {error, bad_name};
        true ->
            Suite = maps:get(suite, Opts, aesgcm_sha512),
            case supported_suite(Suite) of
                false ->
                    {error, bad_suite};
                true ->
                    SuiteId = bouncer_protocol:suite_id(Suite),
                    Header = bouncer_protocol:hello_header(SuiteId),
                    Prologue = bouncer_protocol:prologue(Header, TargetName),
                    case handshake_state(Suite, Prologue, Keys, initiator) of
                        {ok, State0} ->
                            case enoise:step_handshake(State0, {send, <<>>}) of
                                {ok, send, Msg1, State1} when byte_size(Msg1) =:= 32 ->
                                    Hello = bouncer_protocol:hello(SuiteId, Msg1),
                                    case binary:part(Hello, 0, 8) =:= Header of
                                        true ->
                                            case gen_tcp:send(Socket, Hello) of
                                                ok ->
                                                    initiate_reply(Socket, TargetName,
                                                                   maps:get(own_name, Opts),
                                                                   Suite, State1, Opts, Deadline);
                                                {error, Reason} ->
                                                    {error, Reason}
                                            end;
                                        false ->
                                            {error, handshake_failed}
                                    end;
                                {ok, _Direction, _Msg, _State} ->
                                    {error, handshake_failed};
                                {error, _} ->
                                    {error, handshake_failed}
                            end;
                        {error, _} ->
                            {error, bad_keys}
                    end
            end
    end.

initiate_reply(Socket, TargetName, OwnName, Suite, State1, Opts, Deadline) ->
    case read_exact(Socket, 8, Deadline) of
        {ok, ReplyHeader} ->
            case bouncer_protocol:parse_reply_header(ReplyHeader) of
                {ok, Msg2Len} ->
                    case read_exact(Socket, Msg2Len, Deadline) of
                        {ok, Msg2} ->
                            case enoise:step_handshake(State1, {rcvd, Msg2}) of
                                {ok, rcvd, Payload, State2} ->
                                    check_responder(Socket, TargetName, OwnName, Suite,
                                                    State2, Payload, Opts);
                                {error, _} ->
                                    {error, handshake_failed}
                            end;
                        {error, _} = Error ->
                            Error
                    end;
                {error, _} = Error ->
                    Error
            end;
        {error, _} = Error ->
            Error
    end.

check_responder(Socket, TargetName, OwnName, Suite, State2, Payload, Opts) ->
    case bouncer_protocol:decode_name(Payload) of
        {ok, TargetName} ->
            RemoteKey = remote_public_key(State2),
            case bouncer_keys:check_peer(TargetName, RemoteKey, Opts) of
                allowed ->
                    send_msg3(Socket, OwnName, Suite, TargetName, RemoteKey, State2);
                Reason ->
                    log_peer_rejection(TargetName, RemoteKey, Reason),
                    {error, {unauthorized_peer, Reason}}
            end;
        {ok, OtherName} ->
            RemoteKey = remote_public_key(State2),
            log_peer_rejection(OtherName, RemoteKey, name_mismatch),
            {error, target_name_mismatch};
        {error, Reason} ->
            {error, Reason}
    end.

send_msg3(Socket, OwnName, Suite, RemoteName, RemoteKey, State2) ->
    case enoise:step_handshake(State2,
                               {send, bouncer_protocol:name_payload(OwnName)}) of
        {ok, send, Msg3, State3} ->
            case gen_tcp:send(Socket, bouncer_protocol:msg3_frame(Msg3)) of
                ok ->
                    case enoise_hs_state:finalize(State3) of
                        {ok, Split} ->
                            {ok, result(Split, RemoteName, RemoteKey, Suite)}
                    end;
                {error, Reason} ->
                    {error, Reason}
            end;
        {error, _} ->
            {error, handshake_failed}
    end.

respond_handshake(Socket, OwnName, Keys, Opts, Deadline) ->
    case valid_name(OwnName) of
        false ->
            {error, bad_name};
        true ->
            case accepted_suite_ids(Opts) of
                {ok, AcceptedIds} ->
                    respond_header(Socket, OwnName, Keys, Opts, AcceptedIds, Deadline);
                {error, _} = Error ->
                    Error
            end
    end.

respond_header(Socket, OwnName, Keys, Opts, AcceptedIds, Deadline) ->
    case read_exact(Socket, 8, Deadline) of
        {ok, HelloHeader} ->
            case bouncer_protocol:parse_hello_header(HelloHeader, AcceptedIds) of
                {ok, Suite, 32} ->
                    respond_msg1(Socket, HelloHeader, OwnName, Suite, Keys, Opts, Deadline);
                {reject, Status} ->
                    StatusReason = case Status of
                                       1 -> unsupported_version;
                                       2 -> unsupported_suite
                                   end,
                    case gen_tcp:send(Socket, bouncer_protocol:reply_reject(Status)) of
                        ok -> {error, StatusReason};
                        {error, Reason} -> {error, Reason}
                    end;
                {error, Reason} ->
                    logger:debug("bouncer_hs: closing connection with invalid hello header"),
                    {error, Reason}
            end;
        {error, _} = Error ->
            Error
    end.

respond_msg1(Socket, HelloHeader, OwnName, Suite, Keys, Opts, Deadline) ->
    case read_exact(Socket, 32, Deadline) of
        {ok, Msg1} ->
            Prologue = bouncer_protocol:prologue(HelloHeader, OwnName),
            case handshake_state(Suite, Prologue, Keys, responder) of
                {ok, State0} ->
                    case enoise:step_handshake(State0, {rcvd, Msg1}) of
                        {ok, rcvd, <<>>, State1} ->
                            send_msg2(Socket, OwnName, Suite, State1, Opts, Deadline);
                        {ok, rcvd, _UnexpectedPayload, _State1} ->
                            {error, handshake_failed};
                        {error, _} ->
                            {error, handshake_failed}
                    end;
                {error, _} ->
                    {error, bad_keys}
            end;
        {error, _} = Error ->
            Error
    end.

send_msg2(Socket, OwnName, Suite, State1, Opts, Deadline) ->
    case enoise:step_handshake(State1,
                               {send, bouncer_protocol:name_payload(OwnName)}) of
        {ok, send, Msg2, State2} ->
            case gen_tcp:send(Socket, bouncer_protocol:reply_ok(Msg2)) of
                ok ->
                    receive_msg3(Socket, Suite, State2, Opts, Deadline);
                {error, Reason} ->
                    {error, Reason}
            end;
        {error, _} ->
            {error, handshake_failed}
    end.

receive_msg3(Socket, Suite, State2, Opts, Deadline) ->
    case read_exact(Socket, 2, Deadline) of
        {ok, Prefix} ->
            case bouncer_protocol:parse_msg3_prefix(Prefix) of
                {ok, Msg3Len} ->
                    case read_exact(Socket, Msg3Len, Deadline) of
                        {ok, Msg3} ->
                            process_msg3(Msg3, Suite, State2, Opts);
                        {error, _} = Error ->
                            Error
                    end;
                {error, _} = Error ->
                    Error
            end;
        {error, _} = Error ->
            Error
    end.

process_msg3(Msg3, Suite, State2, Opts) ->
    case enoise:step_handshake(State2, {rcvd, Msg3}) of
        {ok, rcvd, Payload, State3} ->
            case bouncer_protocol:decode_name(Payload) of
                {ok, RemoteName} ->
                    RemoteKey = remote_public_key(State3),
                    case bouncer_keys:check_peer(RemoteName, RemoteKey, Opts) of
                        allowed ->
                            case enoise_hs_state:finalize(State3) of
                                {ok, Split} ->
                                    {ok, result(Split, RemoteName, RemoteKey, Suite)}
                            end;
                        Reason ->
                            log_peer_rejection(RemoteName, RemoteKey, Reason),
                            {error, {unauthorized_peer, Reason}}
                    end;
                {error, Reason} ->
                    {error, Reason}
            end;
        {error, _} ->
            {error, handshake_failed}
    end.

handshake_state(Suite, Prologue, Keys, Role) when is_map(Keys) ->
    case {maps:find(public, Keys), maps:find(secret, Keys)} of
        {{ok, <<_:32/binary>> = Public}, {ok, <<_:32/binary>> = Secret}} ->
            KeyPair = enoise_keypair:new(dh25519, Secret, Public),
            enoise:handshake([{noise, bouncer_protocol:noise_name(Suite)},
                              {prologue, Prologue},
                              {s, KeyPair}],
                             Role);
        _ ->
            {error, bad_keys}
    end;
handshake_state(_, _, _, _) ->
    {error, bad_keys}.

remote_public_key(State) ->
    enoise_keypair:pubkey(enoise_hs_state:remote_keys(State)).

result(#{tx := Send, rx := Recv}, RemoteName, RemoteKey, Suite) ->
    #{send => Send, recv => Recv, remote_name => RemoteName,
      remote_key => RemoteKey, suite => Suite}.

accepted_suite_ids(Opts) ->
    Suites = maps:get(accept_suites, Opts, [aesgcm_sha512]),
    case is_list(Suites) andalso
         lists:all(fun supported_suite/1, Suites) of
        true -> {ok, [bouncer_protocol:suite_id(Suite) || Suite <- Suites]};
        false -> {error, bad_options}
    end.

supported_suite(Suite) ->
    lists:member(Suite, bouncer_protocol:known_suites()).

valid_name(Name) ->
    bouncer_keys:valid_node_name(Name).

setup_socket(Socket) ->
    case inet:setopts(Socket, [binary, {packet, 0}, {active, false}, {nodelay, true}]) of
        ok -> ok;
        {error, Reason} -> {error, Reason}
    end.

handshake_deadline(Opts) ->
    Timeout = maps:get(handshake_timeout_ms, Opts, 5000),
    case is_integer(Timeout) andalso Timeout > 0 of
        true -> {ok, erlang:monotonic_time(millisecond) + Timeout};
        false -> {error, bad_options}
    end.

read_exact(Socket, Length, Deadline) ->
    Remaining = max(0, Deadline - erlang:monotonic_time(millisecond)),
    case gen_tcp:recv(Socket, Length, Remaining) of
        {ok, Binary} -> {ok, Binary};
        {error, timeout} -> {error, timeout};
        {error, Reason} -> {error, Reason}
    end.

finish(_Socket, {ok, _} = Success) ->
    Success;
finish(Socket, {error, _} = Error) ->
    gen_tcp:close(Socket),
    Error.

log_peer_rejection(Name, PublicKey, Reason) ->
    Line = bouncer_keys:authorized_line(Name, PublicKey),
    Fingerprint = bouncer_keys:fingerprint(PublicKey),
    logger:warning("bouncer_hs: peer authorization failed (~p). Add to the authorized directory: ~tsFingerprint: ~ts",
                   [Reason, Line, Fingerprint]).
