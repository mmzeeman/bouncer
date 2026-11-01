# bouncer

Erlang distribution over a Noise transport, built on
[enoise](https://github.com/aeternity/enoise) (master branch).

## Build

    rebar3 compile

## Using the `bounce` distribution protocol

The distribution module is `bouncer_dist`, selected with `-proto_dist bouncer`
(Erlang appends `_dist` to the name). The compiled beams must be in the code
path. Note that epmd is still used for name registration unless you
replace it.

Start two nodes from the project directory:

    rebar3 compile
    erl -pa _build/default/lib/*/ebin -proto_dist bouncer -sname a
    erl -pa _build/default/lib/*/ebin -proto_dist bouncer -sname b

Then from node `b`:

    (b@host)1> net_adm:ping('a@host').
    pong

With a release, put it in `vm.args`:

    -proto_dist bouncer

## Noise handshake protocol

The handshake uses the Noise `XX` pattern. The `bouncer_protocol` module
defines the framing around the raw Noise handshake messages; it does not
parse or modify those messages. Integers in the wire format are unsigned and
big-endian.

The initiator chooses one suite and sends flight 1:

```erlang
<<"BNCR", 1:8, SuiteId:8, Msg1Len:16, Msg1:Msg1Len/binary>>
```

For XX with an empty first-message payload, `Msg1` is the 32-byte ephemeral
public key. The 8-byte hello header is the prefix through `Msg1Len`. The
initiator and responder both include that exact header and the target node
name in the Noise prologue:

```erlang
<<"bouncer/1", 0, HelloHeader:8/binary,
  TargetNameLen:16, TargetName/binary>>
```

The target name is a validated node name (3–255 bytes). Binding the header and
target into the prologue makes a change to either fail Noise authentication.

The responder replies with flight 2:

```erlang
<<"BNCR", 1:8, Status:8, Msg2Len:16, Msg2:Msg2Len/binary>>
```

Status `0` means success and carries the responder's raw Noise message 2.
Status `1` or `2` means rejection and has a zero message length. The
initiator sends flight 3 as a two-byte length followed by the raw Noise
message:

```erlang
<<Msg3Len:16, Msg3:Msg3Len/binary>>
```

The node name is encoded as `<<NameLen:16, Name/binary>>` inside the Noise
payloads of messages 2 and 3.

| Suite ID | Noise protocol name | Setting atom |
|---:|---|---|
| 1 | `Noise_XX_25519_ChaChaPoly_BLAKE2b` | `chachapoly_blake2b` |
| 2 | `Noise_XX_25519_AESGCM_SHA512` | `aesgcm_sha512` (default) |
| 3 | `Noise_XX_25519_AESGCM_SHA256` | `aesgcm_sha256` |
| 4 | `Noise_XX_25519_AESGCM_BLAKE2b` | `aesgcm_blake2b` |

Suite ID 2 is the default outgoing suite, and the default incoming
`accept_suites` list contains only `aesgcm_sha512`. Other suites must be
explicitly enabled in the accept list on both peers. There is no suite
negotiation or automatic fallback: a peer that does not accept the initiator's
chosen suite rejects the connection.

To migrate suites without interrupting connectivity:

1. Add the new suite to `accept_suites` on every node.
2. Switch each node's outgoing `suite` to the new suite.
3. Remove the old suite from `accept_suites` after all nodes have switched.


## Transport framing: frame format, flags, policies, defaults

After the handshake, `bouncer_protocol` provides pure functions (no sockets,
processes or application env) that turn dist packets into encrypted frames and
back, using the two enoise cipher states of the handshake. The carrier,
backpressure and tick timers are not part of this.

### Frame format

All integers are big-endian.

```erlang
%% wire
<<CipherLen:16, Ciphertext:CipherLen/binary>>   %% CipherLen 17..65535
%% plaintext inside the AEAD (associated data = the 2-byte CipherLen)
<<Flags:8, Rest/binary>>
```

The smallest frame is 1 flags byte plus the 16-byte tag, so the maximum
plaintext is 65519 bytes, and 65518 bytes of payload in an unpadded frame.

| Bit | Flag | Meaning |
|---:|---|---|
| 0 | `last` | last chunk of one dist packet |
| 1 | `tick` | keepalive; empty payload, no `comp`/`last` |
| 2 | `comp` | payload is the raw deflate of the original chunk |
| 3 | `pad` | `Rest = <<PadLen:16, Payload/binary, 0:PadLen/unit:8>>` instead of `Payload` |
| 4 | `rekey` | sender rekeys its send key after this frame; receiver rekeys its receive key after decrypting it |
| 5-7 | reserved | MUST be 0; a receiver closes on any set bit |

Sender order: split into chunks, compress each chunk, pad, encrypt. The frames
of one packet are contiguous on the wire (ticks may be interleaved).
The receiver requires `PadLen` to fit in the body (and zero padding bytes).
A dist packet is never empty (an empty one is a tick).

`erlang:dist_ctrl_put_data/2` hands exactly one call's data to the VM as one
complete distribution message (`erts/emulator/beam/dist.c`), so the receiver
needs the sender's packet boundaries: `last` marks them, and every
`{packet, Iodata}` event is one `dist_ctrl_put_data/2` call.

### API

```erlang
S0 = bouncer_protocol:new_sender(TxCipherState, SenderPolicy),
R0 = bouncer_protocol:new_receiver(RxCipherState, ReceiverPolicy),
P0 = bouncer_protocol:tx_packet(IoData),
{Frame, S1, more, P1} = bouncer_protocol:tx_next(S0, P0),   %% one frame per call
{Frame, S2, done}     = bouncer_protocol:tx_next(S1, P1),
{Frame, S3}           = bouncer_protocol:tx_tick(S2),
{ok, Events, R1}      = bouncer_protocol:rx_feed(R0, Bytes),  %% {packet, Iodata} | tick
{error, Reason, Dead} = bouncer_protocol:rx_feed(R1, Bytes).  %% close the connection
```

Errors: `decrypt_failed`, `bad_length`, `reserved_flags`, `tick_with_payload`,
`bad_padding`, `compression_not_accepted`, `bad_compression`,
`packet_too_large`, `rekey_required`, `rekey_unsupported`. A receiver that
returned an error refuses all further input.

### Policies and defaults

Settings are layered, highest first: Opts > `-bouncer` flag > env > default
(`bouncer_protocol:sender_policy/1` and `receiver_policy/1` take the layers as
maps; invalid values are rejected with an error naming the allowed values).

| Setting | Values | Default | Flag example |
|---|---|---|---|
| `chunk_size` | 1..65518 | 16384 | `-bouncer chunk_size 16384` |
| `padding` | `none`, `{bucket, N}` (round the plaintext up to a multiple of N, N <= 65519), `{fixed, N}` (every frame plaintext is N bytes, 4 <= N <= 65519; chunks are capped at N-3) | `none` | `-bouncer padding bucket:512` |
| `compression` | `none`, `{zlib, MinSize}` (chunks of at least MinSize bytes, only used if strictly smaller) | `none` | `-bouncer compression zlib:256` |
| `rekey_after` | `never` or any of `{frames, N}`, `{bytes, B}`, `{ms, T}` | `[{bytes, 1073741824}]` | `-bouncer rekey_after bytes:1073741824,ms:3600000` |
| `max_packet` (receiver) | bytes of one reassembled packet; checked while reassembling | 67108864 | `-bouncer max_packet N` |
| `accept_compression` (receiver) | `true`/`false` | `false` | `-bouncer accept_compression true` |
| `max_bytes_without_rekey` (receiver) | integer or `infinity` | `infinity` | |

Padded frames are always accepted. Ticks are padded like data. Inflation is
incremental with a hard 65518 byte limit. Keep compression off when
attacker-chosen data is mixed with secrets (CRIME/BREACH).

The distribution callback currently delegates to `inet_tcp_dist`; this
handshake protocol is not yet connected to the distribution transport.

Note: `bounce_dist` currently delegates to `inet_tcp_dist`; the Noise
transport is still to be implemented.
