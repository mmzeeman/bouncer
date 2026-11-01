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


The distribution callback currently delegates to `inet_tcp_dist`; this
handshake protocol is not yet connected to the distribution transport.

Note: `bounce_dist` currently delegates to `inet_tcp_dist`; the Noise
transport is still to be implemented.

