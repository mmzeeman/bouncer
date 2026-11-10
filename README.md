# Bouncer Dist (WIP)

[![CI](https://github.com/mmzeeman/bouncer/actions/workflows/ci.yml/badge.svg)](https://github.com/mmzeeman/bouncer/actions/workflows/ci.yml)

Requires Erlang/OTP 26 or newer (tested on 26 and 27).

Erlang distribution over a Noise protocol transport, built on
[enoise](https://github.com/mmzeeman/enoise) (bugfix branch).

## Introduction

Bouncer secures Erlang/OTP distribution. Out of the box, Erlang nodes exchange
all distribution traffic — messages, process signals, RPCs, Mnesia
replication — over an unencrypted TCP connection. Bouncer replaces the
standard `inet_tcp` carrier with the [Noise protocol
framework](https://noiseprotocol.org/), giving the node-to-node channels of
an Erlang cluster end-to-end encryption and mutual authentication.

Each node owns a long-term key pair, generated and managed by `bouncer_keys`.
A connection between two nodes starts with a three-flight Noise `XX`
handshake, which exchanges and authenticates both identities: a node only
accepts peers whose public keys appear in its authorized directory, and
private keys never leave their node. The handshake header and the target
node name are bound into the Noise prologue, so any tampering with either
fails authentication. After the handshake, every distribution packet is
framed and AEAD-encrypted by `bouncer_protocol`, with optional compression
and padding and automatic rekeying.

Highlights:

- Drop-in carrier: enabled with `-proto_dist bouncer`; ordinary distribution
  features (RPC, `global`, Mnesia, monitors) work unchanged on top of it.
  Epmd is still used for name registration unless you replace it.
- Mutual public-key authentication without certificates or shared secrets.
- Tunable transport policy: chunk size, padding, compression, rekey
  intervals, and packet limits are all per-node settings.
- Automatic rekeying of the send key after a configured number of frames,
  bytes, or milliseconds.
- A benchmark harness, `tools/bouncer_bench`, that measures bouncer against
  plain `inet_tcp` and `inet_tls` for latency, throughput, and concurrent mailbox traffic.

## Setup: four nodes on four machines (alice, bob, carol, dave)

A walkthrough for a small cluster of four machines in the `example.com`
domain, one node per machine, using the `bouncer_guests` helper for all
key and authorization management:
   Machine | Node name |
 |---|---|
 | alice.example.com | `alice@alice.example.com` |
 | bob.example.com | `bob@bob.example.com` |
 | carol.example.com | `carol@carol.example.com` |
 | dave.example.com | `dave@dave.example.com` |

The host part of a node name is resolved and looked up through epmd, so
each machine's name must resolve (DNS or `/etc/hosts`). The walkthrough
builds a full mesh, but authorization is per node, so any subset of
peer authorizations works too.

`bouncer_guests` only edits the files that `bouncer_keys` reads at
handshake time; it never talks to a running node, and private keys never
leave their machine.

### 1. Install

Build once and copy the compiled libraries and the helper to each
machine:

    rebar3 compile
    rsync -a _build/default/lib/ alice.example.com:/opt/bouncer/lib/
    rsync -a tools/bouncer_guests alice.example.com:/usr/local/bin/

Repeat for bob, carol and dave. The escript needs the bouncer beams on
its code path; `ERL_LIBS=/opt/bouncer/lib` covers that.

### 2. Create the identity (on each machine)

    bouncer_guests init --node alice@alice.example.com \
        --dir /var/lib/bouncer/alice

This creates the key directory and the X25519 identity key (`id_x25519`,
mode 600; the directory mode 700), and prints this node's authorized
line and fingerprint:

    alice@alice.example.com <base64 public key>
    Fingerprint: SHA256:...

Without `--dir` the tool uses `$BOUNCER_DIR`, then the user config
directory. Repeat on bob, carol and dave with their own names and
directories. Use `--no-generate` to create only the directories.

### 3. Exchange and install the public lines

A node accepts a connection only when the peer's announced name and
public key match an entry in its authorized directories. For the full
mesh, every node needs the other three lines. Since `add` accepts the
exact output of `show --self` on stdin, a peer's line can be pulled
straight over ssh:

    ssh bob.example.com \
        bouncer_guests show --self --node bob@bob.example.com \
            --dir /var/lib/bouncer/bob \
    | bouncer_guests add - --dir /var/lib/bouncer/alice

Lines starting with `#` are ignored, so the tool's output can be piped
as is. On alice, repeat for carol and dave, then on every other machine
for its three peers:
 | On machine | authorized lines from |
 |---|---|
 | alice.example.com | bob, carol, dave |
 | bob.example.com | alice, carol, dave |
 | carol.example.com | alice, bob, dave |
 | dave.example.com | alice, bob, carol |

However the lines travel, verify them out-of-band: pass the expected
fingerprint and the command refuses to install a mismatching key (exit
code 4):

    bouncer_guests add --line 'bob@bob.example.com AAAA...' \
        --fingerprint SHA256:... --dir /var/lib/bouncer/alice

`--comment` records where an entry came from, and the guest list can be
inspected afterwards:

    bouncer_guests list --dir /var/lib/bouncer/alice
    bouncer_guests show bob@bob.example.com --dir /var/lib/bouncer/alice
    bouncer_guests check bob@bob.example.com SHA256:... \
        --dir /var/lib/bouncer/alice && echo verified

Authorization is per node and directional: leaving entries out restricts
who may connect, and both ends must authorize each other for a
connection to succeed.

### 4. Configure and start (on each machine)

Put the options in the release's `vm.args` (or pass them as `erl`
flags):

    -name alice@alice.example.com
    -proto_dist bouncer
    -bouncer dir /var/lib/bouncer/alice

`authorized_dirs` defaults to `<dir>/authorized.d`, which is where
`bouncer_guests` writes. The distribution port is chosen dynamically
and registered with epmd; pin it with the usual kernel options:

    -kernel inet_dist_listen_min 9100
    -kernel inet_dist_listen_max 9100

Only two ports must be reachable on each machine: epmd (TCP 4369) and
the distribution port. Bouncer encrypts and authenticates the
distribution channel itself, but epmd is plain and unauthenticated, so
restrict both ports to the cluster machines in the firewall.

### 5. Connect and verify

On alice:

    (alice@alice.example.com)1> net_adm:ping(bob@bob.example.com).
    pong
    (alice@alice.example.com)2> net_adm:ping(carol@carol.example.com).
    pong
    (alice@alice.example.com)3> net_adm:ping(dave@dave.example.com).
    pong
    (alice@alice.example.com)4> nodes().
    [bob@bob.example.com,carol@carol.example.com,dave@dave.example.com]

A peer that is not authorized answers `pang`: the responder rejects it
during the handshake.

### 6. Revoking a peer

Remove an entry whenever a peer must no longer be accepted:

    bouncer_guests remove carol@carol.example.com \
        --fingerprint SHA256:... --dir /var/lib/bouncer/alice

Revocation applies to new handshakes only; established connections stay
up until they are closed or the node restarts. To drop a live
connection, call `net_kernel:disconnect/1` on the node itself.

### Notes

- `bouncer_guests` never talks to a running node and never moves
  private keys: `id_x25519` stays on its machine, and `bouncer_keys`
  re-reads the authorized directories on every handshake, so changes
  apply to the next connection without a restart.
- Authorized directories and `.pub` files must not be writable by
  group or others; symlinks are refused.

## Build and boot-time code path

    rebar3 compile

`bouncer_dist` is loaded before applications start; it does not depend on the
`bouncer` application or application environment. Make `bouncer`, `enoise`, and
all dependencies available on the boot code path with `-pa` or `ERL_LIBS`.
For example, from the project directory:

    erl -pa _build/default/lib/*/ebin -proto_dist bouncer \
        -name a@127.0.0.1 \
        -bouncer dir /var/lib/bouncer/a \
        -bouncer authorized_dirs /var/lib/bouncer/a/authorized.d

The other node needs its own `dir` and authorized directory containing the
first node's public authorization line, and vice versa. Generate/export public
lines with `bouncer_keys`; never copy a private key between nodes.

The distribution module is `bouncer_dist`, selected with `-proto_dist bouncer`
(Erlang appends `_dist` to the name). The compiled beams must be in the code
path. Note that epmd is still used for name registration unless you
replace it.

With a release, put these options in `vm.args`:

    -proto_dist bouncer
    -bouncer dir /var/lib/bouncer/a
    -bouncer authorized_dirs /var/lib/bouncer/a/authorized.d

## Carrier settings

Values can be provided as `-bouncer Key Value` arguments or through matching
`BOUNCER_KEY` environment variables. Explicit options take precedence over
flags, flags over environment, and environment over defaults. Invalid values
make distribution startup fail with the setting name and accepted values.

The distribution module's `childspecs/0` starts `bouncer_dist_sup` under
`net_sup` before `net_kernel` and before applications are started. The supervisor
parses settings once from startup flags and environment without using the
`bouncer` application or application environment. Since the node name is not
available when its `bouncer_dist_config` child first starts, `listen/2` supplies
the name and the config process loads the corresponding key before opening the
listener. If the config process later restarts, it reloads the key for the
running node name without resetting the ETS settings.

Effective non-secret settings and the pending-handshake counters handle are
published as individual key/value entries in a public, read-concurrent ETS
table owned by the distribution supervisor. `bouncer_dist_config:get/1` retrieves
one value at a time; `connection_settings/0` assembles a connection snapshot
from individual ETS entries. Live ETS updates apply to new connections; existing
connections retain their initialized settings. Concurrent multi-key updates may
be observed partially. The key-info map, including the secret-key accessor, stays
only in the config process state and is fetched once per handshake; it is not
placed in ETS or the process dictionary. A missing table or unavailable config during
restart is treated as not-ready, so a handshake fails closed rather than using
empty or default options. The process is marked sensitive to limit tracing and
`process_info` exposure; this does not hide its state from `sys:get_state/1`.
Established connections are not children of the config supervisor and continue
using their already-initialized transport state; new handshakes require the
config child to supply key info.

This follows the `inet_tls_dist` startup pattern: the carrier exports
`childspecs/0`, the distribution supervisor starts before `net_kernel`, and
runtime readers consult ETS settings. The difference is that TLS
loads server/client settings from `-ssl_dist_optfile` in its supervisor, while
Bouncer combines `-bouncer` flags, `BOUNCER_*` values and defaults, then waits
until `listen/2` supplies the node name before loading the identity key.
Transport policy options include `chunk_size`, `padding`, `compression`,
`rekey_after`, `max_packet`, `accept_compression`, and
`max_bytes_without_rekey`. Carrier options are `handshake_timeout_ms` (5000),
`suite` (`aesgcm_sha512`), `accept_suites` (`aesgcm_sha512`),
`max_pending` (64), and `send_timeout_ms` (30000).

## Managing guests with bouncer_guests

`bouncer_guests` manages a node's key directory and its authorized directories
("guests" are the peers allowed to connect). It is a thin layer over
`bouncer_keys`. It only edits files in the key and authorized directories and
does not talk to a running node: no processes, no network, no distribution.
Secret key material is never printed.

Build (result: `_build/default/bin/bouncer_guests`):

    rebar3 escriptize

Usage: `bouncer_guests <command> [options]`. Global options:

    --dir DIR             node key directory (default: $BOUNCER_DIR, then the user config dir/NodeName)
    --authorized-dir DIR  authorized directory, repeatable; `add` writes to the first one
    --node NAME           this node's name (needed for the default directories)
    -q, --quiet           only print errors and the primary result value
    -h, --help

Without `--node`, `--dir` or `--authorized-dir` (or the matching `BOUNCER_*`
variables) must be given. Exit codes: 0 ok, 1 not found, 2 usage error
(including an invalid name, key or comment), 3 error (I/O, permissions, invalid
key file or refused directory), 4 fingerprint mismatch. Errors go to stderr.

**init** creates the key directory (0700) and authorized directory (0755), and
generates the identity key unless `--no-generate`. Idempotent; never loosens
existing permissions. Prints the authorized line and the fingerprint (with `-q`
only the line):

    $ bouncer_guests init --node a@host
    a@host VL6m3WhoKZLs0j95m230Xi/BBTHuBcr5/p93erEUuSI=
    # fingerprint SHA256:T9bHjMsbNZSPpp28o8nVzNhn4+E4W7yDoNB0aEs+c+E

**add** authorizes a peer. The fingerprint is always printed (with `-q` only
the fingerprint). With `--fingerprint FP` (with or without `SHA256:`) nothing is
written unless it matches (exit 4). Forms: `add NAME KEY [--comment TEXT]`,
`add --line "NAME KEY [comment]"`, and `add -` (one line from stdin; empty lines
and lines starting with `#` are ignored, so the output of `init` and
`show --self` can be piped in). Idempotent:

    $ bouncer_guests add b@host 6kDBh5adCE7obYJC2vl2JgJHnZ/1sSv4oIiOwq/m1Ss= --fingerprint SHA256:QKBOFWektI8E8mxkbWlXXhmDEim5fUXRFLQZ+iF7Kv8
    added
    name: b@host
    fingerprint: SHA256:QKBOFWektI8E8mxkbWlXXhmDEim5fUXRFLQZ+iF7Kv8
    file: /home/me/.config/bouncer/a@host/authorized.d/b@host.40a04e1567a4.pub

**remove** `NAME [--fingerprint FP | --all]` revokes a peer. With several keys
(rotation) and neither option it refuses (exit 2) and lists the fingerprints;
unknown name or fingerprint gives exit 1. Revocation applies to NEW handshakes;
established connections stay up until they are closed or the node restarts.

    $ bouncer_guests remove b@host
    removed b@host  SHA256:QKBOFWektI8E8mxkbWlXXhmDEim5fUXRFLQZ+iF7Kv8  /home/me/.config/bouncer/a@host/authorized.d/b@host.40a04e1567a4.pub

**show** `NAME` prints name, fingerprint, key, comment, file and directory of
each entry; `show --self --node NAME` prints this node's own line and
fingerprint and never creates a key (exit 1, run `init`, when there is none).

    $ bouncer_guests show b@host
    name: b@host
    fingerprint: SHA256:QKBOFWektI8E8mxkbWlXXhmDEim5fUXRFLQZ+iF7Kv8
    key: 6kDBh5adCE7obYJC2vl2JgJHnZ/1sSv4oIiOwq/m1Ss=
    comment: 
    file: /home/me/.config/bouncer/a@host/authorized.d/b@host.40a04e1567a4.pub
    directory: /home/me/.config/bouncer/a@host/authorized.d

**list** prints all entries sorted by name and fingerprint. Skipped files
(symlink, too large, malformed, loose permissions) are reported on stderr and
do not change the exit code; a refused directory (e.g. writable by group/other)
is exit 3.

    $ bouncer_guests list
    b@host  SHA256:QKBOFWektI8E8mxkbWlXXhmDEim5fUXRFLQZ+iF7Kv8  /home/me/.config/bouncer/a@host/authorized.d/b@host.40a04e1567a4.pub

**check** `NAME FINGERPRINT` verifies out of band: `ok` and exit 0 on a match,
exit 4 (printing the actual fingerprints) on a mismatch, exit 1 when the name
is unknown. Comparison is case-sensitive; the `SHA256:` prefix is optional.

Usual workflow:

1. Run `bouncer_guests init --node NAME` on both nodes.
2. Exchange the printed lines over a trusted channel and compare the
   fingerprints out of band.
3. On each node: `bouncer_guests add NAME KEY --fingerprint FP` (or pipe the
   line: `... | bouncer_guests add -`).
4. Later, `bouncer_guests check NAME FP` verifies what is authorized.
5. `bouncer_guests remove NAME` revokes (new handshakes only).

## Distribution benchmark

`tools/bouncer_bench` compares `inet_tcp`, `inet_tls` and `bouncer` using peer nodes on
localhost. It measures sequential RPC round-trip latency for small payloads
and one-way payload throughput for larger RPC requests. It also runs a
concurrent mailbox workload: multiple Erlang sender processes send ordinary
tuples with binary payloads to one remote process, which replies to each
message. Set `--mailbox-workers`, `--mailbox-messages`, and
`--mailbox-sizes` to adjust its concurrency and message mix. In that workload,
`latency_ms` is the mean request/acknowledgement round trip per message while
the senders run concurrently; throughput counts request payload bytes.

The same workload definitions and payload bytes are reused for the
`inet_tcp` reference and every bouncer configuration. The `random` payload
option selects deterministic, repeatable high-entropy bytes rather than
generating new random data for each run. Each bouncer result includes the
matching `inet_tcp` reference and percentage changes. The
`inet_tcp` reference is measured once per workload and reused across bouncer
configurations. The default matrix covers all four Noise suites, no
compression and two zlib thresholds, and three chunk sizes. Payloads are
compressible by default; use `--payload random` to measure incompressible data
instead.

Run it after checking out the project (the script builds the project and
benchmark worker first):

    tools/bouncer_bench --output benchmark.csv

`inet_tls` runs with a throwaway self-signed certificate (peer verification
off) and is reported relative to `inet_tcp`; bouncer rows additionally carry
`inet_tls_*` columns comparing them against `inet_tls`. Pass `--tls false` to
skip the TLS reference.

Use `--help` to see matrix and workload options. The worker reports one CSV row
per workload/configuration. It starts temporary peers and key directories,
then removes those directories on exit. Benchmark results are machine- and
load-dependent; compare runs on an otherwise idle host.

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

### Handshake API

`bouncer_hs:initiate(Socket, TargetName, Keys, Opts)` and
`bouncer_hs:respond(Socket, OwnName, Keys, Opts)` perform the three-flight
handshake on a connected `gen_tcp` socket. `Keys` is the map returned by
`bouncer_keys:load_or_generate/2`. Initiator options require `own_name`;
`suite` defaults to `aesgcm_sha512`, while responder `accept_suites` defaults
to `[aesgcm_sha512]`. `handshake_timeout_ms` defaults to 5000 and
`max_pending` defaults to 64. Other key-authorization options are passed to
`bouncer_keys:check_peer/3`.

Success returns `#{send := SendCipherState, recv := RecvCipherState,
remote_name := RemoteName, remote_key := RemotePublicKey, suite := Suite}`.
The socket stays open in binary, passive, raw-packet mode, ready for transport
framing. Pass `send` and `recv` to `bouncer_protocol:new_sender/2` and
`new_receiver/2`; the handshake does not construct transport state. The
initiator returns immediately after sending message 3, without waiting for
responder authorization of its identity. If the responder rejects message 3,
the initiator sees the closed socket on its next read.


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
%% sender
S0 = bouncer_protocol:new_sender(TxCipherState, SenderPolicy),
S1 = bouncer_protocol:tx_start(S0),
P0 = bouncer_protocol:tx_packet(IoData),
{Frame, S2, more, P1} = bouncer_protocol:tx_next(S1, P0),   %% one frame per call
{Frame, S3, done}     = bouncer_protocol:tx_next(S2, P1),
{Frame, S4}           = bouncer_protocol:tx_tick(S3),

%% receiver
R0 = bouncer_protocol:new_receiver(RxCipherState, ReceiverPolicy),
R1 = bouncer_protocol:rx_start(R0),
{ok, Events, R2}      = bouncer_protocol:rx_feed(R1, Bytes),  %% {packet, Iodata} | tick
{error, Reason, Dead} = bouncer_protocol:rx_feed(R2, Bytes).  %% close the connection
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
| `chunk_size` | 1..65518 | 65518 | `-bouncer chunk_size 16384` |
| `padding` | `none`, `{bucket, N}` (round the plaintext up to a multiple of N, N <= 65519), `{fixed, N}` (every frame plaintext is N bytes, 4 <= N <= 65519; chunks are capped at N-3) | `{bucket, 1400}` | `-bouncer padding bucket:512` |
| `compression` | `none`, `{zlib, MinSize}` (chunks of at least MinSize bytes, only used if strictly smaller) | `none` | `-bouncer compression zlib:256` |
| `rekey_after` | `never` or any of `{frames, N}`, `{bytes, B}`, `{ms, T}` | `[{bytes, 1073741824}]` | `-bouncer rekey_after bytes:1073741824,ms:3600000` |
| `max_packet` (receiver) | bytes of one reassembled packet; checked while reassembling | 67108864 | `-bouncer max_packet N` |
| `accept_compression` (receiver) | `true`/`false` | `false` | `-bouncer accept_compression true` |
| `max_bytes_without_rekey` (receiver) | integer or `infinity` | `infinity` | |

Padding limits the effective chunk size to `N - 3` for fixed padding and
`(65519 div N) * N - 3` for bucket padding, if smaller than `chunk_size`.
With the default bucket of 1400, the effective maximum is 64397 bytes.
Padded frames are always accepted. Ticks are padded like data. Inflation is
incremental with a hard 65518 byte limit. Keep compression off when
attacker-chosen data is mixed with secrets (CRIME/BREACH).
