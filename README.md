# bouncer

Erlang distribution over a Noise transport, built on
[enoise](https://github.com/aeternity/enoise) (master branch).

## Build

    rebar3 compile

## Using the `bounce` distribution protocol

The distribution module is `bounce_dist`, selected with `-proto_dist bounce`
(Erlang appends `_dist` to the name). The compiled beams must be in the code
path. Note that epmd is still used for name registration unless you
replace it.

Start two nodes from the project directory:

    rebar3 compile
    erl -pa _build/default/lib/*/ebin -proto_dist bounce -sname a
    erl -pa _build/default/lib/*/ebin -proto_dist bounce -sname b

Then from node `b`:

    (b@host)1> net_adm:ping('a@host').
    pong

With a release, put it in `vm.args`:

    -proto_dist bounce

Note: `bounce_dist` currently delegates to `inet_tcp_dist`; the Noise
transport is still to be implemented.
