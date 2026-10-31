%% End-to-end test: two nodes connected through bouncer_dist.
-module(bouncer_dist_SUITE).
-include_lib("common_test/include/ct.hrl").

-export([all/0, init_per_suite/1, end_per_suite/1]).
-export([connect/1, rpc_roundtrip/1, message_exchange/1]).

all() -> [connect, rpc_roundtrip, message_exchange].

init_per_suite(Config) ->
    os:cmd("epmd -daemon"),
    %% peer requires the controlling node to be alive (default tcp dist is fine here).
    case node() of
        nonode@nohost -> {ok, _} = net_kernel:start([bouncer_ct, shortnames]);
        _ -> ok
    end,
    {ok, PeerA, NodeA} = start_peer(bouncer_a),
    {ok, PeerB, NodeB} = start_peer(bouncer_b),
    [{peer_a, PeerA}, {node_a, NodeA}, {peer_b, PeerB}, {node_b, NodeB} | Config].

end_per_suite(Config) ->
    peer:stop(?config(peer_a, Config)),
    peer:stop(?config(peer_b, Config)),
    ok.

connect(Config) ->
    A = ?config(node_a, Config),
    B = ?config(node_b, Config),
    true = rpc:call(A, net_kernel, connect_node, [B]),
    true = lists:member(B, rpc:call(A, erlang, nodes, [])),
    true = lists:member(A, rpc:call(B, erlang, nodes, [])),
    {ok, [["bouncer"]]} = rpc:call(A, init, get_argument, [proto_dist]),
    ok.

rpc_roundtrip(Config) ->
    A = ?config(node_a, Config),
    B = ?config(node_b, Config),
    <<"hello">> = rpc:call(A, rpc, call, [B, erlang, list_to_binary, ["hello"]]),
    ok.

message_exchange(Config) ->
    A = ?config(node_a, Config),
    B = ?config(node_b, Config),
    Self = self(),
    %% Echo process on B, registered so A can address it by {Name, Node}.
    Echo = fun F() ->
               receive {From, Msg} -> From ! {echo, Msg}, F() end
           end,
    Pid = rpc:call(B, erlang, spawn, [Echo]),
    true = rpc:call(B, erlang, register, [bouncer_echo, Pid]),
    Payload = crypto:strong_rand_bytes(64 * 1024),
    %% A sends from a process on A and reports what it receives back.
    rpc:call(A, erlang, spawn, [fun() ->
        {bouncer_echo, B} ! {self(), Payload},
        receive {echo, Reply} -> Self ! {reply, Reply} after 5000 -> Self ! timeout end
    end]),
    receive
        {reply, Payload} -> ok;
        Other -> ct:fail({unexpected, Other})
    after 10000 -> ct:fail(no_reply)
    end.

start_peer(Name) ->
    Pa = lists:append([["-pa", P] || P <- code:get_path()]),
    {ok, Peer, Node} = peer:start(#{
        name => peer:random_name(atom_to_list(Name)),
        args => ["-proto_dist", "bouncer", "-start_epmd", "false"] ++ Pa
    }),
    {ok, Peer, Node}.
