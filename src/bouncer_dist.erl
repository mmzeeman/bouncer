%% Distribution protocol module, selected with `-proto_dist bounce`.
%% Skeleton: delegates to inet_tcp_dist until the Noise transport is implemented.
-module(bouncer_dist).

-export([listen/1, listen/2, accept/1, accept_connection/5,
         setup/5, close/1, select/1, is_node_name/1]).

listen(Name) -> 
    logger:info(#{ text => <<"Listen">>, name => Name}),
    inet_tcp_dist:listen(Name).

listen(Name, Host) ->
    logger:info(#{ text => <<"Listen">>, name => Name, host => Host}),
    inet_tcp_dist:listen(Name, Host).

accept(Listen) ->
    logger:info(#{ text => <<"Accept">>, listen => Listen}),
    inet_tcp_dist:accept(Listen).

accept_connection(AcceptPid, Socket, MyNode, Allowed, SetupTime) ->
    logger:info(#{ text => <<"Accept Connection">>, args => [AcceptPid, Socket, MyNode, Allowed, SetupTime]}),
    inet_tcp_dist:accept_connection(AcceptPid, Socket, MyNode, Allowed, SetupTime).

setup(Node, Type, MyNode, LongOrShortNames, SetupTime) ->
    logger:info(#{ text => <<"Setup">>, args => [Node, Type, MyNode, LongOrShortNames, SetupTime]}),
    inet_tcp_dist:setup(Node, Type, MyNode, LongOrShortNames, SetupTime).

close(Listen) ->
    logger:info(#{ text => <<"Close">>, args => [Listen]}),
    inet_tcp_dist:close(Listen).

select(Node) ->
    logger:info(#{ text => <<"Select">>, args => [Node]}),
    inet_tcp_dist:select(Node).

is_node_name(Node) ->
    logger:info(#{ text => <<"Is Node Name">>, args => [Node]}),
    dist_util:is_node_name(Node).
