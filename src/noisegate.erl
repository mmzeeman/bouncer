
-module(noisegate).


-export([
    connections/0,
    
    is_noisegate_controller/1
]).

connections() ->
    [connection_info(Node, Entity) || {Node, Entity} <- erlang:system_info(dist_ctrl)].

connection_info(Node, Entity) ->
    #{ node => Node, 
       is_noisegate_controller => is_noisegate_controller(Entity)}.

%controller_info(Controller) ->
%    Ref = make_ref(),
%    Controller ! {info, Ref, self()},
%    receive
%        {Ref, Info} -> Info
%    after 1000 ->
%        timeout
%    end.

is_noisegate_controller(Pid) when is_pid(Pid) ->
    case erlang:process_info(Pid, initial_call) of
        {initial_call, {noisegate_dist, _, _}} ->
            true;
        _ ->
            false
    end;
is_noisegate_controller(_Entity) ->
    false.
