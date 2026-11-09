-module(bouncer_sup).
-behaviour(supervisor).

-export([start_link/0, init/1]).

-spec start_link() -> {ok, pid()} | ignore | {error, term()}.
start_link() ->
    case init:get_argument(bouncer_dist_optfile) of
        {ok, [File]} ->
            DistOpts = [{key, todo}],
            TabOpts = [set, protected, named_table],
            Tab = ets:new(bouncer_dist_opts, TabOpts),
            true = ets:insert(Tab, DistOpts);
        {ok, BadArg} ->
            error({bad_bouncer_dist_optfile, BadArg});
        error ->
            skip
    end,

    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

-spec init([]) -> {ok, {supervisor:sup_flags(), [supervisor:child_spec()]}} | ignore.
init([]) ->
    {ok, {#{strategy => one_for_one, intensity => 1, period => 5}, []}}.
