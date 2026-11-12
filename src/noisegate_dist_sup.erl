-module(noisegate_dist_sup).
-behaviour(supervisor).

-export([childspecs/0, start_link/0, init/1]).

childspecs() ->
    {ok, [#{id => ?MODULE,
            start => {?MODULE, start_link, []},
            restart => permanent,
            shutdown => infinity,
            type => supervisor,
            modules => [?MODULE]}]}.

start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

init([]) ->
    _ = noisegate_dist_config:create_config_table(),
    case noisegate_dist_config:load_settings() of
        ok ->
            child_specs();
        {error, Reason} ->
            exit({invalid_settings, Reason})
    end.

child_specs() ->
    Config = #{id => noisegate_dist_config,
               start => {noisegate_dist_config, start_link, []},
               restart => permanent,
               shutdown => 5000,
               type => worker,
               modules => [noisegate_dist_config]},
    {ok, {#{strategy => one_for_one, intensity => 10, period => 3600},
          [Config]}}.
