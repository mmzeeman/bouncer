-module(noisegate_source_tests).

-include_lib("eunit/include/eunit.hrl").

no_persistent_term_in_source_test() ->
    Files = filelib:wildcard("src/*.erl"),
    ?assert(Files =/= []),
    lists:foreach(
      fun(File) ->
              {ok, Source} = file:read_file(File),
              ?assertEqual(nomatch, binary:match(Source, <<"persistent_term">>))
      end, Files).
