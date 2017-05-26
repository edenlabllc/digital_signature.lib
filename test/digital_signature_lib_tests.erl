-module(digital_signature_lib_tests).

-include_lib("eunit/include/eunit.hrl").

some_test() ->
    ?assertMatch({error, "pkcs7 data is empty"}, digital_signature_lib:processPKCS7Data([], #{general => [], tsp => []})),
    ?assertMatch({ok, #{}}, digital_signature_lib:processPKCS7Data([<<1>>], #{general => [], tsp => []})).
