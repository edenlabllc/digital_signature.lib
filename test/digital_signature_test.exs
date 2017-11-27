defmodule DigitalSignatureLibTest do
  use ExUnit.Case
  doctest DigitalSignatureLib

  test "greets the world" do
    assert DigitalSignatureLib.hello() == :world
  end
end

# -module(digital_signature_lib_tests).

# -include_lib("eunit/include/eunit.hrl").

# some_test() ->
#     ?assertMatch({error, "pkcs7 data is empty"}, digital_signature_lib:processPKCS7Data([], #{general => [], tsp => []}, 1)),
#     ?assertMatch({ok, #{}}, digital_signature_lib:processPKCS7Data([<<1>>], #{general => [], tsp => []}, 1)).
