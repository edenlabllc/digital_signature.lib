defmodule DigitalSignatureLibTest do
  use ExUnit.Case
  doctest DigitalSignatureLib

  test "fail" do
    assert DigitalSignatureLib.processPKCS7Data([], %{general: [], tsp: []}, 1) == {:error, "pkcs7 data is empty"}
  end

  test "ok" do
    assert DigitalSignatureLib.processPKCS7Data([<<1>>], %{general: [], tsp: []}, 1) == {:ok, %{}}
  end
end

# -module(digital_signature_lib_tests).

# -include_lib("eunit/include/eunit.hrl").

# some_test() ->
#     ?assertMatch({error, "pkcs7 data is empty"}, digital_signature_lib:processPKCS7Data([], #{general => [], tsp => []}, 1)),
#     ?assertMatch({ok, #{}}, digital_signature_lib:processPKCS7Data([<<1>>], #{general => [], tsp => []}, 1)).
