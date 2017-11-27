defmodule DigitalSignatureLibTest do
  use ExUnit.Case
  doctest DigitalSignatureLib

  test "fail" do
    assert DigitalSignatureLib.processPKCS7Data([], %{general: [], tsp: []}, 1) == {:error, 'pkcs7 data is empty'}
  end

  test "ok" do
    assert {:ok, %{}} = DigitalSignatureLib.processPKCS7Data([<<1>>], %{general: [], tsp: []}, 1)
  end
end
