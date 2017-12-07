defmodule DigitalSignatureLibTest do
  use ExUnit.Case
  doctest DigitalSignatureLib

  test "fail" do
    assert DigitalSignatureLib.processPKCS7Data([], %{general: [], tsp: []}, 1) == {:error, 'pkcs7 data is empty'}
  end

  test "ok" do
    assert {:ok, %{}} = DigitalSignatureLib.processPKCS7Data([<<1>>], %{general: [], tsp: []}, 1)
  end

  test "real encoded data" do
    signed_content = get_signed_content("test/fixtures/sign1.json")

    assert {:ok, data} = DigitalSignatureLib.processPKCS7Data(signed_content, get_certs(), 1)
    IO.inspect(data)
  end

  defp get_signed_content(json_file) do
    file = File.read!(json_file)
    json = Poison.decode!(file)

    :binary.bin_to_list(json["data"]["signed_content"])
  end

  defp get_certs do
    general = [
    %{
      root: :erlang.binary_to_list(File.read!("test/fixtures/CA-DFS.cer")),
      ocsp: :erlang.binary_to_list(File.read!("test/fixtures/CA-OCSP-DFS.cer"))
    },
    %{
      root: :erlang.binary_to_list(File.read!("test/fixtures/CA-Justice.cer")),
      ocsp: :erlang.binary_to_list(File.read!("test/fixtures/OCSP-Server Justice.cer"))
    },
  ]

  tsp = [
    :erlang.binary_to_list(File.read!("test/fixtures/CA-TSP-DFS.cer")),
    :erlang.binary_to_list(File.read!("test/fixtures/TSP-Server Justice.cer"))
  ]

    %{general: general, tsp: tsp}
  end
end
