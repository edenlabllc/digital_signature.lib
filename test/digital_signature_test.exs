defmodule DigitalSignatureLibTest do
  use ExUnit.Case
  doctest DigitalSignatureLib

  test "fail with incorrect data" do
    assert DigitalSignatureLib.processPKCS7Data([], %{general: [], tsp: []}, 1) == {:error, "pkcs7 data is incorrect"}
  end

  test "fail with empty data" do
    assert DigitalSignatureLib.processPKCS7Data(<<>>, %{general: [], tsp: []}, 1) == {:error, "pkcs7 data is empty"}
  end

  test "fail with incorrect signed data" do
    assert DigitalSignatureLib.processPKCS7Data(<<1>>, %{general: [], tsp: []}, 1) == {:error, "error loading signed data"}
  end

  @tag :pending
  test "real encoded data" do
    data = get_data("test/fixtures/sign1.json")
    signed_content = get_signed_content(data)

    assert {:ok, result} = DigitalSignatureLib.processPKCS7Data(signed_content, get_certs(), 1)

    assert result.is_valid == 1
    assert decode_content(result) == data["content"]
    assert result.signer == atomize_keys(data["signer"])
  end

  @tag :pending
  test "more real encoded data" do
    data = get_data("test/fixtures/sign2.json")
    signed_content = get_signed_content(data)

    assert {:ok, result} = DigitalSignatureLib.processPKCS7Data(signed_content, get_certs(), 1)

    assert result.is_valid == 1
    assert decode_content(result) == data["content"]
    assert result.signer == atomize_keys(data["signer"])
  end

  @tag :pending
  test "processign valid signed declaration" do
    data = get_data("test/fixtures/signed_decl_req.json")
    signed_content = get_signed_content(data)

    assert {:ok, result} = DigitalSignatureLib.processPKCS7Data(signed_content, get_certs(), 1)
    assert result.is_valid == 1
  end

  defp get_data(json_file) do
    file = File.read!(json_file)
    json = Poison.decode!(file)

    json["data"]
  end

  defp get_signed_content(data) do
    data["signed_content"]
    |> Base.decode64!()
  end

  defp get_certs do
    general = [
    %{
      root: File.read!("test/fixtures/CA-DFS.cer"),
      ocsp: File.read!("test/fixtures/CA-OCSP-DFS.cer")
    },
    %{
      root: File.read!("test/fixtures/CA-Justice.cer"),
      ocsp: File.read!("test/fixtures/OCSP-Server Justice.cer")
    },
  ]

  tsp = [
    File.read!("test/fixtures/CA-TSP-DFS.cer"),
    File.read!("test/fixtures/TSP-Server Justice.cer")
  ]

    %{general: general, tsp: tsp}
  end

  defp decode_content(result) do
    Poison.decode!(result.content)
  end

  defp atomize_keys(map) do
    map
    |> Enum.map(fn {k,v} -> {String.to_atom(k), v} end)
    |> Enum.into(%{})
  end
end
