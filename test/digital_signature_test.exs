defmodule DigitalSignatureLibTest do
  use ExUnit.Case
  doctest DigitalSignatureLib

  test "fail with incorrect data" do
    assert DigitalSignatureLib.processPKCS7Data([], get_certs(), true)
      == {:error, "signed data argument is of incorrect type: must be Elixir string (binary)"}
  end

  test "fail with empty data" do
    {:ok, result} = DigitalSignatureLib.processPKCS7Data("", get_certs(), true)

    assert result.is_valid == false
    assert result.validation_error_message == "error processing signed data"
  end

  test "fail with incorrect signed data" do
    {:ok, result} = DigitalSignatureLib.processPKCS7Data("123", get_certs(), true)

    assert result.is_valid == false
    assert result.validation_error_message == "error processing signed data"
  end

  test "fails with correct signed data and without certs provided" do
    data = get_data("test/fixtures/sign1.json")
    signed_content = get_signed_content(data)

    {:ok, result} = DigitalSignatureLib.processPKCS7Data(signed_content, %{general: [], tsp: []}, true)

    assert result.is_valid == false
    assert result.validation_error_message == "matching ROOT certificate not found"
  end

  test "fails with correct signed data and only general certs provided" do
    data = get_data("test/fixtures/sign1.json")
    signed_content = get_signed_content(data)

    %{general: general, tsp: _tsp} = get_certs()

    {:ok, result} = DigitalSignatureLib.processPKCS7Data(signed_content, %{general: general, tsp: []}, true)

    assert result.is_valid == false
    assert result.validation_error_message == "matching TSP certificate not found"
  end

  test "fails with correct signed data and only tsp certs provided" do
    data = get_data("test/fixtures/sign1.json")
    signed_content = get_signed_content(data)

    %{general: _general, tsp: tsp} = get_certs()

    {:ok, result} = DigitalSignatureLib.processPKCS7Data(signed_content, %{general: [], tsp: tsp}, true)

    assert result.is_valid == false
    assert result.validation_error_message == "matching ROOT certificate not found"
  end

  test "real encoded data" do
    data = get_data("test/fixtures/sign1.json")
    signed_content = get_signed_content(data)

    assert {:ok, result} = DigitalSignatureLib.processPKCS7Data(signed_content, get_certs(), true)

    assert result.is_valid == true
    assert decode_content(result) == data["content"]
    assert result.signer == atomize_keys(data["signer"])
  end

  test "more real encoded data" do
    data = get_data("test/fixtures/sign2.json")
    signed_content = get_signed_content(data)

    assert {:ok, result} = DigitalSignatureLib.processPKCS7Data(signed_content, get_certs(), true)

    assert result.is_valid == true
    assert decode_content(result) == data["content"]
    assert result.signer == atomize_keys(data["signer"])
  end

  test "processign valid signed declaration" do
    data = get_data("test/fixtures/signed_decl_req.json")
    signed_content = get_signed_content(data)

    assert {:ok, result} = DigitalSignatureLib.processPKCS7Data(signed_content, get_certs(), true)
    assert result.is_valid == true
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
