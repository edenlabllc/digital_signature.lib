defmodule DigitalSignatureLibTest do
  use ExUnit.Case, async: false

  describe "Must process all data correctly with all certs provided" do
    test "fail with incorrect data" do
      assert DigitalSignatureLib.processPKCS7Data([], get_certs(), true)
        == {:error, "signed data argument is of incorrect type: must be Elixir string (binary)"}
    end

    test "fail with empty data" do
      {:ok, result} = DigitalSignatureLib.processPKCS7Data("", get_certs(), true)

      refute result.is_valid
      assert result.validation_error_message == "error processing signed data"
    end

    test "fails with incorrect signed data" do
      {:ok, result} = DigitalSignatureLib.processPKCS7Data("123", get_certs(), true)

      refute result.is_valid
      assert result.validation_error_message == "error processing signed data"
      assert result.content == "";
    end

    test "fails with complex incorrect signed data" do
      data = get_data("test/fixtures/incorrect_signed_data.json")
      signed_content = get_signed_content(data)

      assert {:ok, result} = DigitalSignatureLib.processPKCS7Data(signed_content, get_certs(), true)

      refute result.is_valid
      assert result.validation_error_message == "error processing signed data"
    end

    test "can process signed legal entity" do
      data = get_data("test/fixtures/signed_le1.json")
      signed_content = get_signed_content(data)

      assert {:ok, result} = DigitalSignatureLib.processPKCS7Data(signed_content, get_certs(), true)

      assert result.is_valid
      assert decode_content(result) == data["content"]
      assert result.signer == atomize_keys(data["signer"])
    end

    test "can process second signed legal entity" do
      data = get_data("test/fixtures/signed_le2.json")
      signed_content = get_signed_content(data)

      assert {:ok, result} = DigitalSignatureLib.processPKCS7Data(signed_content, get_certs(), true)

      assert result.is_valid
      assert decode_content(result) == data["content"]
      assert result.signer == atomize_keys(data["signer"])
    end

    test "processing valid signed declaration" do
      data = get_data("test/fixtures/signed_decl_req.json")
      signed_content = get_signed_content(data)

      assert {:ok, result} = DigitalSignatureLib.processPKCS7Data(signed_content, get_certs(), true)
      assert result.is_valid
    end

    test "can validate data signed with invalid Privat personal key" do
      data = File.read!("test/fixtures/hello_invalid.txt.sig")

      assert {:ok, result} = DigitalSignatureLib.processPKCS7Data(data, get_certs(), true)
      refute result.is_valid
      assert result.validation_error_message == "OCSP certificate verificaton failed"
    end

    test "can validate data signed with valid Privat personal key" do
      data = File.read!("test/fixtures/hello.txt.sig")

      assert {:ok, result} = DigitalSignatureLib.processPKCS7Data(data, get_certs(), true)
      assert result.is_valid
      assert result.content == "{\"hello\": \"world\"}"
    end
  end

  describe "Must process all data or fail correclty when certs no available or available partially" do
    test "fails with correct signed data and without certs provided" do
      data = get_data("test/fixtures/signed_le1.json")
      signed_content = get_signed_content(data)

      {:ok, result} = DigitalSignatureLib.processPKCS7Data(signed_content, %{general: [], tsp: []}, true)

      refute result.is_valid
      assert result.validation_error_message == "matching ROOT certificate not found"
    end

    test "fails with correct signed data and only General certs provided" do
      data = get_data("test/fixtures/signed_le1.json")
      signed_content = get_signed_content(data)

      %{general: general, tsp: _tsp} = get_certs()

      {:ok, result} = DigitalSignatureLib.processPKCS7Data(signed_content, %{general: general, tsp: []}, true)

      refute result.is_valid
      assert result.validation_error_message == "matching TSP certificate not found"
    end

    test "fails with correct signed data and only TSP certs provided" do
      data = get_data("test/fixtures/signed_le1.json")
      signed_content = get_signed_content(data)

      %{general: _general, tsp: tsp} = get_certs()

      {:ok, result} = DigitalSignatureLib.processPKCS7Data(signed_content, %{general: [], tsp: tsp}, true)

      refute result.is_valid
      assert result.validation_error_message == "matching ROOT certificate not found"
    end

    test "Validates signed data with only ROOT certs provided" do
      data = get_data("test/fixtures/signed_le1.json")
      signed_content = get_signed_content(data)

      general = [
        %{
          root: File.read!("test/fixtures/CA-DFS.cer"),
          ocsp: File.read!("test/fixtures/CA-OCSP-DFS.cer")
        }
      ]

      tsp = [
        File.read!("test/fixtures/CA-TSP-DFS.cer"),
        File.read!("test/fixtures/TSP-Server Justice.cer")
      ]

      {:ok, result} = DigitalSignatureLib.processPKCS7Data(signed_content, %{general: general, tsp: tsp}, true)

      assert result.is_valid
      assert decode_content(result) == data["content"]
      assert result.signer == atomize_keys(data["signer"])
    end

    test "can validate data with invalid entries in siganture_info" do
      data = get_data("test/fixtures/invalid_sign_entries.json")
      signed_content = get_signed_content(data)

      assert {:ok, result} = DigitalSignatureLib.processPKCS7Data(signed_content, get_certs(), true)
      refute result.is_valid
      assert result.validation_error_message == "matching ROOT certificate not found"
    end
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
    %{
      root: File.read!("test/fixtures/CA-3004751DEF2C78AE010000000100000049000000.cer"),
      ocsp: File.read!("test/fixtures/CAOCSPServer-D84EDA1BB9381E802000000010000001A000000.cer")
    },
    %{
      root: File.read!("test/fixtures/cert1599998-root.crt"),
      ocsp: File.read!("test/fixtures/cert14493930-oscp.crt")
    }
  ]

  tsp = [
    File.read!("test/fixtures/CA-TSP-DFS.cer"),
    File.read!("test/fixtures/TSP-Server Justice.cer"),
    File.read!("test/fixtures/CATSPServer-3004751DEF2C78AE02000000010000004A000000.cer"),
    File.read!("test/fixtures/cert14491837-tsp.crt")
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
