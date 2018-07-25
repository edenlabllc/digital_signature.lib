defmodule DigitalSignatureLib do
  @on_load {:init, 0}
  @moduledoc """
  Elixir implementation of pkcs7 data processing that uses uaCrypto library (ICAO version) via the NIF api.
  """

  def init do
    nif_path = :filename.join(priv_dir(), 'digital_signature_lib_nif')
    :ok = :erlang.load_nif(nif_path, 0)
  end

  def priv_dir do
    case :code.priv_dir(:digital_signature_lib) do
      {:error, _} ->
        :code.which(:digital_signature_lib)
        |> :filename.dirname()
        |> :filename.dirname()
        |> :filename.join('priv')

      path ->
        path
    end
  end

  def processPKCS7Data(_signed_content, _certs_map, _check_value), do: exit(:nif_not_loaded)

  def initPKCS7Data(_signed_content, _certs_map, _check_value), do: exit(:nif_not_loaded)

  def checkPKCS7Data(_signed_content), do: exit(:nif_not_loaded)

  def oscpPKCS7Data(signed_content, certs_map, check_value) do
    with {:ok, data = %{is_valid: true}, checklist} <- initPKCS7Data(signed_content, certs_map, check_value),
         {:ocsp, true, data} <-
           {:ocsp,
            Enum.all?(checklist, fn oscp_info ->
              with {:ok, %HTTPoison.Response{status_code: 200}} <-
                     HTTPoison.post(
                       oscp_info[:access],
                       oscp_info[:data],
                       [{"Content-Type", "application/ocsp-request"}],
                       timeout: 1000
                     ) do
                true
              else
                {:error, %HTTPoison.Error{reason: reason}} when reason in ~w(timeout connect_timeout)a ->
                  crl_sertificate_valid?(oscp_info)

                _ ->
                  false
              end
            end), data} do
      {:ok, data}
    else
      {:ocsp, false, data} ->
        {:ok, %{data | is_valid: false, validation_error_message: "OCSP certificate verificaton failed"}}

      error ->
        error
    end
  end

  def crl_sertificate_valid?(oscp_info) do
    false
  end
end
