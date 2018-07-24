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
    {:ok, data, checklist} = initPKCS7Data(signed_content, certs_map, check_value)
    IO.inspect(data)
    IO.inspect(checklist)
    {:ok, data}
  end
end
