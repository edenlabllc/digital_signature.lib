defmodule DigitalSignatureLib.MixProject do
  use Mix.Project

  def project do
    [
      app: :digital_signature_lib,
      version: "1.1.0",
      elixir: "~> 1.5",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      compilers: [:make] ++ Mix.compilers,
      aliases: aliases()
     ]
  end

  defp aliases do
    # Make `mix clean` also run `make clean`
    [clean: ["clean.make", "clean"]]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [ ]
  end
end

# mix compile.make
defmodule Mix.Tasks.Compile.Make do
  def run(_) do
    # We just run `make`
    {result, _error_code} = System.cmd("make", [], stderr_to_stdout: true)
    Mix.shell.info result

    :ok
  end
end

# mix clean.make
defmodule Mix.Tasks.Clean.Make do
  def run(_) do
    {result, _error_code} = System.cmd("make", ["clean"], stderr_to_stdout: true)
    Mix.shell.info result

    :ok
  end
end
