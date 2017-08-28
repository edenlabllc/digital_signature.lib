-module(digital_signature_lib).

-on_load(load_nif/0).

-export([processPKCS7Data/3]).

-spec processPKCS7Data(list(), map(), integer()) -> tuple().
processPKCS7Data(_pkcs7_data, _certs, _check) -> erlang:nif_error(not_loaded).

load_nif() ->
  {ok, Path} = init:get_argument(home),
  file:copy(filename:join(code:priv_dir(digital_signature_lib), "libUACryptoQ.so"), filename:join(Path, "libUACryptoQ.so")),
  erlang:load_nif(filename:join(code:priv_dir(digital_signature_lib), "digital_signature_lib"), 0).
