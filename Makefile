ERL_INCLUDE_PATH=$(shell erl -eval 'io:format("~s~n", [lists:concat([code:root_dir(), "/erts-", erlang:system_info(version), "/include"])])' -s init stop -noshell)

all: priv/digital_signature_lib_nif.so

priv/digital_signature_lib_nif.so: src/digital_signature_lib_nif.c
	cc -fPIC -I$(ERL_INCLUDE_PATH) -dynamiclib -undefined dynamic_lookup -o priv/digital_signature_lib_nif.so src/digital_signature_lib_nif.c