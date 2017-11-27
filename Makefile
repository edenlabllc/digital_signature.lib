ERL_INCLUDE_PATH=$(shell erl -eval 'io:format("~s~n", [lists:concat([code:root_dir(), "/erts-", erlang:system_info(version), "/include"])])' -s init stop -noshell)

all: priv/digital_signature_lib_nif.so

priv/digital_signature_lib_nif.so: src/digital_signature_lib_nif.c
	cc -Wall -Wno-unused-parameter -Wl,-undefined -Wl,dynamic_lookup -shared -fPIC -I$(ERL_INCLUDE_PATH) src/digital_signature_lib_nif.c -o priv/digital_signature_lib_nif.so
