CFLAGS = -fPIC  -Wall -Wextra -Wno-unused-parameter -Wl,-undefined -Wl,dynamic_lookup -shared

ERL_INCLUDE_PATH=$(shell erl -eval 'io:format("~s~n", [lists:concat([code:root_dir(), "/erts-", erlang:system_info(version), "/include"])])' -s init stop -noshell)
CFLAGS += -I$(ERL_INCLUDE_PATH)
CFLAGS += -Ic_src

.PHONY: all clean

all: priv/digital_signature_lib_nif.so

priv/digital_signature_lib_nif.so: c_src/digital_signature_lib_nif.c
	cc $(CFLAGS) -o priv/digital_signature_lib_nif.so c_src/digital_signature_lib_nif.c

clean:
	rm -f priv/digital_signature_lib_nif.so
