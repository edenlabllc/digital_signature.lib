CFLAGS = -g -Wall -fPIC -MMD -shared

ERLANG_PATH = $(shell erl -eval 'io:format("~s", [lists:concat([code:root_dir(), "/erts-", erlang:system_info(version), "/include"])])' -s init stop -noshell)
CFLAGS += -I$(ERLANG_PATH)

LIB_NAME = priv/digital_signature_lib_nif.so

NIF_SRC=c_src/digital_signature_lib_nif.c c_src/digital_signature_lib.c

all: priv/digital_signature_lib_nif.so

$(LIB_NAME): $(NIF_SRC)
	mkdir -p priv
	cc $(CFLAGS) $^ -o $@

clean:
	rm -rf $(LIB_NAME)*

.PHONY: all clean