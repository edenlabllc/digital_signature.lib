CFLAGS = -fPIC -Wall -Wextra -Wno-unused-parameter -Wl,-undefined -Wl,dynamic_lookup -shared

ERLANG_PATH = $(shell erl -eval 'io:format("~s", [lists:concat([code:root_dir(), "/erts-", erlang:system_info(version), "/include"])])' -s init stop -noshell)
CFLAGS += -I$(ERLANG_PATH)

LIB_NAME = priv/digital_signature_lib_nif.so

NIF_SRC=c_src/digital_signature_lib_nif.c

all: $(LIB_NAME)

$(LIB_NAME): $(NIF_SRC)
	mkdir -p priv
	$(CC) $(CFLAGS) $^ -o $@

clean:
	rm -rf $(LIB_NAME)*

.PHONY: all clean