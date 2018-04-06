CFLAGS = -g -O3 -Wall -Wextra

ERLANG_PATH = $(shell erl -eval 'io:format("~s", [lists:concat([code:root_dir(), "/erts-", erlang:system_info(version), "/include"])])' -s init stop -noshell)
CFLAGS += -I$(ERLANG_PATH)
CFLAGS += -Ic_src
CFLAGS += -Ic_src/h
CFLAGS += -Lpriv -lUACryptoQ

LIB_NAME = priv/digital_signature_lib_nif.so
ifneq ($(CROSSCOMPILE),)
    # crosscompiling
    CFLAGS += -fPIC
else
    # not crosscompiling
    ifneq ($(OS),Windows_NT)
        CFLAGS += -fPIC

        ifeq ($(shell uname),Darwin)
            LDFLAGS += -dynamiclib -undefined dynamic_lookup
        endif
    endif
endif

NIF_SRC=\
	c_src/digital_signature_lib_nif.c \
	c_src/digital_signature_lib.c \
	c_src/is_utf8.c

all: $(LIB_NAME)

$(LIB_NAME): $(NIF_SRC)
	mkdir -p priv
	$(CC) $(CFLAGS) -shared $(LDFLAGS) $^ -o $@

clean:
	rm -f $(LIB_NAME)
	rm -rf $(LIB_NAME)*

.PHONY: all clean
