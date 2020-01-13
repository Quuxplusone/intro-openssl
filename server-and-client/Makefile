CFLAGS += $(shell pkg-config --cflags openssl)
LDFLAGS += $(shell pkg-config --libs openssl)

all: ssl-server

ssl-server: ssl-server.c
	$(CC) $(CFLAGS) -W -Wall -Wextra -Wno-unused-parameter $^ $(LDFLAGS) -o $@

clean:
	rm -f ssl-server

.PHONY: all clean
