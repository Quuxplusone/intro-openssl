CFLAGS += $(shell pkg-config --cflags openssl)
LDFLAGS += $(shell pkg-config --libs openssl)

all: nossl withssl

nossl: nossl.c
	$(CC) $(CFLAGS) -W -Wall -Wextra $^ $(LDFLAGS) -o $@

withssl: withssl.c
	$(CC) $(CFLAGS) -W -Wall -Wextra $^ $(LDFLAGS) -o $@

clean:
	rm -f nossl withssl

.PHONY: all clean
