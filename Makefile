CFLAGS += $(shell pkg-config --cflags openssl)
LDFLAGS += $(shell pkg-config --libs openssl)

all: nossl withssl NEW-withssl-2step NEW-withssl-buffered-3step

nossl: nossl.c
	$(CC) $(CFLAGS) -W -Wall -Wextra $^ $(LDFLAGS) -o $@

withssl: withssl.c
	$(CC) $(CFLAGS) -W -Wall -Wextra $^ $(LDFLAGS) -o $@

NEW-withssl-2step: NEW-withssl-2step.c
	$(CC) $(CFLAGS) -W -Wall -Wextra $^ $(LDFLAGS) -o $@

NEW-withssl-buffered-3step: NEW-withssl-buffered-3step.c
	$(CC) $(CFLAGS) -W -Wall -Wextra $^ $(LDFLAGS) -o $@

clean:
	rm -f nossl withssl NEW-withssl-2step

.PHONY: all clean
