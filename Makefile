
CC ?= gcc
CFLAGS = -O2 -Wall -Wwrite-strings -pedantic -std=gnu99
LFLAGS = 
SRCS = main.c server.c client.c utils.c log.c
BIN = auth_addrs

default: sodium

sodium:
	$(CC) $(CFLAGS) $(LFLAGS) -DSODIUM -lsodium $(SRCS) -o $(BIN)

nacl:
	$(CC) $(CFLAGS) $(LFLAGS) /usr/lib/libnacl.a $(SRCS) -o $(BIN)

install:
	-strip $(BIN)
	cp $(BIN) /usr/local/bin/

clean:
	rm -f $(BIN)
