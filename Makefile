
CC ?= gcc
CFLAGS = -O2 -Wall -Wwrite-strings -pedantic -std=gnu99
LFLAGS = 
SRCS = main.c server.c client.c utils.c log.c
BIN = auth_addrs

default: sodium

sodium:
	$(CC) $(CFLAGS) $(LFLAGS) -DSODIUM $(SRCS) -o $(BIN) -lsodium

nacl:
	$(CC) $(CFLAGS) $(LFLAGS) $(SRCS) -o $(BIN) -lnacl

install:
	-strip $(BIN)
	cp $(BIN) /usr/local/bin/

clean:
	rm -f $(BIN)
