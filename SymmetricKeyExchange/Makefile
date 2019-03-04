CC = gcc
CFLAGS =  -Wall -pedantic -g
LIBSSL = -lssl -lcrypto

TARGETS = server client demo

all: $(TARGETS)

server: Server/server.c cs457_crypto.c
	$(CC) $(CFLAGS) $(LIBSSL) $^ -o Server/server

client: Client/client.c cs457_crypto.c
	$(CC) $(CFLAGS) $(LIBSSL) $^ -o Client/client 

demo: crypto_demo.c cs457_crypto.o
	$(CC) $(CFLAGS) $(LIBSSL) $^ -o $@

clean:
	rm -f demo Server/server Client/client  *.o
