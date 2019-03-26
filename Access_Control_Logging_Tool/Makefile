CC = gcc
CSHAREDFLAGS =  -Wall -fPIC -shared -pedantic -std=gnu99 -g
CFLASG = -Wall -pedantic -std=gnu99 -g
SUFIX = -ldl -lssl -lcrypto

TARGETS = logger demo monitor

all: $(TARGETS)

monitor: monitor.c
	$(CC) $(CFLAGS)  $^ -o $@

demo: demo.c
	$(CC) $(CFLAGS)  $^ -o $@

logger: logger.c
	$(CC) $(CSHAREDFLAGS) $^ -o logger.so $(SUFIX)

clean:
	rm -f demo *.so  *.o monitor
