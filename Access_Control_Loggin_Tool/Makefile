CC = gcc
CSHAREDFLAGS =  -Wall -fPIC -shared -pedantic -std=gnu99 -g
CFLASG = -Wall -pedantic -std=gnu99 -g
SUFIX = -ldl


TARGETS = logger demo

all: $(TARGETS)

demo: demo.c
	$(CC) $(CFLAGS)  $^ -o $@

logger: logger.c
	$(CC) $(CSHAREDFLAGS) $^ -o logger.so $(SUFIX)

clean:
	rm -f demo *.so  *.o
