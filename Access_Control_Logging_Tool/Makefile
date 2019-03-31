CC = gcc
CSHAREDFLAGS =  -Wall -fPIC -shared -pedantic -std=gnu99 -g
CFLAGS = -Wall -pedantic -std=gnu99 -ggdb3
SUFIX = -ldl -lssl -lcrypto
RSUFIX = -lssl -lcrypto

TARGETS = logger demo monitor ransom

all: $(TARGETS)

monitor: monitor.c monitor_users.c monitor_file_history.c monitor_file_creation.c monitor_encrypted_files.c
	$(CC) $(CFLAGS)  $^ -o $@

demo: demo.c
	$(CC) $(CFLAGS)  $^ -o $@

logger: logger.c
	$(CC) $(CSHAREDFLAGS) $^ -o logger.so $(SUFIX)

ransom: ransomware/wannal4ugh.c
	$(CC) $(CFLAGS) ransomware/wannal4ugh.c -o wannal4ugh $(RSUFIX)

clean:
	rm -f demo *.so  *.o monitor
