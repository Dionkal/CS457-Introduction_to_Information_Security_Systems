CC = gcc
CSHAREDFLAGS =  -Wall -fPIC -shared -pedantic -std=gnu99 -g
CFLAGS = -Wall -pedantic -std=gnu99 -ggdb3
SUFIX = -ldl -lssl -lcrypto
RSUFIX = -lssl -lcrypto

TARGETS = logger test monitor ransom decryptor

all: $(TARGETS)

monitor: monitor.c monitor_users.c monitor_file_history.c monitor_file_creation.c monitor_encrypted_files.c
	$(CC) $(CFLAGS) $(RSUFIX) $^ -o $@

test: tester.c
	$(CC) $(CFLAGS)  $^ -o $@

logger: logger.c
	$(CC) $(CSHAREDFLAGS) $^ -o logger.so $(SUFIX)

ransom: ransomware/wannal4ugh.c ransomware/cs457_crypto.c
	$(CC) $(CFLAGS) $(RSUFIX) ransomware/cs457_crypto.c ransomware/wannal4ugh.c -o ransomware/wannal4ugh

decryptor: ransomware/decryptor.c ransomware/cs457_crypto.c
	$(CC) $(CFLAGS) $(RSUFIX) ransomware/cs457_crypto.c ransomware/decryptor.c -o ransomware/decryptor

clean:
	rm -f test *.so  *.o monitor ransomware/wannal4ugh ransomware/*.o ransomware/decryptor
