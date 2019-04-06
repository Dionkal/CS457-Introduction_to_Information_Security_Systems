#include "cs457_crypto.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <openssl/aes.h>

/* Uncomment the next line for more verbose output */
/* #define _DEBUG_ */

void decryptFile(char *in, char *out)
{
	unsigned char data[AES_BLOCK_SIZE];
	unsigned char encrypted_data[AES_BLOCK_SIZE];
	unsigned char *key = aes_read_key("aes_key.txt");
	// unsigned char *key = (unsigned char *)"3DFFD7544A955E0580D2A67C7DC6E550";

	AES_KEY dec_key;
	AES_set_decrypt_key(key, 32 * 8, &dec_key);

	FILE *fd_src = fopen(in, "r");
	if (fd_src == NULL)
	{
		char buf[BUFSIZ];
		sprintf(buf, "Error opening file: %s", in);
		perror(buf);

		return;
	}

#ifdef _DEBUG_
	printf("Opened source file: %s\n", in);
#endif

	FILE *fd_dest = fopen(out, "w");

	if (fd_dest == NULL)
	{
		char buf[BUFSIZ];
		sprintf(buf, "Error opening file: %s\n", out);
		perror(buf);
		return;
	}

#ifdef _DEBUG_
	printf("Opened destination file: %s\n", out);
#endif

	/* read from input file, encrypt the data and then write the encrypted
	 * data to the output file
	 */
	int enc_bytes;
	while ((enc_bytes = fread(encrypted_data, sizeof(unsigned char), AES_BLOCK_SIZE, fd_src)) != 0)
	{

		int bytes = aes_decrypt(encrypted_data, enc_bytes, key, NULL, data, AES_128_ECB);
		data[bytes] = '\0';
		fwrite(data, sizeof(unsigned char), bytes, fd_dest);

#ifdef _DEBUG_
		printf("READ %d bytes of cipher:\n", enc_bytes);
		print_hex(encrypted_data, enc_bytes);
		printf("Decrypted %d bytes\n", bytes);
		printf("Decrypted Data written:\n\"%s\"\n", data);
		printf("-------------------------------------\n");
#endif
		memset(encrypted_data, 0, AES_BLOCK_SIZE);
		memset(data, 'a', AES_BLOCK_SIZE);
	}
	printf("Decryption Completed!\n");

	/* clean up */
	fclose(fd_src);
	fclose(fd_dest);
	free(key);
}

int main(int argc, char **argv)
{
	int opt;

	char *input_file = NULL;
	char *output_file = NULL;

	while ((opt = getopt(argc, argv, "i:o:")) != -1)
	{
		switch (opt)
		{
		case 'i':
			input_file = malloc(sizeof(char) * (strlen(optarg) + 1));
			strncpy(input_file, optarg, strlen(optarg));
			printf("Input file: %s\n", input_file);
			break;
		case 'o':
			output_file = malloc(sizeof(char) * (strlen(optarg) + 1));
			strncpy(output_file, optarg, strlen(optarg));
			printf("Output file: %s\n", output_file);
			break;
		default:
			exit(EXIT_FAILURE);
		}
	}

	if (!input_file && !output_file)
		exit(EXIT_FAILURE);

	decryptFile(input_file, output_file);
}
