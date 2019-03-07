#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "cs457_crypto.h"

/*
 * small demo to check function correctness
 */
int main(int argc, char **argv)
{
	int cipher_text_len, decrypted_text_len;
	unsigned int numberOfBlocks;
	unsigned char *key = (unsigned char *)"3DFFD7544A955E0580D2A67C7DC6E550";
	unsigned char plaintext[BUFLEN] = {0};
	unsigned char ciphertext[BUFLEN] = {0};
	unsigned char decryptedtext[BUFLEN] = {0};

	/* Variable initialization */
	cipher_text_len = decrypted_text_len = numberOfBlocks = 0;
	strncpy((char *)&plaintext, (char *)(unsigned char *)"This text is huge and needs more than 1 block", BUFLEN);

	/* Determine the number of blocks required for the whole plaintext */
	numberOfBlocks = (strlen((char *)&plaintext) < (AES_BS - 1)) ? 1 : (strlen((char *)&plaintext)) / (AES_BS - 1);

	printf("Plaintext lenght: %d / Block size: %d = Number of blocks: %d\n", (int)strlen((char *)&plaintext), AES_BS - 1, numberOfBlocks);
	/*----------------------------------------------Encrypt----------------------------------------------*/
	int plaintext_block_offset = 0;
	for (size_t i = 0; i < numberOfBlocks; i++)
	{

		cipher_text_len = aes_encrypt(plaintext + plaintext_block_offset, plaintext_block_offset + (AES_BS - 1), key, NULL, ciphertext + plaintext_block_offset + (1 * i), AES_128_ECB);
		printf("Block#%d (block offset: %d)\n:", (int)i + 1, plaintext_block_offset);
		print_hex(ciphertext, cipher_text_len);
		printf("Plaintext size: %d \n",
			   plaintext_block_offset + (AES_BS - 1));
		printf("Ciphertext len: %d\n", cipher_text_len);
		plaintext_block_offset += AES_BS - 1;
	}

	/*----------------------------------------------Decrypt----------------------------------------------*/
	int ciphertext_block_offset = 0;
	for (size_t i = 0; i < numberOfBlocks; i++)
	{
		decrypted_text_len = aes_decrypt(ciphertext + ciphertext_block_offset, ciphertext_block_offset + AES_BS, key, NULL, decryptedtext + ciphertext_block_offset - (1 * i), AES_128_ECB);
		ciphertext_block_offset += AES_BS;
	}

	decryptedtext[decrypted_text_len] = '\0';
	printf("Decrypted text :\n");
	printf("%s\n", decryptedtext);
	printf("Decrypted text lenght: %d\n", decrypted_text_len);

	return 0;
}

/* EOF */
