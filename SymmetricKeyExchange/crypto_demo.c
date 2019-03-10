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
	int plaintext_len, decrypted_text_len;
	unsigned int numberOfBlocks;
	unsigned char *key = NULL;
	unsigned char plaintext[BUFLEN] = {0};
	unsigned char ciphertext[BUFLEN] = {0};
	unsigned char decryptedtext[BUFLEN] = {0};
	// int plaintext_block_offset = 0;

	/* Read key from file*/
	key = aes_read_key();
	printf("AES key:%s\n", key);

	/* Variable initialization */
	decrypted_text_len = numberOfBlocks = 0;
	strncpy((char *)&plaintext, (char *)(unsigned char *)"hello", BUFLEN);
	plaintext_len = strlen((char *)&plaintext);

	/* Determine the number of blocks required for the whole plaintext */

	/*----------------------------------------------Encrypt----------------------------------------------*/

	numberOfBlocks = aes_ecb_block_encrypt(plaintext, plaintext_len, key, NULL, ciphertext, AES_128_ECB);

	printf("After Block encrypt, numberOfBlocks: %d\n", numberOfBlocks);

	/*----------------------------------------------Decrypt----------------------------------------------*/
	decrypted_text_len = aes_ecb_block_decrypt(ciphertext, numberOfBlocks, key, NULL, decryptedtext, AES_128_ECB);

	printf("After Block decrypt, decrypted text length: %d\n", decrypted_text_len);

	return 0;
}

/* EOF */
