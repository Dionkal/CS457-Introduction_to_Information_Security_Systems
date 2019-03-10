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
	int ciphertext_block_offset = 0;

	/* Read key from file*/
	key = aes_read_key();
	printf("AES key:%s\n", key);

	/* Variable initialization */
	decrypted_text_len = numberOfBlocks = 0;
	strncpy((char *)&plaintext, (char *)(unsigned char *)"HELLO Is it me you're looking for. Hello. This is a test. I repeat, this is a TEST", BUFLEN);
	plaintext_len = strlen((char *)&plaintext);

	/* Determine the number of blocks required for the whole plaintext */
	numberOfBlocks = (plaintext_len < (AES_BS - 1)) ? 0 : plaintext_len / AES_BS;

	/*----------------------------------------------Encrypt----------------------------------------------*/

	aes_ecb_block_encrypt(plaintext, plaintext_len, key, NULL, ciphertext, AES_128_ECB);

	/*----------------------------------------------Decrypt----------------------------------------------*/
	//aes_ecb_block_decrypt(ciphertext, ci);
	return 0;
}

/* EOF */
