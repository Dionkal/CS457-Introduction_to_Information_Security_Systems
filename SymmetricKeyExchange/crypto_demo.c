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
	unsigned char *key = NULL;
	unsigned char plaintext[BUFLEN] = {0};
	unsigned char ciphertext[BUFLEN] = {0};
	unsigned char decryptedtext[BUFLEN] = {0};

	/* Read key from file*/
	key = aes_read_key();

	/* Variable initialization */
	cipher_text_len = decrypted_text_len = numberOfBlocks = 0;
	strncpy((char *)&plaintext, (char *)(unsigned char *)"This text is huge and needs more than 1 block", BUFLEN);

	/*----------------------------------------------Encrypt----------------------------------------------*/
	rsa_prv_encrypt();
	/*----------------------------------------------Decrypt----------------------------------------------*/

	return 0;
}

/* EOF */
