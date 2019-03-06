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

	unsigned char *key = (unsigned char *)"3DFFD7544A955E0580D2A67C7DC6E550";
	unsigned char plaintext[BUFLEN];
	unsigned char ciphertext[BUFLEN];
	unsigned char decryptedtext[BUFLEN];

	strncpy((char *)&plaintext, (char *)((unsigned char *)"This is a large string that needs more blocks"), BUFLEN);

	/*----------------------------------------------Encrypt----------------------------------------------*/
	cipher_text_len = aes_encrypt(plaintext, strlen((const char *)&plaintext), key, NULL, ciphertext, AES_128_ECB);

	print_hex(ciphertext, cipher_text_len);
	printf("Plaintext size: %d \t Ciphertext size: %d\n", (int)strlen((const char *)&plaintext), (int)strlen((const char *)&ciphertext));
	printf("Ciphertext len: %d\n", cipher_text_len);

	/*----------------------------------------------Decrypt----------------------------------------------*/
	decrypted_text_len = aes_decrypt(ciphertext, cipher_text_len, key, NULL, decryptedtext, AES_128_ECB);
	decryptedtext[decrypted_text_len] = '\0';
	printf("Decrypted text (%d):\n", decrypted_text_len);
	printf("%s\n", decryptedtext);

	return 0;
}

/* EOF */
