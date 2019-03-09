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
	int cipher_text_len, decrypted_text_len, plain_text_len;
	unsigned char plaintext[BUFLEN] = {0};
	unsigned char ciphertext[BUFLEN] = {0};
	unsigned char decryptedtext[BUFLEN] = {0};
	RSA *private_key1;
	RSA *public_key2;

	RSA *private_key2;
	RSA *public_key1;

	/* Variable initialization */
	cipher_text_len = decrypted_text_len = plain_text_len = 0;
	strncpy((char *)&plaintext, (char *)(unsigned char *)"This text is huge and needs more than 1 block", BUFLEN);
	plain_text_len = (int)strlen((const char *)plaintext);
	private_key1 = rsa_read_key(C_PRV_KF, 0);
	public_key2 = rsa_read_key(C_PUB_KF, 1);

	private_key2 = rsa_read_key(S_PRV_KF, 0);
	public_key1 = rsa_read_key(S_PUB_KF, 1);

	/*----------------------------------------------Encrypt----------------------------------------------*/
	cipher_text_len = rsa_prv_encrypt(plaintext, plain_text_len, private_key1, ciphertext, RSA_PKCS1_PADDING);
	printf("Plaintext size: %d \t Ciphertext size: %d\n", plain_text_len, cipher_text_len);
	print_hex(ciphertext, cipher_text_len);

	decrypted_text_len = rsa_pub_encrypt(ciphertext, cipher_text_len, public_key2, decryptedtext, RSA_NO_PADDING);
	printf("Double Ciphertext size: %d\n", decrypted_text_len);
	print_hex(decryptedtext, decrypted_text_len);

	memset(plaintext, 0, BUFLEN);
	memset(ciphertext, 0, BUFLEN);
	plain_text_len = 0;
	cipher_text_len = 0;
	/*----------------------------------------------Decrypt----------------------------------------------*/

	printf("----------------------------------------------Decrypt----------------------------------------------\n");

	cipher_text_len = rsa_prv_decrypt(decryptedtext, decrypted_text_len, private_key2, ciphertext, RSA_NO_PADDING);
	printf("Server private decrypt: %d\n", cipher_text_len);
	print_hex(ciphertext, cipher_text_len);

	plain_text_len = rsa_pub_decrypt(ciphertext, cipher_text_len, public_key1, plaintext, RSA_PKCS1_PADDING);
	plaintext[plain_text_len] = '\0';

	printf("Server private decrypt: %d\n", plain_text_len);
	printf("%s\n", plaintext);
	return 0;
}

/* EOF */
