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
	RSA *private_key;
	RSA *public_key;

	/* Variable initialization */
	cipher_text_len = decrypted_text_len = plain_text_len = 0;
	strncpy((char *)&plaintext, (char *)(unsigned char *)"This text is huge and needs more than 1 block", BUFLEN);
	plain_text_len = (int)strlen((const char *)plaintext);
	private_key = rsa_read_key(C_PRV_KF, 0);
	public_key = rsa_read_key(C_PUB_KF, 1);

	/*----------------------------------------------Encrypt----------------------------------------------*/
	cipher_text_len = rsa_prv_encrypt(plaintext, plain_text_len, private_key, ciphertext, RSA_PKCS1_PADDING);
	printf("Plaintext size: %d \t Ciphertext size: %d\n", plain_text_len, cipher_text_len);
	print_hex(ciphertext, cipher_text_len);

	decrypted_text_len = rsa_pub_encrypt(ciphertext, cipher_text_len, public_key, decryptedtext, RSA_PKCS1_PADDING);
	printf("Double Ciphertext size: %d\n", decrypted_text_len);
	print_hex(decryptedtext, decrypted_text_len);

	/*----------------------------------------------Decrypt----------------------------------------------*/
	/*decrypted_text_len = rsa_pub_decrypt(ciphertext, cipher_text_len, public_key, decryptedtext, RSA_PKCS1_PADDING);
	printf("Decrypted text (%d) is:\n", decrypted_text_len);
	printf("%s\n", decryptedtext);*/
	return 0;
}

/* EOF */
