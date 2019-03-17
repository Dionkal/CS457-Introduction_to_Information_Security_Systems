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
	int plain_text_len, decrypted_text_len;
	unsigned char plaintext[BUFLEN] = {0};

	RSA *private_key1;
	RSA *private_key2;
	RSA *public_key1;
	RSA *public_key2;

	/* Variable initialization */
	decrypted_text_len = plain_text_len = 0;
	strncpy((char *)&plaintext, (char *)(unsigned char *)"hello_from_cs457", BUFLEN);
	plain_text_len = (int)strlen((const char *)plaintext);
	printf("Plaintext %d\n%s\n", plain_text_len, plaintext);
	private_key1 = rsa_read_key(C_PRV_KF, 0);
	public_key1 = rsa_read_key(C_PUB_KF, 1);

	private_key2 = rsa_read_key(S_PRV_KF, 0);
	public_key2 = rsa_read_key(S_PUB_KF, 1);

	unsigned char rsa_encryption[BUFLEN];
	/*----------------------------------------------Encrypt----------------------------------------------*/
	printf("----------------------------------------------Encrypt----------------------------------------------\n");
	decrypted_text_len = rsa_pub_priv_encrypt(plaintext, plain_text_len, public_key2, private_key1, rsa_encryption);
	printf("encrypted text lenght: %d\n", decrypted_text_len);
	/*----------------------------------------------Decrypt----------------------------------------------*/
	printf("----------------------------------------------Decrypt----------------------------------------------\n");
	memset(plaintext, 0, BUFLEN);
	decrypted_text_len = rsa_pub_priv_decrypt(rsa_encryption, decrypted_text_len, public_key1, private_key2, plaintext);
	printf("plaintext: \n\"%s\"\n", plaintext);
	return 0;
}

/* EOF */
