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
	unsigned char rsa_encryption[BUFLEN] = {0};
	RSA *private_key1;
	RSA *private_key2;
	RSA *public_key1;
	RSA *public_key2;

	/* Variable initialization */
	decrypted_text_len = plain_text_len = 0;
	strncpy((char *)&plaintext, (char *)(unsigned char *)"I'm sitting here alone in darkness.\nWaiting to be free.\nLonely and forlorn I am crying.\nI long for my time to come.\nDeath means just life.\nPlease let me die in solitude", BUFLEN);
	plain_text_len = (int)strlen((const char *)plaintext);
	private_key1 = rsa_read_key(C_PRV_KF, 0);
	public_key1 = rsa_read_key(C_PUB_KF, 1);

	private_key2 = rsa_read_key(S_PRV_KF, 0);
	public_key2 = rsa_read_key(S_PUB_KF, 1);

	/*----------------------------------------------Encrypt----------------------------------------------*/
	printf("----------------------------------------------Encrypt----------------------------------------------\n");
	decrypted_text_len = rsa_pub_priv_encrypt(plaintext, plain_text_len, public_key2, private_key1, rsa_encryption);
	/*----------------------------------------------Decrypt----------------------------------------------*/
	printf("----------------------------------------------Decrypt----------------------------------------------\n");
	memset(plaintext, 0, BUFLEN);
	rsa_pub_priv_decrypt(rsa_encryption, decrypted_text_len, public_key1, private_key2, plaintext);
	return 0;
}

/* EOF */
