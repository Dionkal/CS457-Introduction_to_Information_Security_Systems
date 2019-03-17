#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#include "cs457_crypto.h"

/* error reporting helpers */
#define ERRX(ret, str)             \
	do                             \
	{                              \
		fprintf(stderr, str "\n"); \
		exit(ret);                 \
	} while (0)
#define ERR(ret, str)                                   \
	do                                                  \
	{                                                   \
		fprintf(stderr, str ": %s\n", strerror(errno)); \
		exit(ret);                                      \
	} while (0)

/* buffer size */
#define BUFLEN 2048

/* key files*/
#define AES_KF "keys/aes_key.txt"
#define S_PUB_KF "keys/srv_pub.pem"
#define S_PRV_KF "keys/srv_priv.pem"
#define C_PUB_KF "keys/cli_pub.pem"
#define C_PRV_KF "keys/cli_priv.pem"

/* AES block size */
#define AES_BS 16

/*Uncomment for verbose output*/
/*#define DEBUG*/

#define MERROR(str)          \
	do                       \
	{                        \
		printf("%s\n", str); \
		exit(EXIT_FAILURE);  \
	} while (0)

/* --------------------------- conversion helpers --------------------------- */

/*
 * converts half printable hex value to integer
 */
int half_hex_to_int(unsigned char c)
{
	if (isdigit(c))
		return c - '0';

	if ((tolower(c) >= 'a') && (tolower(c) <= 'f'))
		return tolower(c) + 10 - 'a';

	return 0;
}

/*
 * converts a printable hex array to bytes
 */
char *
hex_to_bytes(char *input)
{
	int i;
	char *output;

	output = NULL;
	if (strlen(input) % 2 != 0)
		ERRX(0, "reading hex string");

	output = calloc(strlen(input) / 2, sizeof(unsigned char));
	if (!output)
		ERRX(1, "h2b calloc");

	for (i = 0; i < strlen(input); i += 2)
	{
		output[i / 2] = ((unsigned char)half_hex_to_int(input[i])) *
							16 +
						((unsigned char)half_hex_to_int(input[i + 1]));
	}

	return output;
}

/*
 * Prints the hex value of the input
 * 16 values per line
 */
void print_hex(unsigned char *data, size_t len)
{
	size_t i;

	if (!data)
		printf("NULL data\n");
	else
	{
		for (i = 0; i < len; i++)
		{
			if (!(i % 16) && (i != 0))
				printf("\n");
			printf("%02X ", data[i]);
		}
		printf("\n");
	}
}

/* ----------------------------- key management ----------------------------- */

/*
 * retrieves an AES key from the key file
 */
unsigned char *aes_read_key(void)
{
	unsigned char *key = NULL;
	FILE *aes_key_file = fopen(AES_KF, "r");
	if (aes_key_file == NULL)
	{
		perror("fopen");
		exit(EXIT_FAILURE);
	}
	size_t key_size = 0;
	if (getline((char **)&key, &key_size, aes_key_file) < 0)
	{
		perror("getline");
		free(key);
		exit(EXIT_FAILURE);
	}

	fclose(aes_key_file);
	return key;
}

/*
 * retrieves an RSA key from the key file
 */
RSA *rsa_read_key(char *kfile, int isPublic)
{
	FILE *rsa_key_file = fopen(kfile, "rb");
	if (rsa_key_file == NULL)
	{
		perror("fopen ");
		exit(EXIT_FAILURE);
	}
	RSA *rsa_key = RSA_new();

	if (rsa_key == NULL)
	{
		perror("RSA new");
		exit(EXIT_FAILURE);
	}

	if (isPublic)
	{
		rsa_key = PEM_read_RSA_PUBKEY(rsa_key_file, &rsa_key, NULL, NULL);
		if (rsa_key == NULL)
		{
			printf("Error reading RSA public key from file %s\n", kfile);
			exit(EXIT_FAILURE);
		}
	}
	else
	{
		rsa_key = PEM_read_RSAPrivateKey(rsa_key_file, &rsa_key, NULL, NULL);
		if (rsa_key == NULL)
		{
			printf("Error reading RSA private key from file %s\n", kfile);
			exit(EXIT_FAILURE);
		}
	}

	return rsa_key;
}

/* ----------------------------- AES functions ------------------------------ */

/*
 * Segments the plaintext into blocks of AES_BS -1 size and performs AES 128 ecb
 */
int aes_ecb_block_encrypt(unsigned char *plaintext, int plaintext_length, unsigned char *key,
						  unsigned char *iv, unsigned char *ciphertext, unsigned int mode)
{
	unsigned int numberOfBlocks = 0;
	int plaintext_block_offset = 0;
	int cipher_text_len = 0;

	if (plaintext_length < 1)
		return -1;

	numberOfBlocks = (plaintext_length - 1) / (AES_BS);

	for (size_t i = 0; i <= numberOfBlocks; i++)
	{
		cipher_text_len = aes_encrypt(plaintext + plaintext_block_offset, plaintext_block_offset + (AES_BS - 1), key, NULL, ciphertext + plaintext_block_offset + (1 * i), mode);

#ifdef DEBUG
		printf("Block#%d (block offset: %d)\n:", (int)i + 1, plaintext_block_offset);
		print_hex(ciphertext, cipher_text_len);
		printf("Plaintext size: %d \n",
			   plaintext_block_offset + (AES_BS - 1));
		printf("Ciphertext len: %d\n", cipher_text_len);
#endif

		plaintext_block_offset += AES_BS - 1;
	}
	return numberOfBlocks;
}

/*
 * Segments the ciphertext into blocks of AES_BS size and decrypts AES 128 ecb to plaintext
 */
int aes_ecb_block_decrypt(unsigned char *ciphertext, int numberOfBlocks, unsigned char *key,
						  unsigned char *iv, unsigned char *plaintext, unsigned int mode)
{

	int ciphertext_block_offset = 0;
	int decrypted_text_len = 0;

	for (size_t i = 0; i <= numberOfBlocks; i++)
	{
		decrypted_text_len = aes_decrypt(ciphertext + ciphertext_block_offset, ciphertext_block_offset + AES_BS, key, NULL, plaintext + ciphertext_block_offset - (1 * i), mode);
		ciphertext_block_offset += AES_BS;
	}

#ifdef DEBUG
	plaintext[decrypted_text_len] = '\0';
	printf("Decrypted text :\n");
	printf("%s\n", plaintext);
	printf("Decrypted text lenght: %d\n", decrypted_text_len);
#endif
	return decrypted_text_len;
}

/*Function dispather for different modes of aes*/
const EVP_CIPHER *(*EncryptionFunctionDispatcher[])() = {EVP_aes_128_ecb, EVP_aes_128_cbc};

/*
 * encrypts the data with 128-bit AES ECB
 */
int aes_encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
				unsigned char *iv, unsigned char *ciphertext, unsigned int mode)
{
	EVP_CIPHER_CTX *ctx;

	int len;

	int ciphertext_len;

	/* Create and initialise the context */
	if (!(ctx = EVP_CIPHER_CTX_new()))
		return -1;

	/* Initialise the encryption operation */
	if (1 != EVP_EncryptInit_ex(ctx, (*EncryptionFunctionDispatcher[mode])(), NULL, key, iv))
		return -1;

	if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
		return -1;
	ciphertext_len = len;

	if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
		return -1;
	ciphertext_len += len;

	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);

	return ciphertext_len;
}

/*
 * decrypts the data and returns the plaintext size
 */
int aes_decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
				unsigned char *iv, unsigned char *plaintext, unsigned int mode)
{
	EVP_CIPHER_CTX *ctx;

	int len;

	int plaintext_len;

	/* Create and initialise the context */
	if (!(ctx = EVP_CIPHER_CTX_new()))
		return -1;

	/* Initialise the decryption operation */
	if (1 != EVP_DecryptInit_ex(ctx, (*EncryptionFunctionDispatcher[mode])(), NULL, key, iv))
		return -1;

	/* Provide the message to be decrypted, and obtain the plaintext output.
   * EVP_DecryptUpdate can be called multiple times if necessary
   */
	if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
		return -1;
	plaintext_len = len;

	/* Finalise the decryption. Further plaintext bytes may be written at
   * this stage.
   */
	if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
		return -1;
	plaintext_len += len;

	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);

	return plaintext_len;
}

/* ----------------------------- RSA functions ------------------------------ */

/*
 * RSA public key encryption
 */
int rsa_pub_encrypt(unsigned char *plaintext, int plaintext_len,
					RSA *key, unsigned char *ciphertext, int padding_mode)
{
	unsigned char intermediate_buf[BUFLEN] = {0};
	int length_1 = plaintext_len;
	int length_2 = 0;
	int result_1 = 0;
	int result_2 = 0;
	int result = 0;

	if (length_1 >= RSA_size(key))
	{
		length_1 = plaintext_len / 2;
		length_2 = plaintext_len - length_1;

		result_1 = RSA_public_encrypt(length_1, plaintext, intermediate_buf, key, padding_mode);
		if (result_1 != RSA_size(key))
			ERRX(-8, "Error after first  rsa_pub_encrypt: Bad cipher size");

#ifdef DEBUG
		printf("First %d bits of public encryption: %d\n", length_1, result_1);
		print_hex(intermediate_buf, result_1);
#endif

		result_2 = RSA_public_encrypt(length_2, plaintext + length_1, intermediate_buf + result_1, key, padding_mode);
		if (result_2 != RSA_size(key))
			ERRX(-8, "Error after second rsa_pub_encrypt: Bad cipher size");

#ifdef DEBUG
		printf("First plaintext %d bits of public encryption: %d\n", length_1, result_1);
		print_hex(intermediate_buf, result_1);
		printf("Second plaintext %d bits of public encryption: %d\n", length_2, result_2);
		print_hex(intermediate_buf + result_1, result_2);
#endif
		result = result_1 + result_2;
	}
	else
	{
		result = RSA_public_encrypt(plaintext_len, plaintext, intermediate_buf, key, padding_mode);
		if (result != RSA_size(key))
			ERRX(-8, "Error after rsa_pub_encrypt: Bad cipher size");
	}

	if (result < 0)
	{
		char *str = ERR_error_string(ERR_get_error(), NULL);
		MERROR(str);
	}

	ciphertext = (unsigned char *)memcpy((char *)ciphertext, (char *)intermediate_buf, result);

#ifdef DEBUG
	printf("--------------------------------------------Intermediate buffer--------------------------------------------\n");
	print_hex(intermediate_buf, result);
	printf("--------------------------------------------Ciphertext buffer--------------------------------------------\n");
	print_hex(ciphertext, result);
#endif
	memset(intermediate_buf, 0, BUFLEN);

	return result;
}

/*
 * RSA private key decryption
 */
int rsa_prv_decrypt(unsigned char *ciphertext, int ciphertext_len,
					RSA *key, unsigned char *plaintext, int padding_mode)
{
	unsigned char intermediate_buf[BUFLEN];
	int length_1 = ciphertext_len;
	int length_2 = 0;
	int result_1 = 0;
	int result_2 = 0;
	int result = 0;

	if (ciphertext_len >= 256)
	{
		length_1 = ciphertext_len / 2;
		length_2 = ciphertext_len - length_1;

		result_1 = RSA_private_decrypt(length_1, ciphertext, intermediate_buf, key, padding_mode);
#ifdef DEBUG
		printf("First %d bits of private decryption: %d\n", length_1, result_1);
		print_hex(intermediate_buf, result_1);
#endif

		result_2 = RSA_private_decrypt(length_2, ciphertext + length_1, intermediate_buf + result_1, key, padding_mode);
#ifdef DEBUG
		printf("First %d bits of private decryption: %d\n", length_1, result_1);
		print_hex(intermediate_buf, result_1);
		printf("Second %d bits of private decryption: %d\n", length_2, result_2);
		print_hex(intermediate_buf + result_1, result_2);
#endif
		result = result_1 + result_2;
	}
	else
	{
		result = RSA_private_decrypt(ciphertext_len, ciphertext, intermediate_buf, key, padding_mode);
	}
	if (result < 0)
		ERRX(-9, "Error at rsa_prv_decrypt: Decryption failed");

	plaintext = (unsigned char *)memcpy((char *)plaintext, (char *)intermediate_buf, BUFLEN);
	memset(intermediate_buf, 0, BUFLEN);

	return result;
}

/*
 * RSA private key encryption
 */
int rsa_prv_encrypt(unsigned char *plaintext, int plaintext_len,
					RSA *key, unsigned char *ciphertext, int padding_mode)
{
	if (plaintext_len > RSA_size(key) - 11)
		ERRX(-10, "Error at rsa_pub_priv_encrypt: plaintext length exceeds allowed value");

	int result = RSA_private_encrypt(plaintext_len, plaintext, ciphertext, key, padding_mode);

	if (result < 0)
	{
		char *str = ERR_error_string(ERR_get_error(), NULL);
		MERROR(str);
	}
	if (result != RSA_size(key))
		ERRX(-10, "Error after rsa_pub_priv_encrypt: Bad cipher size");
	return result;
}

/*
 * RSA public key decryption
 */
int rsa_pub_decrypt(unsigned char *ciphertext, int ciphertext_len,
					RSA *key, unsigned char *plaintext, int padding_mode)
{
	if (ciphertext_len != RSA_size(key))
		ERRX(-11, "Error rsa_pub_decrypt: Invalid cipher lenght");
	int result = RSA_public_decrypt(ciphertext_len, ciphertext, plaintext, key, padding_mode);

	if (result < 0)
		ERRX(-11, "Error rsa_pub_decrypt: Decryption failed");

	return result;
}

/*
 * RSA Public(Private) encryption
 */
int rsa_pub_priv_encrypt(unsigned char *plaintext, int plaintext_len,
						 RSA *pub_k, RSA *priv_k, unsigned char *ciphertext)
{
	int cipher_length = 0;

	cipher_length = rsa_prv_encrypt(plaintext, plaintext_len, priv_k, ciphertext, RSA_PKCS1_PADDING);

#ifdef DEBUG
	printf("Private encryption: %d\n", cipher_length);
	print_hex(ciphertext, cipher_length);
#endif

	cipher_length = rsa_pub_encrypt(ciphertext, cipher_length, pub_k, ciphertext, RSA_PKCS1_PADDING);

#ifdef DEBUG
	printf("Public encryption: %d\n", cipher_length);
	print_hex(ciphertext, cipher_length);
#endif

	return cipher_length;
}

/*
 * RSA Public(Private) decryption
 */
int rsa_pub_priv_decrypt(unsigned char *ciphertext, int ciphertext_len,
						 RSA *pub_k, RSA *priv_k, unsigned char *plaintext)
{
	int length = 0;

	length = rsa_prv_decrypt(ciphertext, ciphertext_len, priv_k, ciphertext, RSA_PKCS1_PADDING);
	// length = RSA_private_decrypt(ciphertext_len, ciphertext, ciphertext, priv_k, RSA_PKCS1_PADDING);

	if (length != RSA_size(priv_k))
		ERRX(-11, "Error at RSA_private_decrypt: decrypted lenght is incorrect");

#ifdef DEBUG
	printf("Private decryption: %d\n", length);
	print_hex(ciphertext, length);
#endif

	length = RSA_public_decrypt(length, ciphertext, plaintext, pub_k, RSA_PKCS1_PADDING);

	if (length < 0)
		ERRX(-11, "Error RSA_public_decrypt: Decryption failed");

#ifdef DEBUG
	printf("Public decryption: %d\n", length);
	printf("%s\n", plaintext);
#endif

	return length;
}

/* EOF */
