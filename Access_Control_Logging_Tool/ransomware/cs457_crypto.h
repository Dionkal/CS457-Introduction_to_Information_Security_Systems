#ifndef _CS457_CRYPTO_H_
#define _CS457_CRYPTO_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/err.h>

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

/*Encryption types*/
#define AES_128_ECB 0
#define AES_128_CBC 1

/* key exchange init info */
#define INIT_MSG "hello"
#define INIT_MSG_LEN 5
#define INIT_MSG_LEN_CT 512

/* --------------------------- conversion helpers --------------------------- */

/*
 * converts a printable hex array to bytes
 *
 */
char *
hex_to_bytes(char *input);

/*
 * Prints the hex value of the input
 * 16 values per line
 */
void print_hex(unsigned char *data, size_t len);

/* ----------------------------- key management ----------------------------- */

/*
 * retrieves an AES key from the key file
 */
unsigned char *aes_read_key(char *);

/*
 * retrieves an RSA key from the key file
 */
RSA *rsa_read_key(char *kfile, int isPublic);

/* ----------------------------- AES functions ------------------------------ */

/*
 * Segments the plaintext into blocks of AES_BS -1 size and performs AES 128 ecb
 */
int aes_ecb_block_encrypt(unsigned char *plaintext, int plaintext_length, unsigned char *key,
                          unsigned char *iv, unsigned char *ciphertext, unsigned int mode);

/*
 * Segments the ciphertext into blocks of AES_BS size and decrypts AES 128 ecb to plaintext
 */
int aes_ecb_block_decrypt(unsigned char *ciphertext, int numberOfBlocks, unsigned char *key,
                          unsigned char *iv, unsigned char *plaintext, unsigned int mode);

/*
 * encrypts the data with 128-bit AES ECB
 */
int aes_encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
                unsigned char *iv, unsigned char *ciphertext, unsigned int mode);

/*
 * decrypts the data and returns the plaintext size
 */
int aes_decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
                unsigned char *iv, unsigned char *plaintext, unsigned int mode);

/* ----------------------------- RSA functions ------------------------------ */

/*
 * RSA public key encryption
 */
int rsa_pub_encrypt(unsigned char *plaintext, int plaintext_len,
                    RSA *key, unsigned char *ciphertext, int padding_mode);

/*
 * RSA private key decryption
 */
int rsa_prv_decrypt(unsigned char *ciphertext, int ciphertext_len,
                    RSA *key, unsigned char *plaintext, int padding_mode);

/*
 * RSA private key encryption
 */
int rsa_prv_encrypt(unsigned char *plaintext, int plaintext_len,
                    RSA *key, unsigned char *ciphertext, int padding_mode);

/*
 * RSA public key decryption
 */
int rsa_pub_decrypt(unsigned char *ciphertext, int ciphertext_len,
                    RSA *key, unsigned char *plaintext, int padding_mode);

/*
 * RSA Public(Private) encryption
 */
int rsa_pub_priv_encrypt(unsigned char *plaintext, int plaintext_len,
                         RSA *pub_k, RSA *priv_k, unsigned char *ciphertext);

/*
 * RSA Public(Private) decryption
 */
int rsa_pub_priv_decrypt(unsigned char *ciphertext, int ciphertext_len,
                         RSA *pub_k, RSA *priv_k, unsigned char *plaintext);

#endif /* _CS457_CRYPTO_H_ */

/* EOF */
