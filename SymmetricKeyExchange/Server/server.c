#include <netinet/in.h>
#include <sys/socket.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>

#include "../cs457_crypto.h"

/*
 * Default server port
 *
 * Be careful when using this port on
 * CSD's machines. Read the README file
 * and select an other port by changing
 * this value or by using -p <port>
 */
#define DEFAULT_PORT 3613
#define PASS_PHRASE "hello friend"
/*
 * prints the usage message
 */
void usage(void)
{
	printf(
		"\n"
		"Usage:\n"
		"    server [-p port]\n"
		"    server -h\n");
	printf(
		"\n"
		"Options:\n"
		"  -p  port       Server's port\n"
		"  -h             This help message\n");
	exit(EXIT_FAILURE);
}

void closeSockets(int fd1, int fd2)
{
	shutdown(fd1, SHUT_RDWR);
	shutdown(fd2, SHUT_RDWR);
	sleep(10);
	close(fd1);
	close(fd2);
}

int ServerGetAESMessage(unsigned char *plaintext, unsigned char *ciphertext, unsigned char *aes_key, int socket, int aes_mode)
{
	/* Decrypt the message and print it */
	memset(plaintext, 0, BUFLEN);
	memset(ciphertext, 0, BUFLEN);
	int bytes_read = 0;
	bytes_read = read(socket, ciphertext, BUFLEN);
	if (bytes_read < 0)
	{
		perror("read AES");
		exit(EXIT_FAILURE);
	}
	int cipher_len = bytes_read;
	int plaintext_length = aes_decrypt(ciphertext, cipher_len, aes_key, NULL, plaintext, aes_mode);
	printf("Fs0ciety: %s\n", plaintext);
	return plaintext_length;
}

int ServerSendAESMessage(unsigned char *plaintext, unsigned char *ciphertext, unsigned char *aes_key, int socket, int AESMode)
{
	int cipher_len = aes_encrypt(plaintext,
								 strlen((char *)plaintext), aes_key, NULL, ciphertext, AESMode);
	int bytes_transmited = send(socket, ciphertext, cipher_len, 0);
	if (bytes_transmited < 0 || bytes_transmited != cipher_len)
	{
		perror("send AES");
		exit(EXIT_FAILURE);
	}
	printf("Whiter0se(you): %s\n", plaintext);
	return bytes_transmited;
}

/*
 * simple chat server with RSA-based AES
 * key-exchange for encrypted communication
 */
int main(int argc, char *argv[])
{
	int sockfd;								/* listen file descriptor */
	int sockcl;								/* comm file descriptor   */
	int port;								/* server port		  */
	int err;								/* errors		  */
	int opt;								/* cmd options		  */
	int optval;								/* socket options	  */
	int plain_len;							/* plaintext size	  */
	int cipher_len;							/* ciphertext size	  */
	size_t rxb;								/* received bytes	  */
	size_t txb;								/* transmitted bytes	  */
	struct sockaddr_in srv_addr;			/* server socket address  */
	int addrlen = sizeof(srv_addr);			/* size of srv_addr	*/
	unsigned char *aes_key;					/* AES key		  */
	unsigned char plaintext[BUFLEN] = {0};  /* plaintext buffer	  */
	unsigned char ciphertext[BUFLEN] = {0}; /* plaintext buffer	  */
	RSA *s_prv_key;							/* server private key	  */
	RSA *c_pub_key;							/* client public key	  */

	/* initialize */
	sockfd = -1;
	sockcl = -1;
	optval = 1;
	port = DEFAULT_PORT;
	memset(&srv_addr, 0, sizeof(srv_addr));

	/* get options */
	while ((opt = getopt(argc, argv, "p:h")) != -1)
	{
		switch (opt)
		{
		case 'p':
			port = atoi(optarg);
			break;
		case 'h':
		default:
			usage();
		}
	}

	/* socket init */
	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
	{
		perror("socket failed");
		exit(EXIT_FAILURE);
	}

	/*
   * bind and listen the socket
   * for new client connections
   */

	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT,
				   &optval, sizeof(optval)))
	{
		perror("setsockopt");
		exit(EXIT_FAILURE);
	}

	srv_addr.sin_family = AF_INET;
	srv_addr.sin_addr.s_addr = INADDR_ANY;
	srv_addr.sin_port = htons(port);

	if (bind(sockfd, (struct sockaddr *)&srv_addr, sizeof(srv_addr)) != 0)
	{
		perror("bind failed");
		exit(EXIT_FAILURE);
	}

	if (listen(sockfd, 1) < 0)
	{
		perror("listen");
		exit(EXIT_FAILURE);
	}

	/* load keys */
	aes_key = aes_read_key();
	s_prv_key = rsa_read_key(S_PRV_KF, 0);
	c_pub_key = rsa_read_key(C_PUB_KF, 1);

	/* accept a new client connection */
	if ((sockcl = accept(sockfd, (struct sockaddr *)&srv_addr, (socklen_t *)&addrlen)) < 0)
	{
		perror("accept");
		exit(EXIT_FAILURE);
	}

	/* wait for a key exchange init */
	rxb = read(sockcl, ciphertext, 512);
	if (rxb < 0)
	{
		perror("read");
		exit(EXIT_FAILURE);
	}

#ifdef DEBUG
	printf("Recieved %d bytes in hex:\n", (int)rxb);
	print_hex(ciphertext, rxb);
#endif

	cipher_len = rxb;
	plain_len = rsa_pub_priv_decrypt(ciphertext, cipher_len, c_pub_key, s_prv_key, plaintext);

	/* send the AES key */
	// TODO: check if client sent the correct passphrase before
	// replying with the AES key
	strncpy((char *)plaintext, (char *)aes_key, strlen((char *)aes_key));
	cipher_len = rsa_pub_priv_encrypt(plaintext, strlen((char *)plaintext), c_pub_key, s_prv_key, ciphertext);

	txb = send(sockcl, ciphertext, cipher_len, 0);
	if (txb < 0 || txb != cipher_len)
	{
		perror("Send AES key");
		exit(EXIT_FAILURE);
	}
	/* receive the encrypted message */
	ServerGetAESMessage(plaintext, ciphertext, aes_key, sockcl, AES_128_ECB);

	strcpy((char *)plaintext, (char *)"Every hacker has her fixation. You hack people, I hack time.");

	ServerSendAESMessage(plaintext, ciphertext, aes_key, sockcl, AES_128_ECB);

	/* cleanup */
	closeSockets(sockfd, sockcl);
	memset(aes_key, 0, strlen((const char *)aes_key));

	return 0;
}

/* EOF */
