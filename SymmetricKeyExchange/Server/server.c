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
   * this will save them from:
   * "ERROR on binding: Address already in use"
   */

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
	if (read(sockcl, ciphertext, 256) < 0)
	{
		perror("read");
		exit(EXIT_FAILURE);
	}

	cipher_len = BUFLEN;
	plain_len = rsa_pub_priv_decrypt(ciphertext, 256, c_pub_key, s_prv_key, plaintext, RSA_NO_PADDING, RSA_PKCS1_PADDING);
	printf("Plaintext form: %d\n", plain_len);
	printf("%s", plaintext);

	/* send the AES key */

	/* receive the encrypted message */

	/* Decrypt the message and print it */
	if (send(sockcl, plaintext, BUFLEN, 0) < 0)
	{
		perror("send");
		exit(EXIT_FAILURE);
	}
	printf("Sent: \"%s\"\n", plaintext);

	/* cleanup */
	closeSockets(sockfd, sockcl);
	memset(aes_key, 0, strlen((const char *)aes_key));

	return 0;
}

/* EOF */
