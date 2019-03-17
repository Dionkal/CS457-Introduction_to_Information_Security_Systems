#include <arpa/inet.h>
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
 * prints the usage message
 */
void usage(void)
{
	printf(
		"\n"
		"Usage:\n"
		"    client -i IP -p port -m message\n"
		"    client -h\n");
	printf(
		"\n"
		"Options:\n"
		"  -i  IP         Server's IP address (xxx.xxx.xxx.xxx)\n"
		"  -p  port       Server's port\n"
		"  -m  message    Message to server\n"
		"  -h             This help message\n");
	exit(EXIT_FAILURE);
}

/*
 * checks the cmd arguments
 */
void check_args(char *ip, unsigned char *msg, int port)
{
	int err;

	err = 0;
	if (!ip)
	{
		printf("No IP provided\n");
		err = 1;
	}
	if (!msg)
	{
		printf("No message provided\n");
		err = 1;
	}
	if (port == -1)
	{
		printf("No port provided\n");
		err = 1;
	}
	if (err)
		usage();
}

void closeSocket(int fd)
{
	shutdown(fd, SHUT_RDWR);
	sleep(10);
	close(fd);
}

int ClientGetAESMessage(unsigned char *plaintext, unsigned char *ciphertext, unsigned char *aes_key, int socket, int aes_mode, unsigned char *vector)
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
	int plaintext_length = aes_decrypt(ciphertext, cipher_len, aes_key, vector, plaintext, aes_mode);
	printf("Whiter0se: %s\n", plaintext);
	return plaintext_length;
}

int clientSendAESMessage(unsigned char *plaintext, unsigned char *ciphertext, unsigned char *aes_key, int socket, int AESMode, unsigned char *vector)
{
	int cipher_len = aes_encrypt(plaintext,
								 strlen((char *)plaintext), aes_key, vector, ciphertext, AESMode);
	int bytes_transmited = send(socket, ciphertext, cipher_len, 0);
	if (bytes_transmited < 0 || bytes_transmited != cipher_len)
	{
		perror("send AES");
		exit(EXIT_FAILURE);
	}
	printf("Fs0ciety(you): %s\n", plaintext);
	return bytes_transmited;
}

/*
 * simple chat client with RSA-based AES
 * key-exchange for encrypted communication
 */
int main(int argc, char *argv[])
{
	int cfd;								/* comm file descriptor	 */
	int port;								/* server port		 */
	int err;								/* errors		 */
	int opt;								/* cmd options		 */
	int plain_len;							/* plaintext size	 */
	int cipher_len;							/* ciphertext size	 */
	size_t rxb;								/* received bytes	 */
	size_t txb;								/* transmitted bytes	 */
	char *sip;								/* server IP		 */
	struct sockaddr_in srv_addr;			/* server socket address */
	unsigned char *msg;						/* message to server	 */
	unsigned char *aes_key;					/* AES key		 */
	unsigned char plaintext[BUFLEN] = {0};  /* plaintext buffer	 */
	unsigned char ciphertext[BUFLEN] = {0}; /* plaintext buffer	 */
	unsigned char *IV = (unsigned char *)"143278389942760";
	RSA *c_prv_key; /* client private key	 */
	RSA *s_pub_key; /* server public key	 */

	/* initialize */
	cfd = -1;
	port = -1;
	sip = NULL;
	msg = NULL;
	memset(&srv_addr, 0, sizeof(srv_addr));

	/* get options */
	while ((opt = getopt(argc, argv, "i:m:p:h")) != -1)
	{
		switch (opt)
		{
		case 'i':
			sip = strdup(optarg);
			break;
		case 'm':
			msg = (unsigned char *)strdup(optarg);
			break;
		case 'p':
			port = atoi(optarg);
			break;
		case 'h':
		default:
			usage();
		}
	}

	/* check cmd args */
	check_args(sip, msg, port);

	/* socket init */
	if ((cfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		printf("ERROR %d:\tSocket creation error\n", errno);
		exit(EXIT_FAILURE);
	}

	/* connect to server */
	memset(&srv_addr, '0', sizeof(srv_addr));

	// Convert IPv4 and IPv6 addresses from text to binary form
	if (inet_pton(AF_INET, sip, &srv_addr.sin_addr) <= 0)
	{
		printf("Error: Invalid address/ Address %s not supported \n", sip);
		exit(EXIT_FAILURE);
	}

	srv_addr.sin_family = AF_INET;
	srv_addr.sin_port = htons(port);

	if (connect(cfd, (struct sockaddr *)&srv_addr, sizeof(srv_addr)) < 0)
	{
		printf("\nConnection Failed \n");
		exit(EXIT_FAILURE);
	}

	/* load keys */
	c_prv_key = rsa_read_key(C_PRV_KF, 0);
	s_pub_key = rsa_read_key(S_PUB_KF, 1);

	/* perform the AES key exchange */

	/*
   * encrypt the init message
   * and send it to the server
   */
	strncpy((char *)plaintext, (char *)msg, strlen((char *)msg));
	plain_len = strlen((const char *)plaintext);
	cipher_len = rsa_pub_priv_encrypt(plaintext, plain_len, s_pub_key, c_prv_key, ciphertext);

	txb = send(cfd, ciphertext, cipher_len, 0);
	if (txb < 0 || txb != cipher_len)
	{
		perror("send");
		exit(EXIT_FAILURE);
	}

#ifdef DEBUG
	printf("Sent %d bytes in hex:\n", (int)txb);
	print_hex(ciphertext, txb);
#endif

	memset(ciphertext, 0, txb);
	memset(plaintext, 0, plain_len);
	/*
   * receive the key from the server,
   * decrypt it and register it
   */
	rxb = read(cfd, ciphertext, BUFLEN);
	rxb = cipher_len;
	if (rxb < 0)
	{
		perror("read");
		exit(EXIT_FAILURE);
	}
	plain_len = rsa_pub_priv_decrypt(ciphertext, cipher_len, s_pub_key, c_prv_key, plaintext);

#ifdef DEBUG
	printf("Recieved: %d\n\"%s\"\n", plain_len, plaintext);
#endif

	aes_key = malloc(sizeof(unsigned char) * 129); // reserve space for key
	aes_key = (unsigned char *)strndup((const char *)plaintext, plain_len);

	memset(plaintext, 0, plain_len);
	memset(ciphertext, 0, cipher_len);

	/* encrypt the message with the AES key */
	/* send the encrypted message */
	strcpy((char *)plaintext, (char *)"A bug is never just a mistake. It represents something bigger. An error of thinking. That makes you who you are.");
	clientSendAESMessage(plaintext, ciphertext, aes_key, cfd, AES_128_CBC, IV);
	ClientGetAESMessage(plaintext, ciphertext, aes_key, cfd, AES_128_CBC, IV);

	/* cleanup */
	closeSocket(cfd);
	/*clean up memory before freeing the pointer*/
	aes_key = memset(aes_key, 0, strlen((char *)aes_key));
	free(aes_key);
	return 0;
}

/* EOF */
