#include "wannal4ugh.h"
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

void printUsage()
{
	printf("Usage: wannalaugh  -[e <directory>]  -[o <number of files>]\n");
	printf("-e <directory>: Encrypts all files in the given directory\n");
	printf("-o <filename>: Obfuscates ransom detection by creating Y files in the given directory\n");
	printf("-v: Prints the current version.\n");
	printf("-h: Prints this help message\n");
}

void printVersion()
{
	printf("wannal4ugh: Version 1.0\n");
	printf("DISCLAIMER: You should ask for permission before using this tool.");
	printf(" Author shall not be held responsible for any illegal use of his tool.\n");
}

int main(int argc, char *argv[])
{
	int opt;

	while ((opt = getopt(argc, argv, "hve:o:")) != -1)
	{
		switch (opt)
		{
		case 'e':
			printf("Ransom mode: target directory = %s\n", optarg);
			break;
		case 'o':
			printf("Obfuscate mode: number of files = %d\n", atoi(optarg));
			break;
		case 'v':
			printVersion();
			exit(EXIT_SUCCESS);
			break;
		case 'h':
			printUsage();
			exit(EXIT_SUCCESS);
			break;
		default:
			printUsage();
			exit(EXIT_FAILURE);
		}
	}
}
