#include "monitor_encrypted_files.h"
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>

/* uncomment the line below for verbose output */
// #define DEBUG

static encrypted_files **eFiles;
static int numOfEntries = 0;

void MonitorMode_EncryptedFiles()
{
	printf("++++++++Begin encrypted files operation++++++++\n");
	parseLog(NULL, ParseMode_FindEncryptedFiles);

	printf("-------------Possible encrypted files-------------\n");
	for (int i = 0; i < numOfEntries; i++)
	{
		if (eFiles[i]->CrEFlag == 1 && eFiles[i]->WrEFlag == 1)
			printEncryptedFile(eFiles[i]);
	}

	/* Clean up */
	cleanEncryptedFiles();
}

void ParseMode_FindEncryptedFiles(logEntry *e, void *ptr)
{
	int res;
	int enc_suffix = isEncryptSuffix(e->filename);
#ifdef DEBUG
	printLogEntry(e);
	printf("Has encrypted suffix: %d\n", enc_suffix);
#endif

	if (enc_suffix)
	{ /* search if the filename without the encrypt suffix exists */
		char bufname[BUFSIZ];
		strncpy(bufname, e->filename, strlen(e->filename) - 8);
		res = isInEncryptedFiles(bufname);
		if (res > -1)
			updatedEncryptedFile(e, res);
	}
	else
	{ /* normal filename without .encrypt suffix */
		res = isInEncryptedFiles(e->filename);
		if (res == -1 && e->action_denied == 0 && e->type == 1) /* create new entry */
			insertInEncryptedFiles(e);
	}
}

int isInEncryptedFiles(char *filename)
{
	assert(filename != NULL);
	int i;
	for (i = 0; i < numOfEntries; i++)
	{
		if (strcmp(filename, eFiles[i]->filename) == 0)
		{
			return i;
		}
	}

	return -1;
}

/*
 * Creates a new encrypted file entry based on the data
 * from the given log entry e and appends it to the efiles
 * table.
 */
void insertInEncryptedFiles(logEntry *e)
{
	assert(e != NULL);

	/* create a new encrypted_files entry */
	encrypted_files *ef = malloc(sizeof(encrypted_files));
	ef->filename = malloc(sizeof(char) * strlen(e->filename));
	strncpy(ef->filename, e->filename, strlen(e->filename));
	ef->CrEFlag = 0;
	ef->WrEFlag = 0;

	/* append the entry to the eFiles table */
	numOfEntries++;
	eFiles = realloc(eFiles, sizeof(encrypted_files *) * numOfEntries);
	eFiles[numOfEntries - 1] = ef;

#ifdef DEBUG
	printf("Created new entry: \n");
	printEncryptedFile(ef);
#endif
}

/*
 * Updates the encrypted file of efiles[index] with the
 * data of log entry e where possible.
 */
void updatedEncryptedFile(logEntry *e, int index)
{
	assert(e != NULL);
	assert(index >= 0);
	assert(eFiles[index] != NULL);
	assert(eFiles[index]->filename != NULL);

	if (eFiles[index]->CrEFlag == 0 && e->action_denied == 0 && e->type == 0)
	{
		eFiles[index]->CrEFlag = 1;
	}
	else if (eFiles[index]->WrEFlag == 0 && eFiles[index]->CrEFlag == 1 && e->action_denied == 0 && e->type == 2)
	{
		eFiles[index]->WrEFlag = 1;
	}
	else
	{
#ifdef DEBUG
		printf("Didn't update encrypted_file entry in log entry\n");
		printLogEntry(e);
		printEncryptedFile(eFiles[index]);
#endif
		return;
	}

#ifdef DEBUG
	printf("Updated encrypted_file entry in log entry\n");
	printLogEntry(e);
	printEncryptedFile(eFiles[index]);
#endif
}

/*
 * Prints the given encrypted file struct
*/
void printEncryptedFile(encrypted_files *ef)
{
	assert(ef != NULL);

	printf("Filename: %s\n", ef->filename);
	printf("Encrypted file with same name created: %d\n", ef->CrEFlag);
	printf("Encrypted file with same name written: %d\n", ef->WrEFlag);
}

void cleanEncryptedFiles()
{
	if (eFiles != NULL)
	{
		for (int i = 0; i < numOfEntries; i++)
		{
			free(eFiles[i]->filename);
			free(eFiles[i]);
		}
		free(eFiles);
	}
}

/*
 * Examines if the given filename has the suffix ".encrypt".
 * Returns 1 if true and 0 if false
 */
int isEncryptSuffix(char *filename)
{
	assert(filename != NULL);
	/* 8: lenght of .encrypt suffix */
	int encrypted_str_len = strlen(filename);
	if (encrypted_str_len > 8 && (strcmp(filename + (encrypted_str_len - 8), ".encrypt") == 0))
	{
		return 1;
	}
	return 0;
}

/*
 * Compares the two strings without the ".encrypt" suffix on the efilename.
 * Returns 0 when the two strings match, or non zero when they differ.
 */
int compareFilenames(char *efilename, char *filename)
{
	assert(efilename != NULL);
	assert(filename != NULL);
	/* 8: lenght of .encrypt suffix */
	if (isEncryptSuffix(efilename))
	{
		/* comapre the two filenames without the 8 last chars of the encrypt suffix */
		return strncmp(efilename, filename, strlen(efilename) - 8);
	}
	return -1;
}
