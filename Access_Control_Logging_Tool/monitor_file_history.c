#include "monitor_file_history.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>

/* uncomment the line below for verbose output */
/* #define DEBUG */

static file_history **files;
static int nmbrOfEntries = 0;

void MonitorMode_File_History(char *filename)
{
	parseLog(filename, ParseMode_File_History);

	int i;
	printf("--------------Printing File History--------------\n");
	for (i = 0; i < nmbrOfEntries; i++)
	{
		printf("Entry #%d\n", i);
		printFileHistory(files[i]);
		printf("-------------------------------------------------\n");
	}

	CleanFiles();
}

void ParseMode_File_History(logEntry *e, void *ptr)
{
	char *filename = (char *)ptr;

#ifdef DEBUG
	printf("Input file: %s\n", filename);
	printf("Entry file: %s\n,", e->filename);
	printLogEntry(e);
	printf("---------------------------------------------\n");
#endif

	/* We need to only check entries that match
	 the given filename */
	if ((strcmp(e->filename, filename) == 0) && (e->action_denied == ACTION_FILE_SUCCESS))
	{
		int index = isInFiles(e->uid);
		if (index >= 0)
		{
			if (memcmp(e->fingerprint, (files[index]->fingerprint), MD5_DIGEST_LENGTH) != 0)
				UpdateFiles(e, index);
		}
		else
			insertInFiles(e);
	}
}

/*
 * Checks the files data stracture to see if there a
 * file_history entry already exists. If it exists then
 * it returns a pointer pointing to this entry, else it
 * returns NULL
*/
int isInFiles(uid_t id)
{
	int i = 0;
	for (i = 0; i < nmbrOfEntries; i++)
	{
		assert(files[i] != NULL);
		if (id == files[i]->uid)
			return i;
	}
	return -1;
}

void insertInFiles(logEntry *e)
{
	assert(e != NULL);

	/* create and initialize a new file_history struct */
	file_history *fh = malloc(sizeof(file_history));
	fh->uid = e->uid;
	memcpy(fh->fingerprint, e->fingerprint, 33);
	fh->timesModified = 1;

	/* add file_history_struct to files table */
	nmbrOfEntries++;
	files = realloc(files, sizeof(file_history *) * nmbrOfEntries);
	files[nmbrOfEntries - 1] = fh;

#ifdef DEBUG
	printf("Inserted new file_history entry\n");
	printFileHistory(fh);
#endif
}

/*
 * Given the logEntry it updated the file_history struct
 * that files[index] points to.
*/
void UpdateFiles(logEntry *e, int index)
{
	assert(e != NULL);
	assert(files != NULL);
	assert(files[index] != NULL);

	/* update fingerprint */
	memcpy(files[index]->fingerprint, e->fingerprint, 33);
	files[index]->timesModified++;

#ifdef DEBUG
	printf("Updated existing file_history entry\n");
	printFileHistory(files[index]);
#endif
}

void printFileHistory(file_history *fh)
{
	assert(fh != NULL);
	printf("Uid: %d\n", fh->uid);
	printf("Fingerprint: %s\n", fh->fingerprint);
	printf("\nTimes modified: %d\n", fh->timesModified);
}

/*
 * Cleans the files table and all the dynamically
 * allocated file_history structs
*/
void CleanFiles()
{
	if (files != NULL)
	{
		for (int i = 0; i < nmbrOfEntries; i++)
		{
			free(files[i]);
		}
		free(files);
	}
}
