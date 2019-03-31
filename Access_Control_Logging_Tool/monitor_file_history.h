#ifndef _MONITOR_FILE_HISTORY_LIB_
#define _MONITOR_FILE_HISTORY_LIB_

#include "monitor.h"
#include <unistd.h>
#include <openssl/md5.h>

/* Checks file history */
void MonitorMode_File_History(char *filename);

void ParseMode_File_History(logEntry *e, void *ptr);

typedef struct file_history file_history;
struct file_history
{
	uid_t uid;
	unsigned char *fingerprint[MD5_DIGEST_LENGTH];
	unsigned int timesModified;
};

/*
 * Checks the files data stracture to see if there a
 * file_history entry already exists. If it exists then
 * it returns a pointer pointing to this entry, else it
 * returns NULL
*/
int isInFiles(uid_t id);

/*
 * Makes a new file_history struct given
 * the data from the logEntry and appends it
 * to the files structure
*/
void insertInFiles(logEntry *e);

/*
 * Given the logEntry it updated the file_history struct
 * that files[index] points to.
*/
void UpdateFiles(logEntry *e, int index);

/*
 * Prints the given file_history struct
*/
void printFileHistory(file_history *fh);

/*
 * Cleans the files table and all the dynamically
 * allocated file_history structs
*/
void CleanFiles();
#endif
