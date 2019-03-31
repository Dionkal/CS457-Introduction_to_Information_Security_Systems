#ifndef _MONITOR_ENCRYPTED_FILES_LIB_
#define _MONITOR_ENCRYPTED_FILES_LIB_

#include "monitor.h"

struct encrypted_files
{
    char *filename;
    int CrEFlag; /* created encrypted file of filename */
    int WrEFlag; /* written to that encrypted file */
};

typedef struct encrypted_files encrypted_files;

/* Finds encrypted files */
void MonitorMode_EncryptedFiles();

void ParseMode_FindEncryptedFiles(logEntry *e, void *ptr);

/* 
 * Parses eFiles table to find if there is an encrypted file 
 * entry with filename. If it exists then it returns the index 
 * of the entry. Else it returns -1.
*/
int isInEncryptedFiles(char *filename);

/* 
 * Creates a new encrypted file entry based on the data
 * from the given log entry e and appends it to the efiles
 * table.
 */
void insertInEncryptedFiles(logEntry *e);

/*
 * Updates the encrypted file of efiles[index] with the
 * data of log entry e where possible.
 */
void updatedEncryptedFile(logEntry *e, int index);

/*
 * Prints the given encrypted file struct
*/
void printEncryptedFile(encrypted_files *ef);

void cleanEncryptedFiles();

/*
 * Examines if the given filename has the suffix ".encrypt".
 * Returns 1 if true and 0 if false
 */
int isEncryptSuffix(char *filename);

/*
 * Compares the two strings without the ".encrypt" suffix on the efilename.
 * Returns 0 when the two strings match, or non zero when they differ.
 */
int compareFilenames(char *efilename, char *filename);
#endif
