#ifndef _MONITOR_LIB_
#define _MONITOR_LIB_
#include <stdio.h>
#include <unistd.h>
#include <time.h>

typedef struct logEntry logEntry;
typedef struct user user;

struct logEntry
{
    uid_t uid;
    char *filename;
    char *date;
    time_t time;
    int type;
    int action_denied;
    unsigned char *fingerprint;
};

struct user
{
    uid_t uid;        /* username id */
    char **filenames; /* files that the user has tried to unsuccesfully access */
    int isMalicious;  /* Flag for malicious users */
};

/* Parses the log file */
void parseLog(void *ptr, void (*dispatcher)(logEntry *, void *));

/* Tokenizes the parsed line into a logEntry type */
logEntry *parseLine(char *line);

/* prints the given logEntry e */
void printLogEntry(logEntry *e);

/* Finds malicious Users */
void MonitorMode_MaliciousUsers();

/* Checks file history */
void MonitorMode_File(char *filename);

/*
 * Checks to see if there are created more
 * than n files in the last 20 minutes.
*/
void MonitorMode_NumberOfFiles(int n);

/* Finds encrypted files */
void MonitorMode_EncryptedFiles();
#endif
