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

/* prints the given logEntry e */
void printLogEntry(logEntry *e);

/* Parses the log file */
void parseLog();

#endif