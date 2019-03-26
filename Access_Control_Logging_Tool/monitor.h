#ifndef _MONITOR_LIB_
#define _MONITOR_LIB_
#include <stdio.h>
#include <unistd.h>
#include <time.h>

typedef struct logEntry logEntry;

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

/* Parses the log file */
void parseLog(void *ptr, void (*dispatcher)(logEntry *, void *));

/* Tokenizes the parsed line into a logEntry type */
logEntry *parseLine(char *line);

/* prints the given logEntry e */
void printLogEntry(logEntry *e);

#endif
