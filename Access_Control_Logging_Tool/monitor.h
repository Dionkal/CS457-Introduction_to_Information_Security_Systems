#ifndef _MONITOR_LIB_
#define _MONITOR_LIB_
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <openssl/md5.h>

/* Path to log file */
#define _LOG_PATH_ "my_logfile.log"

/* FILE ACTION TYPE MACROS */
#define TYPE_CREATE_FILE 0
#define TYPE_OPEN_FILE 1
#define TYPE_WRITE_FILE 2

/* FILE ACCESS MACROS */
#define ACTION_FILE_SUCCESS 0
#define ACTION_FILE_FAILURE 1

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
