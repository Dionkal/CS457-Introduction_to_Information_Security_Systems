#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include "monitor.h"

/* Path to log file */
#define _LOG_PATH_ "my_logfile.log"

/* uncomment the line below for verbose output */
#define DEBUG

int main()
{
    parseLog();
    return 0;
}

void printLogEntry(logEntry *e)
{
    printf("LogEntry:\n");
    printf("uid: %d\n", e->uid);
    printf("filename: %s\n", e->filename);
    printf("date: %s\n", e->date);
    printf("time: %u\n", e->time);
    printf("type: %d\n", e->type);
    printf("action_denied: %d\n", e->action_denied);
    printf("fingerprint: %s\n", e->fingerprint);
}

void parseLog()
{
    char *log_entry_string = NULL;
    FILE *fd = fopen(_LOG_PATH_, "r");
    if (fd == NULL)
    {
        perror("Error in fopen");
        exit(EXIT_FAILURE);
    }

    size_t i = 0;
    while (getline(&log_entry_string, &i, fd) != -1)
    {
        printf("Line: %s\n", log_entry_string);

        logEntry e;

        /* uid */
        char *token = strtok(log_entry_string, ",");
        assert(token != NULL);
        e.uid = atol(token);
        /* filename */
        token = strtok(NULL, ",");
        assert(token != NULL);
        e.filename = token;
        /* date */
        token = strtok(NULL, ",");
        assert(token != NULL);
        e.date = token;
        /* time */
        token = strtok(NULL, ",");
        assert(token != NULL);
        e.time = atol(token);
        /* type */
        token = strtok(NULL, ",");
        assert(token != NULL);
        e.type = atoi(token);
        /* action_denied */
        token = strtok(NULL, ",");
        assert(token != NULL);
        e.action_denied = atoi(token);
        /* fingerprint */
        token = strtok(NULL, ",");
        assert(token != NULL);
        e.fingerprint = (unsigned char *)token;
        token = strtok(NULL, ",");
        assert(token == NULL);

#ifdef DEBUG
        printLogEntry(&e);
#endif
    }

    /* clean up */
    free(log_entry_string);
    log_entry_string = NULL;
    i = 0;
}