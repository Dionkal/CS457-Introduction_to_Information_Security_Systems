#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include "monitor.h"

/* Path to log file */
#define _LOG_PATH_ "my_logfile.log"

/* uncomment the line below for verbose output */
// #define DEBUG

/* externals */
/* Finds malicious Users */
extern void MonitorMode_MaliciousUsers();
extern void MonitorMode_File_History(char *filename);
extern void MonitorMode_NumberOfFiles(int n);
extern void MonitorMode_EncryptedFiles();

/*
 * prints to stdout a message with the correct usage of the program
*/
void printUsage()
{
    printf("Usage: monitor -[meh] | -[i <filename>] | -[v <number of files>]\n");
    printf("-m: Print malicious users\n");
    printf("-i <filename>: Print table of users that modified the file <filename> and the number of modifications\n");
    printf("-v <number of files>: If more than <number of files> files were created the last 20 minutes, it prints\n"
           "                      the total number, otherwise it prints a notification message that the logfile\n"
           "                      parsing was succesfully completedwith no suspicious results\n");
    printf("-e: Prints all the files that were encrypted by the ransomware\n");
    printf("-h: Prints this help message\n");
}

int main(int argc, char *argv[])
{
    int opt;

    if ((opt = getopt(argc, argv, "mehi:v:")) != -1)
    {
        switch (opt)
        {
        case 'm':
            MonitorMode_MaliciousUsers();
            break;
        case 'e':
            MonitorMode_EncryptedFiles();
            break;
        case 'i':
            MonitorMode_File_History(optarg);
            break;
        case 'v':
            MonitorMode_NumberOfFiles(atoi(optarg));
            break;
        case 'h':
            printUsage();
            return 0;
            break;
        default:
            printUsage();
            exit(EXIT_FAILURE);
        }
    }
    else
    {
        printUsage();
        exit(EXIT_FAILURE);
    }

    return 0;
}

void printLogEntry(logEntry *e)
{
    printf("LogEntry:\n");
    printf("uid: %d\n", e->uid);
    printf("filename: %s\n", e->filename);
    printf("date: %s\n", e->date);
    printf("time: %li\n", e->time);
    printf("type: %d\n", e->type);
    printf("action_denied: %d\n", e->action_denied);
    printf("fingerprint: %s\n", e->fingerprint);
}

void parseLog(void *ptr, void (*dispatcher)(logEntry *, void *))
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
        logEntry *e = parseLine(log_entry_string);

        /* Do monitor operations */
        (*dispatcher)(e, ptr);

        /* clean up */
        free(e);
        free(log_entry_string);
        log_entry_string = NULL;
        i = 0;
    }

    /* clean up */
    free(log_entry_string);
    fclose(fd);
}

/* Tokenizes the parsed line into a logEntry type */
logEntry *parseLine(char *line)
{
    logEntry *e = malloc(sizeof(logEntry));

    /* uid */
    char *token = strtok(line, ",");
    assert(token != NULL);
    e->uid = atol(token);
    /* filename */
    token = strtok(NULL, ",");
    assert(token != NULL);
    e->filename = token;
    /* date */
    token = strtok(NULL, ",");
    assert(token != NULL);
    e->date = token;
    /* time */
    token = strtok(NULL, ",");
    assert(token != NULL);
    e->time = atol(token);
    /* type */
    token = strtok(NULL, ",");
    assert(token != NULL);
    e->type = atoi(token);
    /* action_denied */
    token = strtok(NULL, ",");
    assert(token != NULL);
    e->action_denied = atoi(token);
    /* fingerprint */
    token = strtok(NULL, "\n");
    assert(token != NULL);
    e->fingerprint = (unsigned char *)token;
    token = strtok(NULL, ",");
    assert(token == NULL);

#ifdef DEBUG
    printLogEntry(e);
#endif

    return e;
}
