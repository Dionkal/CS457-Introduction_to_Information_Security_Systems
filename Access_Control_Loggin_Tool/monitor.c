#include <stdio.h>
#include <stdlib.h>

/* Path to log file */
#define _LOG_PATH_ "my_logfile.log"

int main()
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
        free(log_entry_string);
        log_entry_string = NULL;
        i = 0;
    }
    return 0;
}