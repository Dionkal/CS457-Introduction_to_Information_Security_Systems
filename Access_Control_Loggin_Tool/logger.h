#ifndef _LOGGER_HEADER_
#define _LOGGER_HEADER_

#include <stdio.h>

/* Path to log file */
#define _LOG_PATH_ "my_logfile.log"

/* FILE ACTION TYPE MACROS */
#define TYPE_CREATE_FILE 0
#define TYPE_OPEN_FILE 1
#define TYPE_WRITE_FILE 2

/* FILE ACCESS MACROS */
#define ACTION_FILE_SUCCESS 0
#define ACTION_FILE_FAILURE 1

/* Buffer size*/
#define BUFSIZE 256

/* Open file _LOG_PATH_ and append a log entry to it.
 * Each message is seperated by a new line.
 * Each value is seperated by a comma.
 */
void LogStuff(const char *filename, int action_type, int action_denied);

/* Returns the file name and path of the given FILE structure.
 * Please note that the path of the file must not exceed BUFLEN -1
 * bytes in order to avoid memory corruption.
*/
char *getFilePath(FILE *stream, const char *filename, int mode);

#endif
