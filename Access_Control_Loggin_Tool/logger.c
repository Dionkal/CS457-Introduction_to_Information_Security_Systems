#define _GNU_SOURCE

#include <stdio.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include "logger.h"

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

/* GetFileName modes */
#define GET_FILE_NAME_FOPEN_MODE 0
#define GET_FILE_NAME_FWRITE_MODE 1

/* Open file _LOG_PATH_ and append a log entry to it.
 * Each message is seperated by a new line.
 * Each value is seperated by a comma.
 */
void LogStuff(const char *filename, int action_type, int action_denied)
{
	char buffer[BUFSIZE];
	FILE *(*original_fopen)(const char *, const char *);
	original_fopen = dlsym(RTLD_NEXT, "fopen");
	size_t (*original_fwrite)(const void *, size_t, size_t, FILE *);
	original_fwrite = dlsym(RTLD_NEXT, "fwrite");

	/* Open log file */
	FILE *logFile;
	logFile = (*original_fopen)(_LOG_PATH_, "a+");

	/* UID */
	uid_t uid = getuid();

	/* Time operations */
	time_t t = time(NULL);
	char *date = ctime(&t);
	char *date2 = (char *)malloc(sizeof(char) * 64);
	date2 = strncpy(date2, date, strlen(date) - 1);

	/* Write to Log*/
	sprintf(buffer, "%d,%s,%s,%li,%d,%d\n", uid, filename, date2, t, action_type, action_denied);
	(*original_fwrite)(buffer, sizeof(char), strlen(buffer), logFile);

	/* Clean Up */
	free(date2);
	fclose(logFile);
}

FILE *fopen(const char *pathname, const char *mode)
{
	/* pointer to original fopen */
	FILE *(*original_fopen)(const char *, const char *);
	original_fopen = dlsym(RTLD_NEXT, "fopen");

	/* Actual call of fopen */
	FILE *original_fopen_return = (*original_fopen)(pathname, mode);

	char *filepath = getFilePath(NULL, pathname, GET_FILE_NAME_FOPEN_MODE);

	/* Log stuff */
	if (errno == EACCES)
		LogStuff(filepath, TYPE_OPEN_FILE, ACTION_FILE_FAILURE);
	else
		LogStuff(filepath, TYPE_OPEN_FILE, ACTION_FILE_SUCCESS);

	/* Clean Up */
	free(filepath);

	return original_fopen_return;
}

/*
 *	The function fwrite() writes nmemb items of data, each size bytes long,
 *  to the stream pointed to by stream, obtaining them  from  the  location
 *  given by ptr. It also logs the action it takes in the corresponding log
 *  file.
*/
size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream)
{
	/* pointer to original fwrite */
	size_t (*original_fwrite)(const void *, size_t, size_t, FILE *);
	original_fwrite = dlsym(RTLD_NEXT, "fwrite");

	/* Actual call of fwrite */
	size_t original_fwrite_return = (*original_fwrite)(ptr, size, nmemb, stream);

	/* Get file name Vodoo*/
	char *file_name = getFilePath(stream, NULL, GET_FILE_NAME_FWRITE_MODE);

	/* Log stuff */
	if (original_fwrite_return != nmemb)
		LogStuff(file_name, TYPE_WRITE_FILE, ACTION_FILE_FAILURE);
	else
		LogStuff(file_name, TYPE_WRITE_FILE, ACTION_FILE_SUCCESS);

	/* Clean Up */
	free(file_name);

	return original_fwrite_return;
}

/* Returns the file name and path of the given FILE structure.
 * Please note that the path of the file must not exceed BUFLEN -1
 * bytes in order to avoid memory corruption.
*/
char *getFilePath(FILE *stream, const char *filename, int mode)
{

	char *buff = malloc(sizeof(char) * BUFSIZE);
	if (buff == NULL)
	{
		fprintf(stderr, "insufficient memory\n");
		exit(EXIT_FAILURE);
	}

	char *filepath = malloc(sizeof(char) * BUFSIZE);
	if (filepath == NULL)
	{
		fprintf(stderr, "insufficient memory\n");
		exit(EXIT_FAILURE);
	}

	if (mode == GET_FILE_NAME_FWRITE_MODE && stream != NULL)
	{
		sprintf(filepath, "/proc/self/fd/%d", stream->_fileno); /* same as fileno(stream)  */

		ssize_t linksize = readlink(filepath, buff, BUFSIZE);
		buff[linksize] = '\0';
	}
	else if (mode == GET_FILE_NAME_FOPEN_MODE && filename != NULL)
	{
		getcwd(filepath, BUFSIZE - 1);
		if (filepath == NULL)
		{
			perror("getcwd");
			exit(EXIT_FAILURE);
		}
		sprintf(buff, "%s/%s", filepath, filename);
	}
	else
	{
		fprintf(stderr, "invalid mode in getFilePath\n");
	}

	free(filepath);

	return buff;
}
