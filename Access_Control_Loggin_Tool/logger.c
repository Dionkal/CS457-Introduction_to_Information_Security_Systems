#define _GNU_SOURCE

#include <stdio.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <string.h>

#define _LOG_PATH_ "my_logfile.log"

FILE *fopen(const char *pathname, const char *mode)
{
	/* pointers to original fopen & fwrite */
	FILE *(*original_fopen)(const char *, const char *);
	original_fopen = dlsym(RTLD_NEXT, "fopen");
	size_t (*original_fwrite)(const void *, size_t, size_t, FILE *);
	original_fwrite = dlsym(RTLD_NEXT, "fwrite");

	/* Log stuff */
	LogStuff("Fopen wrapper\n");

	/* Actual call of fopen */
	return (*original_fopen)(pathname, mode);
}

/*
 *	The function fwrite() writes nmemb items of data, each size bytes long,
 *  to the stream pointed to by stream, obtaining them  from  the  location
 *  given by ptr. It also logs the action it takes in the corresponding log
 *  file.
*/
size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream)
{
	/* pointers to original fopen & fwrite */
	FILE *(*original_fopen)(const char *, const char *);
	original_fopen = dlsym(RTLD_NEXT, "fopen");
	size_t (*original_fwrite)(const void *, size_t, size_t, FILE *);
	original_fwrite = dlsym(RTLD_NEXT, "fwrite");

	/* Log stuff */
	LogStuff("Fwrite wrapper\n");

	/* Actual call of fwrite */
	return (*original_fwrite)(ptr, size, nmemb, stream);
}

/* Appends the given message to the file specified by _LOG_PATH_ */
void LogStuff(char *msg)
{
	FILE *(*original_fopen)(const char *, const char *);
	original_fopen = dlsym(RTLD_NEXT, "fopen");
	size_t (*original_fwrite)(const void *, size_t, size_t, FILE *);
	original_fwrite = dlsym(RTLD_NEXT, "fwrite");

	/* Log stuff */
	FILE *logFileptr;
	logFileptr = (*original_fopen)(_LOG_PATH_, "a");
	(*original_fwrite)(msg, strlen(msg), sizeof(char), logFileptr);
}
