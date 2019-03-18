#define _GNU_SOURCE

#include <stdio.h>
#include <dlfcn.h>
#include <stdlib.h>

FILE *fopen(const char *pathname, const char *mode)
{
	/* Log stuff */
	printf("Fopen wrapper\n");

	/* Actual call of fopen */
	FILE *(*original_fopen)(const char *, const char *);
	original_fopen = dlsym(RTLD_NEXT, "fopen");
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
	/* Log stuff */
	printf("Fwrite wrapper\n");

	/* Actual call of fwrite */
	size_t (*original_fwrite)(const void *, size_t, size_t, FILE *);
	original_fwrite = dlsym(RTLD_NEXT, "fwrite");
	return (*original_fwrite)(ptr, size, nmemb, stream);
}
