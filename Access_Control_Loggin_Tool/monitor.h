#ifndef _MONITOR_LIB_
#define _MONITOR_LIB_
#include <stdio.h>
#include <unistd.h>

struct user
{
    uid_t uid;        /* username id */
    char **filenames; /* files that the user has tried to unsuccesfully access */
    int isMalicious;  /* Flag for malicious users */
}

#endif