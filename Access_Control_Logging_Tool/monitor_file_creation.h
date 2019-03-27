#ifndef _MONITOR_FILE_CREATION_LIB_
#define _MONITOR_FILE_CREATION_LIB_

#include "monitor.h"

/* Defines the time window the monitor operation takes place.
 * eg. #define TIME_WINDOW 20 means that the tool will monitor
 *  the creation of files in the last 20 minutes.
*/
#define TIME_WINDOW 20

/*
 * Checks to see if there are created more
 * than n files in the last 20 minutes.
*/
void MonitorMode_NumberOfFiles(int n);

void ParseMode_NumberOfFiles(logEntry *e, void *ptr);

#endif
