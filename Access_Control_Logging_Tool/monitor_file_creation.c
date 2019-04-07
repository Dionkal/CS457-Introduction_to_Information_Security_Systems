#include "monitor_file_creation.h"
#include <stdio.h>
#include <time.h>
#include <assert.h>

/* uncomment the line below for verbose output */
/* #define DEBUG */

/* number of files created in the last n minutes */
static int files_created = 0;

void MonitorMode_NumberOfFiles(int n)
{
	printf("++++++++Begin number of files operation (%d)++++++++\n", n);

	time_t current_time = time(NULL);

	parseLog((void *)(&current_time), ParseMode_NumberOfFiles);

	if (files_created >= n)
		printf("Attention, files created in the last 20 minutes %d\n", files_created);
	else
		printf("File creation is normal.\n");
}

void ParseMode_NumberOfFiles(logEntry *e, void *ptr)
{
	time_t *currtime = (time_t *)ptr;
	assert(currtime != NULL);

#ifdef DEBUG
	printf("entry time:  %ld\n", e->time);
	printf("time window: %ld\n", (*currtime - (60 * TIME_WINDOW)));
	printf("Entry type %d\n", e->type);
#endif

	if ((e->time >= (*currtime - (60 * TIME_WINDOW))) && (e->type == TYPE_CREATE_FILE) && (e->action_denied == 0))
	{
		printf("Found suspicious file: %s\n", e->filename);
		files_created++;
	}
}
