#include "monitor_users.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>

static User **users;
static int nmbOfUsers = 0;

/* uncomment the line below for verbose output */
#define DEBUG

void MonitorMode_MaliciousUsers()
{

	printf("++++++++Beginning malicious users operation++++++++\n");
	parseLog(NULL, ParseMode_MaliciousUsers);
	/* TODO: Cleanup users */
}

void ParseMode_MaliciousUsers(logEntry *e, void *ptr)
{
	printf("---------malicious user line---------\n");

	if (e->action_denied == 0) /* we don't care about succesfull accesses*/
		return;

	User *u = isInUsers(e->uid);
	if (u != NULL)
	{
		updateUsers(e, u);
	}
	else
	{
		insertInUsers(e);
	}
}

/* ================ users Operations================ */

User *isInUsers(uid_t id)
{
	int i = 0;
	while (i < nmbOfUsers)
	{
		assert(users[i] != NULL);
		if ((users[i])->uid == id)
			return users[i];
		i++;
	}

	return NULL;
}

/*
 * Creates and initializes a new User entry in the users data structure
*/
void insertInUsers(logEntry *e)
{
	assert(e != NULL);

	/* create & initialize new User struct */
	User *usr = malloc(sizeof(User));
	usr->uid = e->uid;
	usr->nmbrOfFiles = 0;
	usr->filenames = NULL;
	insertInFileNames(usr, e->filename, strlen(e->filename));
	usr->isMalicious = 0;

	/* Add User struct to the users data structure */
	nmbOfUsers++;
	users = realloc(users, sizeof(User *) * nmbOfUsers);
	users[nmbOfUsers - 1] = usr;

#ifdef DEBUG
	printf("Inserted new user: \n");
	printUser(usr);
#endif
}

/*
 * Checks if e->filename is already in the list of the u->filenames.
 * If it isn't then it appends it to the filename data stracture and returns.
 * Else it does nothing and returns 0.
*/
int updateUsers(logEntry *e, User *u)
{
	assert(u != NULL);
	if (isInFileNames(u, e->filename, strlen(e->filename)) == -1)
	{
		insertInFileNames(u, e->filename, strlen(e->filename));
#ifdef DEBUG
		printf("User updated: \n");
		printUser(u);
#endif
		return 1;
	}
#ifdef DEBUG
	printf("User not updated: \n");
	printUser(u);
#endif

	return 0;
}

void printUser(User *u)
{
	assert(u != NULL);

	printf("Uid:\t\t\t%d\n", u->uid);
	printf("filenames (%d):\n", u->nmbrOfFiles);
	printFilenames(u);
	printf("IsMalicious:\t%d\n", u->isMalicious);
}

/*
 * Cleans up all the User structs of users
*/
void cleanUsers()
{
	/* TODO parse users and clean up all the User structs*/
}

/* ================Filenames Operations================ */
int isInFileNames(User *u, const char *str, int strSize)
{
	int i = 0;
	assert(u->filenames != NULL);

	while (i < u->nmbrOfFiles)
	{
		assert((u->filenames)[i] != NULL);
		/* filename found */
		if (strncmp((u->filenames)[i], str, strSize) == 0)
			return i;
		i++;
	}
	return -1;
}

char *insertInFileNames(User *u, const char *str, int strSize)
{
	/* Get new filename entry*/
	u->nmbrOfFiles++;
	u->filenames = realloc(u->filenames, sizeof(char *) * u->nmbrOfFiles);

	/* Copy the string */
	(u->filenames)[u->nmbrOfFiles - 1] = malloc(sizeof(char *) * strSize);
	strncpy((u->filenames)[u->nmbrOfFiles - 1], str, strSize);

	return (u->filenames)[u->nmbrOfFiles - 1];
}

void printFilenames(User *u)
{
	assert(u->filenames != NULL);

	int i = 0;
	while (i < u->nmbrOfFiles)
	{
		printf("\t\t\t\t%s\n", (u->filenames)[i]);
	}
}

/*
 * Cleans all the filenames of the given user u
*/
void cleanFileNames(User *u)
{
	/* TODO Clean all the filenames of the given user u*/
}
