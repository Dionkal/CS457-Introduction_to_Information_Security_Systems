#ifndef _MONITOR_USERS_LIB_
#define _MONITOR_USERS_LIB_

#include <stdio.h>
#include <unistd.h>
#include "monitor.h"

typedef struct user User;

struct user
{
	uid_t uid;		  /* username id */
	char **filenames; /* files that the user has tried to unsuccesfully access */
	int nmbrOfFiles;
	int isMalicious; /* Flag for malicious users */
};

/* Finds malicious Users */
void MonitorMode_MaliciousUsers();

void ParseMode_MaliciousUsers(logEntry *e, void *ptr);

/* ================ users Operations================ */

/*
 * Search users data structure to find if a user with the given id
 * exits. If found, returs a pointer to the user struct, else it returns
 * NULL pointer.
*/
User *isInUsers(uid_t id);

void insertInUsers(logEntry *e);

/*
 * Checks if filename is already in the list of the user filenames.
 * If it isn't then it appends it to the filename data stracture and returns.
 * Else it does nothing and returns 0.
*/
int updateUsers(logEntry *e, User *u);

void printUser(User *u);

/*
 * Cleans up all the User structs of users
*/
void cleanUsers();
/* ================Filenames Operations================ */

int isInFileNames(User *u, const char *str, int strSize);

char *insertInFileNames(User *u, const char *str, int strSize);

void printFilenames(User *u);

/*
 * Cleans all the filenames of the given user u
*/
void cleanFileNames(User *u);
#endif
