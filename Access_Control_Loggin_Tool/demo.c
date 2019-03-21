#include <stdio.h>
#include <string.h>

int main()
{
	FILE *fd = fopen("fsocity00.dat", "w");
	if (fd == NULL)
	{
		perror("Error in fopen");
	}
	char *str = "test";
	int i = fwrite(str, sizeof(char), strlen(str), fd);
	if (i != strlen(str))
	{
		perror("Error in fwrite");
	}
	return 0;
}
