#include <stdio.h>
#include <string.h>

int main()
{
	FILE *fd = fopen("test.dat", "a+");

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
	fclose(fd);
	return 0;
}
