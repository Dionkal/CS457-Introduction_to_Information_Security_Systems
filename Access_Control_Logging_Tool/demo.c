#include <stdio.h>
#include <string.h>

int main()
{
	FILE *fd = fopen("test.dat", "a");

	if (fd == NULL)
	{
		perror("Error in fopen");
	}

	char *str = "test\n";
	int i = fwrite(str, sizeof(char), strlen(str), fd);
	if (i != strlen(str))
	{
		perror("Error in fwrite");
	}

	char *str2 = "This is a second write before fclose\n";
	i = fwrite(str2, sizeof(char), strlen(str2), fd);
	if (i != strlen(str2))
	{
		perror("Error in fwrite");
	}
	fclose(fd);
	return 0;
}
