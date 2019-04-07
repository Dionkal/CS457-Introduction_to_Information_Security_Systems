#include <stdio.h>
#include <string.h>

int main()
{

	/* create files */
	FILE *fd1 = fopen("test1.dat", "w");
	FILE *fd2 = fopen("test2.dat", "a");
	FILE *fd3 = fopen("test3.dat", "a");
	FILE *fd4 = fopen("test4.dat", "a");
	FILE *fd5 = fopen("test5.dat", "a");

	char *str = "test\n";
	fwrite(str, sizeof(char), strlen(str), fd1);
	fwrite(str, sizeof(char), strlen(str), fd2);
	fwrite(str, sizeof(char), strlen(str), fd3);
	fwrite(str, sizeof(char), strlen(str), fd4);
	fwrite(str, sizeof(char), strlen(str), fd5);

	char *str2 = "second test\n";
	fwrite(str2, sizeof(char), strlen(str2), fd1);
	fwrite(str2, sizeof(char), strlen(str2), fd2);
	fwrite(str2, sizeof(char), strlen(str2), fd3);
	fwrite(str2, sizeof(char), strlen(str2), fd4);
	fwrite(str2, sizeof(char), strlen(str2), fd5);

	/* close files */
	fclose(fd1);
	fclose(fd2);
	fclose(fd3);
	fclose(fd4);
	fclose(fd5);

	/* Uncomment to delete them */
	/* remove(fd1);
	remove(fd2);
	remove(fd3);
	remove(fd4);
	remove(fd5);
*/
	return 0;
}
