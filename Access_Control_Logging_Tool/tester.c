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
	FILE *fd6 = fopen("test6.dat", "a");
	FILE *fd7 = fopen("test7.dat", "a");
	FILE *fd8 = fopen("test8.dat", "a");
	FILE *fd9 = fopen("test9.dat", "a");
	FILE *fd10 = fopen("test10.dat", "a");
	FILE *fd11 = fopen("test11.dat", "r");

	char *str = "test\n";
	if (fd1)
		fwrite(str, sizeof(char), strlen(str), fd1);
	if (fd2)
		fwrite(str, sizeof(char), strlen(str), fd2);
	if (fd3)
		fwrite(str, sizeof(char), strlen(str), fd3);
	if (fd4)
		fwrite(str, sizeof(char), strlen(str), fd4);
	if (fd5)
		fwrite(str, sizeof(char), strlen(str), fd5);
	if (fd6)
		fwrite(str, sizeof(char), strlen(str), fd6);
	if (fd7)
		fwrite(str, sizeof(char), strlen(str), fd7);
	if (fd8)
		fwrite(str, sizeof(char), strlen(str), fd8);
	if (fd9)
		fwrite(str, sizeof(char), strlen(str), fd9);
	if (fd10)
		fwrite(str, sizeof(char), strlen(str), fd10);
	if (fd11)
		fwrite(str, sizeof(char), strlen(str), fd11);

	char *str2 = "second test\n";
	if (fd1)
		fwrite(str2, sizeof(char), strlen(str2), fd1);
	if (fd2)
		fwrite(str2, sizeof(char), strlen(str2), fd2);
	if (fd3)
		fwrite(str2, sizeof(char), strlen(str2), fd3);
	if (fd4)
		fwrite(str2, sizeof(char), strlen(str2), fd4);
	if (fd5)
		fwrite(str2, sizeof(char), strlen(str2), fd5);
	if (fd6)
		fwrite(str2, sizeof(char), strlen(str2), fd6);
	if (fd7)
		fwrite(str2, sizeof(char), strlen(str2), fd7);
	if (fd8)
		fwrite(str2, sizeof(char), strlen(str2), fd8);
	if (fd9)
		fwrite(str2, sizeof(char), strlen(str2), fd9);
	if (fd10)
		fwrite(str2, sizeof(char), strlen(str2), fd10);
	if (fd11)
		fwrite(str2, sizeof(char), strlen(str2), fd11);

	/* close files */
	if (fd1)
		fclose(fd1);
	if (fd2)
		fclose(fd2);
	if (fd3)
		fclose(fd3);
	if (fd4)
		fclose(fd4);
	if (fd5)
		fclose(fd5);
	if (fd6)
		fclose(fd6);
	if (fd7)
		fclose(fd7);
	if (fd8)
		fclose(fd8);
	if (fd9)
		fclose(fd9);
	if (fd10)
		fclose(fd10);
	if (fd11)
		fclose(fd11);

	return 0;
}
