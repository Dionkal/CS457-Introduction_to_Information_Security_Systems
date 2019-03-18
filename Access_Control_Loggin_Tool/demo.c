#include <stdio.h>

int main()
{
	FILE *fd = fopen("fsocity00.dat", "r");
	fwrite("test", 0, 1, NULL);
	return 0;
}
