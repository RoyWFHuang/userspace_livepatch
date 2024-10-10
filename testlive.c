#include <stdio.h>
#include <time.h>
#include <limits.h>
#include <unistd.h>
#include <sys/mman.h>

int func_J(int a, int b)
{
    char *str_P = "func_J";
	printf("in %s\n", str_P);
	sleep(3);
	printf("exit %s\n", str_P);
	return (a+b);
}


int main ()
{

	while(1) {
		int a = func_J(1, 2);
		sleep(3);
	    printf("in main %d\n", a);
	}

}

