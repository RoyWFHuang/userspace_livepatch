#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stddef.h>
#include <dlfcn.h>



int func1(int a, int b) {
    printf("in fixup\n");
    sleep(2);
    printf("exit fixup\n");
    return (a*10+b);
}



