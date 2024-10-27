#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stddef.h>
#include <dlfcn.h>

// int __wrap_sleep (int second)
// {
//     sleep(3);
//     return 0;
// }

int func1(int a, int b) {
    printf("in func1\n");
    // static void *(*real_sleep)(int) = NULL;
    // if (real_sleep == NULL) {
    //     real_sleep = dlsym(RTLD_NEXT, "sleep");
    // }
    // __wrap_sleep(3);
    // real_sleep(3);
    sleep(2);
    printf("exit func1\n");
    return (a*10+b);
}



