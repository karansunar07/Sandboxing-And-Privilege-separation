#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(void) {
    puts("memory_hog: allocating memory");
    fflush(stdout);
    for (;;) {
        void *p = malloc(1024 * 1024);
        if (p == NULL) {
            perror("malloc");
            sleep(1);
            continue;
        }
        memset(p, 0x41, 1024 * 1024);
        usleep(100000);
    }
}
