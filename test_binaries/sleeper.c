#include <stdio.h>
#include <unistd.h>

int main(void) {
    puts("sleeper: sleeping longer than the sandbox time limit");
    fflush(stdout);
    sleep(30);
    return 0;
}
