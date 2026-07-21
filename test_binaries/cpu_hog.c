#include <stdint.h>
#include <stdio.h>

int main(void) {
    volatile uint64_t x = 0;
    puts("cpu_hog: spinning");
    fflush(stdout);
    for (;;) {
        x++;
    }
}
