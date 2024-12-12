#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>

char* cache;

int init_cache(int cache_size) {
    cache = (char*) malloc(cache_size * sizeof(char));
    if (cache == NULL) {
        fprintf(stderr, "malloc error: can't alloc memmory\n");
        return -1;
    }
    return 0;
}