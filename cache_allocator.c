#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

char* memmory = NULL;
int memmory_size = 0;

char* alloc_mem(uint32_t size) {
    int i = 0;
    while (i < memmory_size) {
        uint32_t size_seg = *(uint32_t*)(memmory + i);
        if (size_seg == 0) {
            *(memmory + i) = size;
            return memmory + i + 4;
        }
        i += 4 + size_seg;
    }
    return NULL;
}

void free_mem(char* mem) {
    uint32_t size_seg = *(uint32_t*)(mem - 4);
    memset((mem - 4), 0, size_seg);
}

int init_alloc(int size) {
    memmory_size = size;
    memmory = (char*) malloc(size * sizeof(char));
    if (memmory == NULL) {
        fprintf(stderr, "malloc error: can't alloc memmory\n");
        return -1;
    }
    memset(memmory, 0, size);
    return 0;
}

void finish_alloc() {
    free(memmory);
}
