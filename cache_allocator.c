#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <string.h>

char* memmory = NULL;
size_t memmory_size = 0;

char* alloc_mem(unsigned int size) {
    int i = 0;
    while (i < memmory_size) {
        unsigned int* size_seg = (unsigned int*)(memmory + i);
        if (*size_seg == 0) {
            *size_seg = size;
            return memmory + i + 4;
        }
        i += 4 + *size_seg;
    }
    printf("can't alloc mem \n");
    return NULL;
}

void free_mem(char* mem) {
    if (mem == NULL) {
        return;
    }
    uint32_t size_seg = *(uint32_t*)(mem - 4);
    memset((mem - 4), 0, size_seg);
}

int init_alloc(size_t size) {
    memmory_size = size;
    memmory = (char*) calloc(size, sizeof(char));
    if (memmory == NULL) {
        fprintf(stderr, "malloc error: can't alloc memmory %s\n", strerror(errno));
        return -1;
    }

    printf("mem %p \n", (memmory));
    return 0;
}

void finish_alloc() {
    free(memmory);
}