#ifndef CACHE_ALLOC_H
#define CACHE_ALLOC_H

#include <stdint.h>

char* alloc_mem(uint32_t size);
void free_mem(char* mem);
int init_alloc(int size);
void finish_alloc();

#endif