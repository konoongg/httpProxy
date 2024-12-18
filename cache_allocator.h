#ifndef CACHE_ALLOC_H
#define CACHE_ALLOC_H

#include <stdint.h>

char* alloc_mem(unsigned int size);
void free_mem(char* mem);
int init_alloc(size_t size);
void finish_alloc();

#endif