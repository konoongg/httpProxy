#ifndef CACHE_H
#define CACHE_H

#define DEFAULT_CACHE_TTL 5 // sec
#define DEFAULT_CACHE_INIT_SIZE 1 * 1024 * 1024 // byte
#define DEFAULT_CACHE_MAX_SIZE 10 * 1024 * 1024 // byte

#define MIN_CACHE_INIT_SIZE 1024
#define MAX_CACHE_INIT_SIZE 1024 * 1024 * 1024

#define MIN_CACHE_MAX_SIZE 1024
#define MAX_CACHE_MAX_SIZE 1024 * 1024 * 1024

#define MIN_CACHE_TTL 0 // 0 - not_ttl, in seconds
#define MAX_CACHE_TTL  (unsigned int)1024 * 1024 * 1024 * 4 // max uint32

typedef struct cache_value {
  char* data;
  struct cache_value* left;
  struct cache_value* right;
} cache_value;
#endif