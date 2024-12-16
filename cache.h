#ifndef CACHE_H
#define CACHE_H

#include <time.h>
#include <pthread.h>

#define DEFAULT_CACHE_TTL 5 // sec
#define DEFAULT_CACHE_INIT_SIZE 1 * 1024 * 1024 * 1024// byte
#define DEFAULT_CACHE_MAX_SIZE (size_t)10UL * 1024 * 1024 * 1024 // byte

#define MIN_CACHE_INIT_SIZE 0
#define MAX_CACHE_INIT_SIZE (size_t)(10ULL * 1024ULL * 1024ULL * 1024ULL)

#define MIN_CACHE_MAX_SIZE 0
#define MAX_CACHE_MAX_SIZE (size_t) 10 * 1024 * 1024 * 1024 // 10gb

#define MIN_CACHE_TTL 0 // 0 - not_ttl, in seconds
#define MAX_CACHE_TTL  (unsigned int)1024 * 1024 * 1024 * 4 // max uint32

#define HASH_TABLE_SIZE 10000
#define HASH_PARAM HASH_TABLE_SIZE - 1

typedef struct cache_req {
    char* url;
    char* content;
    time_t load_time;
    int content_offset;
    int content_size;
    struct cache_req* next;
} cache_req;

typedef struct cache_bascket {
    pthread_rwlock_t lock;
    struct cache_req* first;
    struct cache_req* last;
} cache_bascket;

int init_cache(size_t cache_size, int ttl_s);
int add_req_content(char* key, char* content);
int add_cache_req(char* key, int content_size);
int get_cache(char* key, char** content,  int content_offset);
void finish_cache();

#endif
