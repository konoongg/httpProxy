#ifndef CACHE_H
#define CACHE_H

#include <time.h>
#include <pthread.h>
#include <stdbool.h>

#define DEFAULT_CACHE_TTL 5 // sec
#define DEFAULT_CACHE_INIT_SIZE (size_t)1024 * 1024 * 1024 // 1gb
#define DEFAULT_CACHE_MAX_SIZE (size_t)10 * 1024 * 1024 * 1024 // 10gb

#define MIN_CACHE_INIT_SIZE 0
#define MAX_CACHE_INIT_SIZE (size_t)10 * 1024 * 1024 * 1024 // 10gb

#define MIN_CACHE_MAX_SIZE 0
#define MAX_CACHE_MAX_SIZE (size_t)10 * 1024 * 1024 * 1024 // 10gb

#define MIN_CACHE_TTL 0 // 0 - not_ttl, in seconds
#define MAX_CACHE_TTL (unsigned int)1024 * 1024 * 1024 * 4 // max uint32

#define HASH_TABLE_SIZE 10000
#define HASH_PARAM HASH_TABLE_SIZE - 1

typedef enum {
    DATA,
    HAVE_WRITER,
    NO_WRITER,
    NO_DATA,
    CACHE_ERR,
    FINISH
} cache_data_status;

typedef struct wait_list {
    struct wait_list* next;
    int pipe_fd;
} wait_list;

typedef struct cache_req {
    cache_data_status data_status;
    char* url;
    char* content;
    time_t load_time;
    int content_offset;
    int content_size;
    struct cache_req* next;
    wait_list* wait_l;
} cache_req;

typedef struct cache_bascket {
    pthread_spinlock_t lock;
    cache_req* first;
    cache_req* last;
} cache_bascket;

int init_cache(size_t cache_size, int ttl_s);
int add_cache_content(char* key, char* content, int content_size);
int add_cache_req(char* key, int content_size);
int add_cache_cd(char* key, int fd);
cache_data_status get_cache(char* key, char* buffer, int buffer_size, int content_offset, int* count_data);
int finish_cache();

#endif
