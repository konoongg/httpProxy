#include <errno.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "cache.h"
#include "cache_allocator.h"

cache_bascket** cache = NULL;
int cache_ttl_s;
 
#define save_rwlock_unlock(lock) \
    err = pthread_rwlock_unlock(lock); \
    if (err != 0) { \
        printf(" pthread_rwlock_unlock() failed %s\n", strerror(err)); \
        return -1;\
    } 

#define save_rwlock_rdlock(lock) \
    err = pthread_rwlock_rdlock(lock); \
    if (err != 0) { \
        printf("pthread_rwlock_rdlock() failed: %s\n", strerror(err)); \
        return -1; \
    }

#define save_rwlock_wrlock(lock) \
    err = pthread_rwlock_wrlock(lock);\
        if (err != 0) { \
            printf("pthread_rwlock_wrlock() failed: %s\n", strerror(err)); \
            return -1; \
        }

int init_cache(size_t cache_size, int ttl_s) {
    cache_ttl_s = ttl_s;
    int err = init_alloc(cache_size);
    if (err == -1) {
        return -1;
    }
    cache = (cache_bascket**)malloc(HASH_TABLE_SIZE * sizeof(cache_bascket*));
    if (cache == NULL) {
        fprintf(stderr, "malloc error: can't alloc memmory\n");
        return -1;
    }
    memset(cache, 0, HASH_TABLE_SIZE * sizeof(cache_bascket*));
    for (int i = 0; i < HASH_TABLE_SIZE; ++i) {
        cache[i] = (cache_bascket*)malloc(sizeof(cache_bascket));
        memset(cache[i], 0, sizeof(cache_bascket));
        cache_bascket* bascket = cache[i];
        if (bascket == NULL) {
            fprintf(stderr, "malloc error: can't alloc memmory\n");
            return -1;
        }
        int err = pthread_rwlock_init(&bascket->lock, NULL);
        if (err != 0) {
            printf("queue_init: pthrpthread_spin_init() failed: %s\n", strerror(err));
            return -1;
        }
    }
    return 0;
}

uint32_t hash_function_horner(char* key) {
    uint32_t hash_result = 0;
    for (int i = 0; i < strlen(key); ++i) {
        hash_result += (HASH_PARAM * hash_result + key[i]) % HASH_TABLE_SIZE;
    }
    hash_result = (hash_result * 2 + 1) % HASH_TABLE_SIZE;
    return hash_result;
}

//content without \0
int add_req_content(char* key, char* content) {
    uint32_t hash =  hash_function_horner(key);
    cache_bascket* hash_basket = cache[hash];

    int err;
    save_rwlock_wrlock(&hash_basket->lock);

    if (hash_basket == NULL) {
        fprintf(stderr, "bascket isn't exist\n");
        save_rwlock_unlock(&hash_basket->lock);
        return -1;
    }
    cache_req* cur_req = hash_basket->first;
    while (cur_req != NULL) {
        if (strncmp(cur_req->url, key, strlen(key) + 1) == 0) {
            int content_size = strlen(content);
            memcpy(cur_req->content + cur_req->content_offset, content, content_size);
            cur_req->content_offset += content_size;
            cur_req->content[cur_req->content_offset] = '\0';
            save_rwlock_unlock(&hash_basket->lock);
            return 0;
        }
        cur_req = cur_req->next;
    }
    fprintf(stderr, "can't find \n");
    save_rwlock_unlock(&hash_basket->lock);
    return -1;
}

int add_cache_req(char* key, int content_size) {
    uint32_t hash =  hash_function_horner(key);
    cache_bascket* hash_basket = cache[hash];
    int err;

    save_rwlock_wrlock(&hash_basket->lock);

    if (hash_basket->first == NULL) {
        hash_basket->last = hash_basket->first = (cache_req*)malloc(sizeof(cache_req));
        fprintf(stderr, "malloc error: can't alloc memmory\n");
        save_rwlock_unlock(&hash_basket->lock);
        return -1;
    } else {
        hash_basket->last->next = (cache_req*)malloc(sizeof(cache_req));
        if (hash_basket->last->next == NULL) {
            fprintf(stderr, "malloc error: can't alloc memmory\n");
            save_rwlock_unlock(&hash_basket->lock);
            return -1;
        }
        hash_basket->last = hash_basket->last->next;
    }
    hash_basket->last->content_offset = 0;
    hash_basket->last->load_time = time(NULL);
    if (hash_basket->last->load_time  == (time_t) -1) {
        fprintf(stderr, "can't get current time %s\n", strerror(errno));
        save_rwlock_unlock(&hash_basket->lock);
        return -1;
    }
    hash_basket->last->next = NULL;
    hash_basket->last->url = alloc_mem(strlen(key) + 1);
    if (hash_basket->last->url == NULL) {
        save_rwlock_unlock(&hash_basket->lock);
        return -1;
    }
    memcpy(hash_basket->last->url, key, strlen(key) + 1);
    hash_basket->last->content = alloc_mem(content_size + 1);
    if (hash_basket->last->url == NULL) {
        free_mem(hash_basket->last->url);
        save_rwlock_unlock(&hash_basket->lock);
        return -1;
    }
    
    save_rwlock_unlock(&hash_basket->lock);
    return 0;
}

int get_cache(char* key, char** content, int content_offset) {
    uint32_t hash =  hash_function_horner(key);
    cache_bascket* hash_basket = cache[hash];
    if (hash_basket == NULL) {
        fprintf(stderr, "hash_basket is null\n");
        return -1;
    }

    int err;
    save_rwlock_rdlock(&hash_basket->lock);

    cache_req* cur_req = hash_basket->first;
    while (cur_req != NULL) {
        if (strncmp(cur_req->url, key, strlen(key) + 1) == 0) {
            time_t cur_time = time(NULL);
            if (cur_time == (time_t) -1) {
                fprintf(stderr, "get_cache: can't get current time %s\n", strerror(errno));
                save_rwlock_unlock(&hash_basket->lock);
                *content = NULL;
                return -1;
            }
            double time_diff = (double)(cur_req->load_time - cur_time);
            if (cache_ttl_s != 0 &&  time_diff >= 5) {
                save_rwlock_unlock(&hash_basket->lock);

                save_rwlock_wrlock(&hash_basket->lock);
                free_mem(cur_req->content);
                free_mem(cur_req->url);
                save_rwlock_unlock(&hash_basket->lock);
                *content = NULL;
                return 0;
            }
            *content = cur_req->content + content_offset;
            return 0;
        }
        cur_req = cur_req->next;
    }
    
    save_rwlock_unlock(&hash_basket->lock);
    *content = NULL;
    return 0;
}


void finish_cache() {
    for (int i = 0; i < HASH_TABLE_SIZE; ++i) {
        cache_bascket* bascket = cache[i];
        if (bascket != NULL) {
            cache_req* cur_req = bascket->first;
            while (cur_req != NULL) {
                cache_req* next_req = cur_req->next;
                free(cur_req);
                cur_req = next_req;
            }
        }
        free(bascket);
    }
    finish_alloc();
}
