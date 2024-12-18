#include <errno.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "cache.h"
#include "cache_allocator.h"

cache_bascket** cache = NULL;
int cache_ttl_s;

#define save_pthread_spin_lock(lock) \
    err = pthread_spin_lock(lock); \
    if (err != 0) { \
		printf(" pthread_spin_lock() failed: %s\n", strerror(err)); \
	    return -1; \
    }

#define save_pthread_spin_unlock(lock) \
    err = pthread_spin_unlock(lock); \
    if (err != 0) { \
		printf(" pthread_spin_unlock() failed: %s\n", strerror(err)); \
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
        err = pthread_spin_init(&bascket->lock, PTHREAD_PROCESS_PRIVATE);
        if (err != 0){
            printf("queue_init: pthrpthread_spin_init() failed: %s\n", strerror(err));
            abort();
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
int add_cache_content(char* key, char* content, int content_size) {
    uint32_t hash =  hash_function_horner(key);
    cache_bascket* hash_basket = cache[hash];

    int err;
    save_pthread_spin_lock(&hash_basket->lock);

    if (hash_basket == NULL) {
        fprintf(stderr, "bascket isn't exist\n");
        save_pthread_spin_unlock(&hash_basket->lock);
        return -1;
    }
    cache_req* cur_req = hash_basket->first;
    while (cur_req != NULL) {
        if (strncmp(cur_req->url, key, strlen(key) + 1) == 0) {
            memcpy(cur_req->content + cur_req->content_offset, content, content_size);
            cur_req->content_offset += content_size;
            cur_req->content[cur_req->content_offset] = '\0';
            if (cur_req->content_offset == cur_req->content_size) {
                cur_req->data_status = ALL_DATA;
            }
            time_t cur_time = time(NULL);
            if (cur_time == (time_t) -1) {
                fprintf(stderr, "get_cache: can't get current time %s\n", strerror(errno));
                save_pthread_spin_unlock(&hash_basket->lock);
                return -1;
            }
            cur_req->load_time = cur_time;
            save_pthread_spin_unlock(&hash_basket->lock);
            return 0;
        }
        cur_req = cur_req->next;
    }
    fprintf(stderr, "can't find \n");
    save_pthread_spin_unlock(&hash_basket->lock);
    return -1;
}

int add_cache_req(char* key, int content_size) {
    uint32_t hash =  hash_function_horner(key);
    cache_bascket* hash_basket = cache[hash];
    int err;

    save_pthread_spin_lock(&hash_basket->lock);

    if (hash_basket->first == NULL) {
        hash_basket->last = hash_basket->first = (cache_req*)malloc(sizeof(cache_req));
        if (hash_basket->last == NULL) {
            fprintf(stderr, "malloc error: can't alloc memmory\n");
            save_pthread_spin_unlock(&hash_basket->lock);
            return -1;
        }
    } else {
        hash_basket->last->next = (cache_req*)malloc(sizeof(cache_req));
        if (hash_basket->last->next == NULL) {
            fprintf(stderr, "malloc error: can't alloc memmory\n");
            save_pthread_spin_unlock(&hash_basket->lock);
            return -1;
        }
        hash_basket->last = hash_basket->last->next;
    }
    hash_basket->last->content_offset = 0;
    hash_basket->last->load_time = time(NULL);
    if (hash_basket->last->load_time  == (time_t) -1) {
        fprintf(stderr, "can't get current time %s\n", strerror(errno));
        save_pthread_spin_unlock(&hash_basket->lock);
        return -1;
    }
    hash_basket->last->next = NULL;
    hash_basket->last->url = alloc_mem(strlen(key) + 1);
    if (hash_basket->last->url == NULL) {
        save_pthread_spin_unlock(&hash_basket->lock);
        return -1;
    }
    memcpy(hash_basket->last->url, key, strlen(key) + 1);
    hash_basket->last->content = alloc_mem(content_size + 1);
    hash_basket->last->content_size = content_size;
    if (hash_basket->last->content == NULL) {
        free_mem(hash_basket->last->url);
        save_pthread_spin_unlock(&hash_basket->lock);
        return -1;
    }
    hash_basket->last->data_status = HAVE_WRITER;
    save_pthread_spin_unlock(&hash_basket->lock);
    return 0;
}

cache_data_status get_cache(char* key, char* buffer, int buffer_size, int content_offset, int* count_data) {
    uint32_t hash =  hash_function_horner(key);
    cache_bascket* hash_basket = cache[hash];

    if (hash_basket == NULL) {
        fprintf(stderr, "hash_basket is null\n");
        return CACHE_ERR;
    }

    int err;
    printf("try lick \n");
    save_pthread_spin_lock(&hash_basket->lock);
    printf("suc lick \n");

    cache_req* cur_req = hash_basket->first;
    while (cur_req != NULL) {
        printf("cur_req->url %s key %s  %d \n", cur_req->url, key, strncmp(cur_req->url, key, strlen(key) + 1));
        if (strncmp(cur_req->url, key, strlen(key) + 1) == 0) {
            time_t cur_time = time(NULL);
            if (cur_time == (time_t) -1) {
                fprintf(stderr, "get_cache: can't get current time %s\n", strerror(errno));
                save_pthread_spin_unlock(&hash_basket->lock);
                return CACHE_ERR;
            }
            double time_diff = (double)(cur_req->load_time - cur_time);
            if (cache_ttl_s != 0 &&  time_diff >= cache_ttl_s) {
                printf("TTL\n");
                free_mem(cur_req->content);
                free_mem(cur_req->url);
                save_pthread_spin_unlock(&hash_basket->lock);
                return NO_DATA;
            }
            cache_data_status ret_status = cur_req->data_status;
            printf("cur_req->content_size(%d) - content_offset(%d) < buffer_size(%d) \n",cur_req->content_size, content_offset, buffer_size);
            if (cur_req->content_size - content_offset < buffer_size) {
                ret_status = FINISH;
                *count_data = cur_req->content_size - content_offset;
            } else {
                *count_data = buffer_size;
            }
            memcpy(buffer, cur_req->content + content_offset, *count_data);
            save_pthread_spin_unlock(&hash_basket->lock);
            return ret_status;
        }
        cur_req = cur_req->next;
    }

    save_pthread_spin_unlock(&hash_basket->lock);
    return NO_DATA;
}


int finish_cache() {
    for (int i = 0; i < HASH_TABLE_SIZE; ++i) {
        cache_bascket* bascket = cache[i];
        if (bascket != NULL) {
            cache_req* cur_req = bascket->first;
            while (cur_req != NULL) {
                cache_req* next_req = cur_req->next;
                free(cur_req);
                cur_req = next_req;
            }
            int err = pthread_spin_destroy(&bascket->lock);
            if (err != 0) {
                printf(" pthread_spin_destroy() failed: %s\n", strerror(err));
                return -1;
            }
        }
        free(bascket);
    }
    finish_alloc();
    return 0;
}
