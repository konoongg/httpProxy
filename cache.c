#include <errno.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "cache.h"
#include "cache_allocator.h"

cache_bascket** cache = NULL;
int cache_ttl_s;

#define save_pthread_spin_lock(lock) \
    err = pthread_spin_lock(lock); \
    if (err != 0) { \
		fprintf(stderr, "pthread_spin_lock() failed: %s\n", strerror(err)); \
	    return -1; \
    }

#define save_pthread_spin_unlock(lock) \
    err = pthread_spin_unlock(lock); \
    if (err != 0) { \
		fprintf(stderr, "pthread_spin_unlock() failed: %s\n", strerror(err)); \
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
            fprintf(stderr, "pthrpthread_spin_init() failed: %s\n", strerror(err));
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

int send_wake_up(cache_req* cur_req) {
    wait_list* cur_wait_node = cur_req->wait_l;
    while (cur_wait_node != NULL) {
        char mes = 'w';
        int err =  write(cur_wait_node->pipe_fd, &mes, 1);
        if (err == 1) {
            wait_list* node = cur_wait_node->next;
            free(cur_wait_node);
            cur_wait_node = node;
        } else if (err < 0) {
            fprintf(stderr, "write: %s\n", strerror(errno));
            return -1;
        }
    }
    cur_req->wait_l = NULL;
    return 0;
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
            if (cur_req->content  == NULL) {
                save_pthread_spin_unlock(&hash_basket->lock);
                return -1;
            }
            memcpy(cur_req->content + cur_req->content_offset, content, content_size);
            cur_req->content_offset += content_size;
            cur_req->content[cur_req->content_offset] = '\0';
            if (cur_req->content_offset == cur_req->content_size) {
                cur_req->data_status = DATA;
            } else {
                cur_req->data_status = HAVE_WRITER;
            }
            time_t cur_time = time(NULL);
            if (cur_time == (time_t) -1) {
                fprintf(stderr, "get_cache: can't get current time %s\n", strerror(errno));
                save_pthread_spin_unlock(&hash_basket->lock);
                return -1;
            }
            cur_req->load_time = cur_time;

            int err = send_wake_up(cur_req);
            save_pthread_spin_unlock(&hash_basket->lock);
            return err;
        }
        cur_req = cur_req->next;
    }
    fprintf(stderr, "can't find key\n");
    save_pthread_spin_unlock(&hash_basket->lock);
    return -1;
}

int add_cache_req(char* key, int content_size) {
    uint32_t hash =  hash_function_horner(key);
    cache_bascket* hash_basket = cache[hash];
    int err;
    save_pthread_spin_lock(&hash_basket->lock);

    cache_req* cur_req = hash_basket->first;
    while (cur_req != NULL) {
        if (strncmp(cur_req->url, key, strlen(key) + 1) == 0) {
            cur_req->content_offset = 0;
            cur_req->load_time = time(NULL);
            if (cur_req->load_time  == (time_t) -1) {
                fprintf(stderr, "can't get current time %s\n", strerror(errno));
                save_pthread_spin_unlock(&hash_basket->lock);
                return -1;
            }
            cur_req->next = NULL;
            cur_req->content = alloc_mem(content_size + 1);
            cur_req->content_size = content_size;
            if (cur_req->content == NULL) {
                free_mem(cur_req->url);
                save_pthread_spin_unlock(&hash_basket->lock);
                return -1;
            }
            hash_basket->last->data_status = HAVE_WRITER;
            save_pthread_spin_unlock(&hash_basket->lock);
            return 0;
        }
    }
    save_pthread_spin_unlock(&hash_basket->lock);
    return -1;
}

int add_cache_cd(char* key, int fd) {
    uint32_t hash =  hash_function_horner(key);
    cache_bascket* hash_basket = cache[hash];

    if (hash_basket == NULL) {
        fprintf(stderr, "hash_basket is null\n");
        return -1;
    }

    int err;
    save_pthread_spin_lock(&hash_basket->lock);

    cache_req* cur_req = hash_basket->first;
    while (cur_req != NULL) {
        if (strncmp(cur_req->url, key, strlen(key) + 1) == 0) {
            if (cur_req->wait_l == NULL) {
                cur_req->wait_l = (wait_list*)malloc(sizeof(wait_list));
                if (cur_req->wait_l == NULL) {
                    fprintf(stderr, "malloc error: can't alloc memmory\n");
                    save_pthread_spin_unlock(&hash_basket->lock);
                    return -1;
                }
                cur_req->wait_l->pipe_fd = fd;
                cur_req->wait_l->next = NULL;
            } else {
                wait_list* cur_node = cur_req->wait_l;
                while (true) {
                    if (cur_node->next == NULL) {
                        cur_node->next = (wait_list*)malloc(sizeof(wait_list));
                        if (cur_node->next == NULL) {
                            fprintf(stderr, "malloc error: can't alloc memmory\n");

                            save_pthread_spin_unlock(&hash_basket->lock);
                            return -1;
                        }
                        cur_node->next->next = NULL;
                        cur_node->next->pipe_fd = fd;
                        break;
                    }
                    cur_node = cur_node->next;
                }
            }
            save_pthread_spin_unlock(&hash_basket->lock);
            return 0;
        }
        cur_req = cur_req->next;
    }
    fprintf(stderr, "can't find key\n");
    save_pthread_spin_unlock(&hash_basket->lock);
    return -1;
}

int free_cache_req(char* key) {
    if (key == NULL) {
        return 0;
    }
    printf("FREE KEY %s \n", key);
    uint32_t hash =  hash_function_horner(key);
    cache_bascket* hash_basket = cache[hash];

    if (hash_basket == NULL) {
        fprintf(stderr, "hash_basket is null\n");
        return -1;
    }

    int err;
    save_pthread_spin_lock(&hash_basket->lock);

    cache_req* cur_req = hash_basket->first;
    cache_req* prev_req = NULL;
    while (cur_req != NULL) {
        if (strncmp(cur_req->url, key, strlen(key) + 1) == 0) {
            free_mem(cur_req->url);
            free_mem(cur_req->content);
            int err = send_wake_up(cur_req);
            if (prev_req == NULL) {
                hash_basket->first = cur_req->next;
            } else {
                prev_req->next = cur_req->next;
            }
            free(cur_req);
            save_pthread_spin_unlock(&hash_basket->lock);
            return err;
        }
        prev_req = cur_req;
        cur_req = cur_req->next;
    }
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

    save_pthread_spin_lock(&hash_basket->lock);;
    if (hash_basket->first == NULL) {
        hash_basket->last = hash_basket->first = (cache_req*)malloc(sizeof(cache_req));
        if (hash_basket->last == NULL) {
            fprintf(stderr, "malloc error: can't alloc memmory\n");
            save_pthread_spin_unlock(&hash_basket->lock);
            return CACHE_ERR;
        }
        hash_basket->last->url = alloc_mem(strlen(key) + 1);
        if (hash_basket->last->url == NULL) {
            save_pthread_spin_unlock(&hash_basket->lock);
            return CACHE_ERR;
        }
        memcpy(hash_basket->last->url, key, strlen(key) + 1);
        hash_basket->last->content = NULL;
        hash_basket->last->content_offset = 0;
        hash_basket->last->data_status = HAVE_WRITER;
        hash_basket->last->wait_l = NULL;
        hash_basket->last->next = NULL;

        time_t cur_time = time(NULL);
        if (cur_time == (time_t) -1) {
            fprintf(stderr, "get_cache: can't get current time %s\n", strerror(errno));
            save_pthread_spin_unlock(&hash_basket->lock);
            return CACHE_ERR;
        }

        hash_basket->last->load_time = cur_time;
        save_pthread_spin_unlock(&hash_basket->lock);
        return NO_DATA;
    }

    cache_req* cur_req = hash_basket->first;
    cache_req* prev_req = NULL;
    while (cur_req != NULL) {
        if (strncmp(cur_req->url, key, strlen(key) + 1) == 0) {
            time_t cur_time = time(NULL);
            if (cur_time == (time_t) -1) {
                fprintf(stderr, "get_cache: can't get current time %s\n", strerror(errno));
                save_pthread_spin_unlock(&hash_basket->lock);
                return CACHE_ERR;
            }
            double time_diff = (double)(cur_time - cur_req->load_time);
            if (cache_ttl_s != 0 &&  time_diff >= cache_ttl_s) {
                free_mem(cur_req->content);
                cur_req->content = NULL;
                cur_req->content_offset = 0;
                cur_req->load_time = cur_time;
                cur_req->data_status = HAVE_WRITER;
                int err = send_wake_up(cur_req);
                if (err != 0) {
                    save_pthread_spin_unlock(&hash_basket->lock);
                    return CACHE_ERR;
                }
                cur_req->wait_l = NULL;
                save_pthread_spin_unlock(&hash_basket->lock);
                return NO_DATA;
            }
            cache_data_status ret_status = cur_req->data_status;
            if ((cur_req->content_size - content_offset < buffer_size) && (cur_req->content_offset == cur_req->content_size)) {
                ret_status = FINISH;
                *count_data = cur_req->content_size - content_offset;
            } else if (content_offset + buffer_size < cur_req->content_offset) {
                ret_status = DATA;
                *count_data = buffer_size;
            } else {
                save_pthread_spin_unlock(&hash_basket->lock);
                return ret_status;
            }
            memcpy(buffer, cur_req->content + content_offset, *count_data);
            save_pthread_spin_unlock(&hash_basket->lock);
            return ret_status;
        }
        prev_req = cur_req;
        cur_req = cur_req->next;
    }

    prev_req = (cache_req*)malloc(sizeof(cache_req));
    if (prev_req == NULL) {
        fprintf(stderr, "malloc error: can't alloc memmory %s\n", strerror(errno));
        save_pthread_spin_unlock(&hash_basket->lock);
        return CACHE_ERR;
    }
    prev_req->url = alloc_mem(strlen(key) + 1);
    if (prev_req->url == NULL) {
        save_pthread_spin_unlock(&hash_basket->lock);
        return CACHE_ERR;
    }
    memcpy(prev_req->url, key, strlen(key) + 1);
    prev_req->content_offset = 0;
    prev_req->content = NULL;
    prev_req->data_status = HAVE_WRITER;
    prev_req->wait_l = NULL;
    prev_req->next = NULL;
    save_pthread_spin_unlock(&hash_basket->lock);
    return NO_DATA;
}


int finish_cache() {
    for (int i = 0; i < HASH_TABLE_SIZE; ++i) {
        cache_bascket* bascket = cache[i];
        if (bascket != NULL) {
            cache_req* cur_req = bascket->first;
            while (cur_req != NULL) {
                wait_list* cur_node = cur_req->wait_l;
                while(cur_node != NULL) {
                    wait_list* node =  cur_node->next;
                    free(cur_node);
                    cur_node = node;
                }
                cache_req* next_req = cur_req->next;
                free(cur_req);
                cur_req = next_req;
            }
            int err = pthread_spin_destroy(&bascket->lock);
            if (err != 0) {
                fprintf(stderr, "pthread_spin_destroy() failed: %s\n", strerror(err));
                return -1;
            }
        }
        free(bascket);
    }
    finish_alloc();
    return 0;
}
