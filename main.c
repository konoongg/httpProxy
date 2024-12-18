#include <errno.h>
#include <stdio.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <pthread.h>

#include "worker.h"
#include "cache.h"

#define MIN_PORT_NUM 1
#define MAX_PORT_NUM 65535
#define DEFAULT_PORT_NUM 8080

#define uint32 unsigned int

#define check_count_arg(i, argc, message) \
    if ((i) + 1 >= (argc)) { \
        fprintf(stderr, (message)); \
        exit(EXIT_FAILURE); \
    }

#define send_sig_threads(set, tids, signum) \
    if (set != NULL && tids != NULL) { \
        for (int i = 0; i < set->max_count_threads; ++i) { \
            int err = pthread_kill(tids[i], signum); \
            if (err == -1){ \
                printf("main: pthread_cancel(%ld) failed: %s\n", tids[i], strerror(err)); \
            } \
        } \
    }

#define save_finish_cache()\
    err = finish_cache();\
    if (err != 0) { \
        printf("Incorrect cache release \n"); \
        exit(EXIT_FAILURE); \
    }

typedef struct settings {
  uint32 port;
  uint32 max_count_threads;
  size_t init_cache_size;
  size_t max_cache_size;
  uint32 cache_ttl;
} settings;

pthread_t* tids = NULL;
settings* set = NULL;

void signal_handler(int signal) {
    if (signal == SIGINT) {
        printf("are you want fast shutdowm[y/n]");
        char c = getchar();
        if (c == EOF) {
            fprintf(stderr, "can't getchar\n");
            exit(EXIT_FAILURE);
        } else if (c == 'y') {
            printf("fast shutdown\n");
            exit(EXIT_SUCCESS);
        } else  {
            printf("don't fast shutdown (you have written %c)\n", c);
        }
    } else if (signal == SIGTERM) {
        send_sig_threads(set, tids, SIGUSR1);
        printf("SHUTDOWN WITH FREE");
    } else if (signal == SIGQUIT) {
        send_sig_threads(set, tids, SIGUSR2);
        printf("SHUTDOWN WITH WAIT \n");
    } else {
        fprintf(stderr, "unknown signal\n");
    }
}

int init_sig_handlers() {
    struct sigaction sa;
    sa.sa_handler = signal_handler;
    int err = sigemptyset(&sa.sa_mask);
    if (err == -1) {
        fprintf(stderr, "sigemptyset ERROR%s\n", strerror(errno));
        return -1;
    }
    sa.sa_flags = 0;
    if (sigaction(SIGINT, &sa, NULL) == -1) {
        fprintf(stderr, "Failed to set signal handler for SIGINT%s\n", strerror(errno));
        return 1;
    }
    if (sigaction(SIGTERM, &sa, NULL) == -1) {
        fprintf(stderr, "Failed to set signal handler for SIGTERM%s\n", strerror(errno));
        return 1;
    }

    if (sigaction(SIGQUIT, &sa, NULL) == -1) {
        fprintf(stderr, "Failed to set signal handler for SIGQUIT%s\n", strerror(errno));
        return 1;
    }
    return 0;
}


void print_help() {
    printf("\n\n");
    printf("use makefile for build\n");
    printf("To run the application, use: ./httpProxy\n");
    printf("--port | -p - The port on which the proxy listens. Default is 8080 \n");
    printf("--max-client-threads | -t  - The maximum number of working threads (size of the client connection pool). Default is 4.\n");
    printf("--help | -h - Displays a message on how to run the proxy, possible flags, and their descriptions \n");
    printf("--cache-initial-size | -i  - Initial cache size. Default is 1MB. format [value][b | kb | mb | gb]\n");
    printf("--cache-max-size | -m - Maximum cache size. Default is 10MB. format [value][kb| mb | b]\n");
    printf("--cache-ttl | -l - Cache entry time to live in seconds. Default is 5 seconds\n");
    printf("\n\n");
}

//reads a number and returns it if it was successfully read and lies within the specified range;
// the pointer to the remainder of the string is returned in endptr
int pars_int(char* str, size_t min_val, size_t max_val, char** endptr) {
    errno = 0;
    int val =  (int)strtol(str, endptr, 10);
    if (endptr != NULL && *endptr == str) {
        fprintf(stderr, "No digits were found\n");
        exit(EXIT_FAILURE);
    }
    if (errno != 0) {
        perror("strtol");
        exit(EXIT_FAILURE);
    }
    if (val > max_val || val < min_val) {
        fprintf(stderr, "val is %d, but min_val: %ld, max_val: %ld\n", val, min_val, max_val);
        exit(EXIT_FAILURE);
    }
    return val;
}

//defines memory measurement units
int define_size_scale(char* str) {
	if (strncmp(str, "b", 2) == 0) {
        return 1;
	} else if (strncmp(str, "kb", 3) == 0) {
        return 1024;
	} else if (strncmp(str, "mb", 3) == 0) {
        return 1024 * 1024;
	}else if (strncmp(str, "gb", 3) == 0) {
        return 1024 * 1024 * 1024;
	} else {
        fprintf(stderr, "Unknown size scale: %s\n", str);
        exit(EXIT_FAILURE);
	}
}


// init settings,  if help return 1, else 0
int proccess_flags(int argc, char** argv, settings* set) {
    set->port = DEFAULT_PORT_NUM;
    set->max_count_threads = DEFAULT_COUNT_WORKER;
    set->init_cache_size = DEFAULT_CACHE_INIT_SIZE;
    set->max_cache_size = DEFAULT_CACHE_MAX_SIZE;
    for(int i = 1; i < argc; i++){
        if(strncmp(argv[i], "--help", 6) == 0 || strncmp(argv[i], "-h", 2) == 0) {
            print_help();
            return 1;
        } else if (strncmp(argv[i], "--port", 7) == 0 || strncmp(argv[i], "-p", 3) == 0) {
            check_count_arg(i, argc, "Port must be given an integer\n");
            ++i;
            set->port = pars_int(argv[i], MIN_PORT_NUM, MAX_PORT_NUM, NULL);
        } else if (strncmp(argv[i], "--max-client-threads", 21) == 0 || strncmp(argv[i], "-t", 3) == 0) {
            check_count_arg(i, argc, "max client threads must be given an integer\n");
            ++i;
            set->max_count_threads = pars_int(argv[i], MIN_COUNT_WORKER, MAX_COUNT_WORKER, NULL);
        } else if (strncmp(argv[i], "--cache-initial-size", 21) == 0 || strncmp(argv[i], "-i", 3) == 0) {
            check_count_arg(i, argc, "cache initial size must be given an integer\n");
            ++i;
            char* endptr;
			set->init_cache_size = pars_int(argv[i], MIN_CACHE_INIT_SIZE, MAX_CACHE_INIT_SIZE, &endptr);
           	set->init_cache_size *= define_size_scale(endptr);
        } else if (strncmp(argv[i], "--cache-max-size", 17) == 0 || strncmp(argv[i], "-m", 3) == 0) {
            check_count_arg(i, argc, "cache max size must be given an integer\n");
            ++i;
            char* endptr;
			set->max_cache_size = pars_int(argv[i], MIN_CACHE_MAX_SIZE, MAX_CACHE_MAX_SIZE, &endptr);
           	set->max_cache_size *= define_size_scale(endptr);
        } else if (strncmp(argv[i], "--cache-ttl", 12) == 0 || strncmp(argv[i], "-l", 3) == 0) {
            check_count_arg(i, argc, "cache ttl must be given an integer\n");
            ++i;
			set->cache_ttl = pars_int(argv[i], MIN_CACHE_TTL, MAX_CACHE_TTL, NULL);
        } else {
            fprintf(stderr, "unknown arg %s\n", argv[i]);
        }
    }
    return 0;
}

int main(int argc, char** argv) {
    printf("PID: %d \n", getpid());
    set = (settings*)(malloc(sizeof(settings)));
    if (set == NULL) {
        fprintf(stderr, "can't malloc %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    int isHelp = proccess_flags(argc, argv, set);
    if (isHelp == 1) {
        free(set);
        return 0;
    }
    int err = init_sig_handlers();
    if (err != 0) {
        free(set);
        exit(EXIT_FAILURE);
    }

    err = init_cache(set->init_cache_size, set->cache_ttl);
    if (err != 0) {
        free(set);
        exit(EXIT_FAILURE);
    }

    tids = (pthread_t*)malloc(set->max_count_threads * sizeof(pthread_t));
    if (tids == NULL) {
        fprintf(stderr, "can't alloc memmro: %s\n", strerror(errno));
        free(set);
        save_finish_cache();
        exit(EXIT_FAILURE);
    }
    err = init_workers(set->max_count_threads, set->port, tids);
    if (err != 0) {
        free(set);
        save_finish_cache();
        exit(EXIT_FAILURE);
    }

    save_finish_cache();
    free(set);
    free(tids);
    printf("finish\n");
    return 0;
}
