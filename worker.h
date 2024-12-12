#ifndef WORKER_H
#define WORKER_H

#include "structs.h"

#define BACKLOG_SIZE 512

#define SQ_SIZE 4096

#define DEFAULT_COUNT_WORKER 4
#define MIN_COUNT_WORKER 1
#define MAX_COUNT_WORKER 100


#define MAX_CONNECTIONS 1024
#define MAX_PROCCESSING_EV 100


int init_workers(int count_worker, int listen_port, pthread_t* tids);

typedef struct worker_info {
    int port;
} worker_info;

typedef enum {
    FIN,
    FIN_WITH_RING
} fin_mode;


typedef struct worker_end {
    fin_mode mode;
    int s_fd;
    struct io_uring* ring;
    conn_info* conns;

} worker_end;

pars_status pars_data(conn_info* conn);
#endif
