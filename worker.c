#define _GNU_SOURCE

#include <assert.h>
#include <liburing.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <sys/socket.h>
#include <pthread.h>
#include <threads.h>
#include <netinet/in.h>

#include "cache.h"
#include "data_parser.h"
#include "proccess_http.h"
#include "structs.h"
#include "worker.h"

thread_local int shutdown_with_wait;
thread_local conn_info* conns = NULL;
thread_local int conns_size = MAX_CONNECTIONS;
thread_local int listen_socket_fd = -1;

#define get_sqe(ring, sqe) \
    sqe = io_uring_get_sqe(ring); \
    if (sqe == NULL) { \
        fprintf(stderr, "io_uring_get_sqe failed\n"); \
        return -1; \
    }

#define get_conn_i_id(conn_i, conn_i_id, fd) \
    conn_i_id = get_conn_i(conn_i, fd); \
    if (conn_i_id == -1) { \
        create_new_conn_i(); \
        for (int i = conns_size; i < 2 * conns_size; ++i)  {\
            int err = conn_init(&(conns[i])); \
            if (err == -1) { \
                return -1; \
            } \
        } \
        conn_i_id = get_conn_i(conn_i, fd); \
        if (conn_i_id == -1) { \
            return -1; \
        } \
    }

#define finalize(err, s_fd) \
    err = close(s_fd); \
    if (err == -1) { \
        fprintf(stderr, "close: %s\n", strerror(errno)); \
    } \
   	return NULL;

#define finalize_with_ring(err, s_fd, ring, coons, end) \
        printf("finalize_with_ring \n");\
        for (int i = 0; i < conns_size; ++i ) { \
            free_conn_info(&(coons[i])); \
        } \
        free(coons); \
        free(end); \
		io_uring_queue_exit(&ring); \
        finalize(err, s_fd); \
        printf("thread %d finished \n", gettid());

#define init_connection(connection) \
    connection->fd = -1; \
    connection->read_buffer_size = 0; \
    connection->size_http_res = 0; \
    connection->need_send_size = 0; \
    connection->http = (http_mes*)malloc(sizeof(http_mes)); \
    connection->http->domain = NULL; \
    connection->http->version = NULL; \
    connection->http->method = NULL; \
    connection->http->host = NULL; \
    connection->http->headers = NULL;\
    connection->http->status_mes = NULL;\
    connection->read_buffer = NULL; \
    connection->write_buffer = NULL; \
    connection->http_mes_buffer = NULL;

#define save_free(memmory) \
    free(memmory); \
    memmory = NULL;

#define free_connection(connection) \
        save_free(connection->http->domain); \
        save_free(connection->http->host); \
        save_free(connection->http->method); \
        save_free(connection->http->version); \
        save_free(connection->http->status_mes); \
        if (connection->http->headers != NULL) { \
            http_header* cur_header = connection->http->headers->first; \
            while (cur_header != NULL) { \
                http_header* next_header = (http_header*)cur_header->next; \
                save_free(cur_header->key); \
                save_free(cur_header->value); \
                save_free(cur_header); \
                cur_header = next_header; \
            } \
            save_free(connection->http->headers); \
        } \
        save_free(connection->http); \
        if (connection->fd != -1) { \
            err = close(connection->fd); \
            if ( err == -1) { \
                fprintf(stderr, "close: %s\n", strerror(errno)); \
                return -1; \
            } \
            connection->fd = -1; \
        }\
        save_free(connection->read_buffer);\
        save_free(connection->write_buffer);\
        save_free(connection->http_mes_buffer);\
        save_free(connection);


int create_new_conn_i() {
    conn_info* new_conns = (conn_info*)calloc(conns_size *2, sizeof(conn_info));
    if (conns == NULL) {
      	fprintf(stderr, "can't malloc %s\n", strerror(errno));
        return -1;
    }
    memcpy(new_conns, conns, conns_size * sizeof(conn_info));
    conns_size *= 2;
    free(conns);
    conns = new_conns;
    printf("create new connect struct: new size %d \n", conns_size);
    return 0;
}

int free_conn_info(conn_info* conn) {
    int err;
    save_free(conn->sockaddr);
    if (conn->client != NULL) {
        free_connection(conn->client);
    }
    if (conn->server != NULL) {
        free_connection(conn->server);
    };
    conn->type = ACCEPT;
    if (conn->cache_i != NULL) {
        if (!conn->cache_i->finish_write) {
            int err = free_cache_req(conn->cache_i->cache_key);
            if (err != 0) {
                printf("free_cache_req error \n");
            }
        }
        save_free(conn->cache_i->cache_key);
        if (conn->cache_i->pipe_open) {
            int err = close(conn->cache_i->pipe_fd[0]);
            if (err == -1) {
                fprintf(stderr, "close: %s\n", strerror(errno));
            }

            err = close(conn->cache_i->pipe_fd[1]);
            if (err == -1) {
                fprintf(stderr, "close: %s\n", strerror(errno));
            }
        }
    }
    save_free(conn->cache_i);
    return 0;
}


void cleanup_handler(void *arg) {
    worker_end* end = (worker_end*)arg;

    if (end->mode == FIN_WITH_RING) {
        for (int i = 0; i < conns_size; ++i ) {
            free_conn_info(&((end->conns)[i]));
        }
        free(end->conns);
		io_uring_queue_exit(end->ring);
    } else if (end->mode == FIN) {
        int err = close(end->s_fd); \
        if (err == -1) {
            fprintf(stderr, "cleanup_handler: close error %s\n", strerror(errno));
        }
    }

    free(end);
    printf("cleanup_handler %d \n" , gettid());
}

int conn_init(conn_info* conn_i) {
    if (conn_i->client == NULL) {
        conn_i->client = (connection*)malloc(sizeof(connection));
        if (conn_i->client == NULL) {
            fprintf(stderr, "close: %s\n", strerror(errno));
            return -1;
        }
        init_connection(conn_i->client);
    }
    if (conn_i->server == NULL) {
        conn_i->server = (connection*)malloc(sizeof(connection));
        if (conn_i->server == NULL) {
            fprintf(stderr, "close: %s\n", strerror(errno));
            return -1;
        }
        init_connection(conn_i->server);
    }
    if (conn_i->sockaddr == NULL) {
        conn_i->sockaddr = (struct sockaddr_in*)malloc(sizeof(struct sockaddr_in));
        if (conn_i->sockaddr == NULL) {
            fprintf(stderr, "can't malloc: %s\n", strerror(errno));
            return -1;
        }
        memset(conn_i->sockaddr , 0 , sizeof(struct sockaddr_in));
    }
    if (conn_i->cache_i == NULL) {
        conn_i->cache_i = (cache_info*)malloc(sizeof(cache_info));
        if (conn_i->cache_i == NULL) {
            fprintf(stderr, "can't malloc: %s\n", strerror(errno));
            return -1;
        }
        conn_i->cache_i->cache_key = NULL;
        conn_i->cache_i->read_from_cache = false;
        conn_i->cache_i->count_write = 0;
        conn_i->cache_i->write_without_cache = 0;
        conn_i->cache_i->pipe_open = false;
        conn_i->cache_i->finish_write = false;
    }
    return 0;
}

int get_conn_i(conn_info* conn_i, int fd) {
    for (int i = 0; i < conns_size; i++) {
        int err = conn_init(&(conn_i[i]));
        if (err == -1) {
            return -1;
        }
        if (conn_i[i].client->fd == fd || conn_i[i].server->fd == fd) {
        	return i;
        }
    }

    for (int i = 0; i < conns_size; i++) {
        if (conn_i[i].client->fd == -1) {
        	return i;
        }
    }
    return -1;
}

int add_accept(struct io_uring *ring, int fd, conn_info* conn_i) {
    struct io_uring_sqe* sqe;
    int conn_i_id;
    get_sqe(ring, sqe);
    get_conn_i_id(conn_i, conn_i_id, fd);
    conn_info* conn = &conn_i[conn_i_id];

    conn->client->read_buffer = (char*)malloc(MAX_MESSAGE_LEN * sizeof(char));
    if (conn->client->read_buffer == NULL) {
        fprintf(stderr, "can't malloc: %s\n", strerror(errno));
        return -1;
    }
    conn->client->write_buffer = (char*)malloc(MAX_MESSAGE_LEN * sizeof(char));
    if (conn->client->write_buffer == NULL) {
        fprintf(stderr, "can't malloc: %s\n", strerror(errno));
        return -1;
    }
    conn->client->http_mes_buffer = (char*)malloc(MAX_HTTP_SIZE * sizeof(char));
    if (conn->client->http_mes_buffer == NULL) {
        fprintf(stderr, "can't malloc: %s\n", strerror(errno));
        return -1;
    }


    conn->server->read_buffer = (char*)malloc(MAX_MESSAGE_LEN * sizeof(char));
    if (conn->server->read_buffer == NULL) {
        fprintf(stderr, "can't malloc: %s\n", strerror(errno));
        return -1;
    }
    conn->server->write_buffer = (char*)malloc(MAX_MESSAGE_LEN * sizeof(char));
    if (conn->server->write_buffer == NULL) {
        fprintf(stderr, "can't malloc: %s\n", strerror(errno));
        return -1;
    }
    conn->server->http_mes_buffer = (char*)malloc(MAX_HTTP_SIZE * sizeof(char));
    if (conn->server->http_mes_buffer == NULL) {
        fprintf(stderr, "can't malloc: %s\n", strerror(errno));
        return -1;
    }


    io_uring_prep_accept(sqe, fd, NULL, 0, 0);
    conn->client->fd = fd;
    conn->type = ACCEPT;
    io_uring_sqe_set_data(sqe, conn);
    return 0;
}

int add_socket_read_client(struct io_uring *ring, int fd, conn_info* conn) {
    struct io_uring_sqe* sqe;
    get_sqe(ring, sqe);

    connection* client = conn->client;
    io_uring_prep_recv(sqe, fd, (void*)(client->read_buffer + client->read_buffer_size), MAX_MESSAGE_LEN - client->read_buffer_size, 0);
    conn->type = READ;
    io_uring_sqe_set_data(sqe, conn);
    return 0;
}

int add_wait_cache(struct io_uring *ring, conn_info* conn) {
    struct io_uring_sqe* sqe;
    get_sqe(ring, sqe);
    cache_info* cache_i = conn->cache_i;
    io_uring_prep_read(sqe, cache_i->pipe_fd[0], &cache_i->cache_wake_up, 1, 0);
    conn->type = UPDATE_CACHE;
    io_uring_sqe_set_data(sqe, conn);
    return 0;
}

int add_socket_read_server(struct io_uring *ring, int fd, conn_info* conn, type_ev type) {
    struct io_uring_sqe* sqe;

    get_sqe(ring, sqe);
    connection* server = conn->server;
    io_uring_prep_recv(sqe, fd, (void*)(server->read_buffer + server->read_buffer_size), MAX_MESSAGE_LEN - server->read_buffer_size, 0);
    conn->type = type;
    io_uring_sqe_set_data(sqe, conn);
    return 0;
}

int add_socket_write_client(struct io_uring *ring, int fd, conn_info* conn) {
    struct io_uring_sqe* sqe;

    get_sqe(ring, sqe);
    connection* server = conn->server;
    io_uring_prep_send(sqe, fd, server->http_mes_buffer, server->size_http_res, 0);
    conn->type = WRITE;
    io_uring_sqe_set_data(sqe, conn);
    return 0;
}

int add_socket_write_server(struct io_uring* ring, int fd, conn_info* conn) {
    struct io_uring_sqe* sqe;
    get_sqe(ring, sqe);
    connection* client = conn->client;

    io_uring_prep_send(sqe, fd, client->http_mes_buffer, client->size_http_res, 0);
    conn->type = WRITE_TO_SERV;
    io_uring_sqe_set_data(sqe, conn);
    return 0;
}

void check_finish_proxing() {
    for (int i = 0; i < conns_size; ++i) {
        if (conns[i].type != ACCEPT) {
            return;
        }
    }
    pthread_exit(NULL);
}

void sig_thread_handler(int signal) {
    if (signal == SIGUSR1) {
        pthread_exit(NULL);
    } else  if (signal == SIGUSR2) {
        check_finish_proxing();
        shutdown_with_wait = 1;
    } else {
        fprintf(stderr, "unknown signal\n");
    }
}

int init_signals() {
    sigset_t mask;
    int err = sigfillset(&mask);
    if (err == -1) {
        fprintf(stderr, "init_signals: sigfillset error: %s\n", strerror(errno));
        return -1;
    }
    err = pthread_sigmask(SIG_BLOCK, &mask, NULL);
    if (err != 0) {
        fprintf(stderr, "init_signals: pthread_sigmask error: %s\n", strerror(err));
        return -1;
    }
    err = sigemptyset(&mask);
    if (err == -1) {
        fprintf(stderr, "init_signals: sigemptyset error: %s\n", strerror(errno));
        return -1;
    }
    err = sigaddset(&mask, SIGUSR1 );
    if (err == -1) {
        fprintf(stderr, "init_signals: sigaddset error: %s\n", strerror(errno));
        return -1;
    }
    err = sigaddset(&mask, SIGUSR2 );
    if (err == -1) {
        fprintf(stderr, "init_signals: sigaddset error: %s\n", strerror(errno));
        return -1;
    }
    err = pthread_sigmask(SIG_UNBLOCK, &mask, NULL);
    if (err != 0) {
        fprintf(stderr, "init_signals: pthread_sigmask error: %s\n", strerror(errno));
        return -1;
    }

    struct sigaction sa;
    err = sigemptyset(&sa.sa_mask);
    if (err == -1) {
        fprintf(stderr, "sigemptyset ERROR%s\n", strerror(errno));
        return -1;
    }
    sa.sa_flags = 0;
    sa.sa_handler = sig_thread_handler;
    err = sigaction(SIGUSR2, &sa, NULL);
    if (err == -1) {
        fprintf(stderr, "init_signals: sigaction error: %s\n", strerror(errno));
        return -1;
    }
    err = sigaction(SIGUSR1, &sa, NULL);
    if (err == -1) {
        fprintf(stderr, "init_signals: sigaction error: %s\n", strerror(errno));
        return -1;
    }
    return 0;
}


int create_server_connect(conn_info* conn, struct io_uring* ring) {
    printf("create_server_connect\n");
    connection* client = conn->client;
    int err = resolve_domain(client->http->host, conn->sockaddr);
    if (err == -1) {
        return -1;
    }

    int server_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (server_fd == -1) {
        fprintf(stderr, "socket failed: %s\n", strerror(errno));
        return -1;
    }
    conn->server->fd = server_fd;

    err = connect(server_fd, (struct sockaddr*)conn->sockaddr, sizeof(*(conn->sockaddr)));
    if (err == -1) {
        fprintf(stderr, "connect failed: %s\n", strerror(errno));
        return 0;
    }
    err = add_socket_write_server(ring, conn->server->fd, conn);
    if (err != 0) {
        return  -1;
    }
    printf("fnish create_server_connect\n");
    return 0;
}

proc_status proccess_accept(int res, conn_info* conn, struct io_uring* ring, conn_info* conns) {
    //printf("proccess_accept\n");
    if (shutdown_with_wait) {
        free_conn_info(conn);
        return PROC_CON;
    }
    if (res < 0) {
        fprintf(stderr, "ACCEPT failed %s \n", strerror(-res));
        return PROC_ERR;
    }
    printf("conn->client %p \n", conn->client);
    conn->client->fd = res;
    int err = add_socket_read_client(ring, res, conn);
    if (err != 0) {
        return PROC_ERR;
    }
    err = add_accept(ring, listen_socket_fd, conns);
     if (err != 0) {
        return PROC_ERR;
    }
    return PROC_OK;
}

proc_status proccess_cache(conn_info* conn, struct io_uring* ring) {
    printf("proccess_cache\n");
    connection* server = conn->server;
    cache_data_status status =  get_cache(conn->cache_i->cache_key, server->http_mes_buffer, MAX_HTTP_SIZE, conn->cache_i->count_write, &server->size_http_res);
    if (status == NO_DATA || status == CACHE_ERR ) {
        conn->cache_i->read_from_cache = false;
        conn->server->size_http_res = 0;
        int err = create_server_connect(conn, ring);
        if (err == -1) {
            return PROC_ERR;
        }
    } else if (status == HAVE_WRITER) {
        int err = pipe(conn->cache_i->pipe_fd);
        if (err == -1) {
            fprintf(stderr, "pipe error: %s", strerror(errno));
            int err = create_server_connect(conn, ring);
            if (err == -1) {
                return PROC_ERR;
            }
        }

        err = add_cache_cd(conn->cache_i->cache_key, conn->cache_i->pipe_fd[1]);
        if (err == -1) {
            int err = create_server_connect(conn, ring);
            if (err == -1) {
                return PROC_ERR;
            }
        }

        conn->cache_i->pipe_open = true;

        err = add_wait_cache(ring, conn);
        if (err != 0 ) {
            return PROC_ERR;
        }

    } else if (status == DATA) {
        conn->cache_i->read_from_cache = true;
        conn->cache_i->count_write += server->size_http_res;
        conn->server->need_send_size = server->size_http_res + 1;
        int err = add_socket_write_client(ring, conn->client->fd, conn);
        if (err != 0 ) {
            return PROC_ERR;
        }
    } else  if (status == FINISH) {
        conn->cache_i->read_from_cache = true;
        conn->cache_i->count_write += server->size_http_res;
        conn->server->need_send_size = server->size_http_res;
        int err = add_socket_write_client(ring, conn->client->fd, conn);
        if (err != 0 ) {
            return PROC_ERR;
        }
    } else {
        fprintf(stderr, "unknown cache data status \n");
        int err = create_server_connect(conn, ring);
        if (err == -1) {
            return PROC_ERR;
        }
    }
    return PROC_OK;
}

proc_status proccess_read(int res, conn_info* conn, struct io_uring* ring) {
    //printf("proccess_read \n");
    if (res < 0) {
        fprintf(stderr, "READ failed, disconnect %s\n", strerror(-res));
        return PROC_ERR;
    } else if (res == 0) {
        fprintf(stderr, "READ finish, disconnect\n");
        return PROC_ERR;
    } else {
        connection* client = conn->client;
        client->read_buffer_size += res;
        pars_status status = pars_head(conn->client, CLIENT);
        if (status == ALL_PARS) {
            if (conn->cache_i->cache_key == NULL) {
                conn->cache_i->cache_key = get_url(conn->client->http->domain, conn->client->http->host);
            }
            return proccess_cache(conn, ring);

        } else if (status == ERR) {
                return PROC_ERR;
        } else if (status == PART_PARS) {
            int err = add_socket_read_client(ring, client->fd, conn);
            if (err != 0) {
                return PROC_ERR;
            }
        }
    }
    return PROC_OK;
}

proc_status proccess_write_to_serv(int res, conn_info* conn, struct io_uring* ring) {
    //printf("proccess_write_to_serv \n");
    if (res < 0) {
        fprintf(stderr, "WRITE TO SERV failed %s\n", strerror(-res));
        return PROC_ERR;
    } else {
        int need_write = conn->client->size_http_res - res;
        assert(need_write >= 0);
        conn->client->size_http_res = need_write;
        if (need_write == 0) {
            int err = add_socket_read_server(ring, conn->server->fd, conn, READ_SERV_HEAD);
            if (err != 0 ) {
                return PROC_ERR;
            }
        } else {
            char* http_res_coppy = (char*)malloc(need_write * sizeof(char));
            memcpy(http_res_coppy, conn->client->http_mes_buffer + res, need_write);
            memcpy(conn->client->http_mes_buffer, http_res_coppy, need_write);
            int err = add_socket_write_server(ring, conn->server->fd, conn);
            if (err != 0 ) {
                return PROC_ERR;
            }
        }
    }
    //printf("finish proccess_write_to_serv \n");
    return PROC_OK;
}

int do_write(conn_info* conn, struct io_uring* ring) {
    //printf("do_write\n");
    int yet_write = conn->cache_i->write_without_cache - conn->cache_i->count_write;
    conn->cache_i->write_without_cache += conn->server->size_http_res;
    if (yet_write > 0 || conn->cache_i->count_write == 0) {
        if (yet_write < conn->server->size_http_res && conn->cache_i->count_write != 0) {
            char* http_mes_buffer = conn->server->http_mes_buffer;
            conn->server->size_http_res -= yet_write;
            http_mes_buffer = memmove(http_mes_buffer, http_mes_buffer  + yet_write, conn->server->size_http_res);
        }
    }
    int err = add_socket_write_client(ring, conn->client->fd, conn);
    if (err != 0) {
        return -1;
    }
    return 0;
}

proc_status proccess_read_serv_body(int res, conn_info* conn, struct io_uring* ring) {
    //printf("proccess_read_serv_body res %d\n", res);
    if (res < 0) {
        fprintf(stderr, "READ failed, disconnect %s\n", strerror(-res));
        return PROC_ERR;
    } else if (res == 0) {
        fprintf(stderr, "READ_SERV_BODY finish, disconnect %d %d\n", conn->server->size_http_res, conn->server->read_buffer_size);
        return PROC_ERR;
    } else {
        connection* server = conn->server;
        server->read_buffer_size += res;
        pars_status status = pars_body(conn->server);
        if (status == ALL_PARS) {
            if (server->http->status / 100 == 3) {
                int err = prepare_redirect(conn);
                if (err == -1) {
                    err = add_socket_write_client(ring, conn->client->fd, conn);
                } else {
                    err = close(conn->server->fd);
                    if (err == -1) {
                        fprintf(stderr, "close: %s\n", strerror(errno));
                    }
                    create_server_connect(conn, ring);
                }
            } else {
                int err = add_cache_content(conn->cache_i->cache_key, conn->server->http_mes_buffer, conn->server->size_http_res);
                if (err != 0) {
                    fprintf(stderr, "proccess_read_serv_body: Failed to write the data to the cache \n");
                }

                err = do_write(conn, ring);
                if (err != 0) {
                    return PROC_ERR;
                }
            }
        } else if (status == PART_PARS) {
            int err = add_socket_read_server(ring, conn->server->fd, conn, READ_SERV_BODY);
            if (err != 0) {
                return PROC_ERR;
            }
        } else if (status == FULL_BUFFER) {
            conn->prev_type = READ_SERV_BODY;
            int err = add_cache_content(conn->cache_i->cache_key, conn->server->http_mes_buffer, conn->server->size_http_res);
            if (err != 0) {
                fprintf(stderr, "Failed to write the data to the cache \n");
            }
            err = do_write(conn, ring);
            if (err != 0) {
                return PROC_ERR;
            }
        } else if (status == ERR) {
            return PROC_ERR;
        }
    }
    return PROC_OK;
}

proc_status proccess_read_serv_head(int res, conn_info* conn, struct io_uring* ring) {
    //printf("proccess_read_serv_head res %d\n", res);
    if (res < 0) {
        fprintf(stderr, "READ failed, disconnect %s\n", strerror(-res));
        return PROC_ERR;
    } else if (res == 0) {
        fprintf(stderr, "READ finish, disconnect\n");
        return PROC_ERR;
    } else {
        connection* server = conn->server;
        server->read_buffer_size += res;
        pars_status status = pars_head(conn->server, SERVER);
        if (status == ALL_PARS) {
            int http_mes_all_size = conn->server->need_send_size + conn->server->size_http_res;
            if (server->http->status / 100 != 3) {
                int err = add_cache_req(conn->cache_i->cache_key, http_mes_all_size);
                if (err != 0) {
                    fprintf(stderr, "Failed to write the request header to the cache \n");
                    return PROC_ERR;
                }
            }
            int new_res = res - conn->server->size_http_res;
            if (res > conn->server->size_http_res) {
                server->read_buffer_size -= new_res;
                return proccess_read_serv_body(new_res, conn, ring);
            } else {
                int err = add_socket_read_server(ring, conn->server->fd, conn, READ_SERV_BODY);
                if (err != 0) {
                    return PROC_ERR;
                }
            }
        } else if (status == PART_PARS) {
            int err = add_socket_read_server(ring, conn->server->fd, conn, READ_SERV_HEAD);
            if (err != 0) {
                return PROC_ERR;
            }
        } else if (status == ERR) {
            return PROC_ERR;
        } else if (status == FULL_BUFFER) {
            printf("so big http head \n");
            return PROC_ERR;
        }
    }
    return PROC_OK;
}

proc_status proccess_write(int res, conn_info* conn, struct io_uring* ring) {
    //printf("proccess_write %d\n", res);
    if (res < 0) {
        fprintf(stderr, "WRITE failed %s\n", strerror(-res));
        return PROC_ERR;
    } else {
        int need_write = conn->server->size_http_res - res;
        assert(need_write >= 0);
        connection* server = conn->server;
        if (need_write == 0 && server->need_send_size == 0) {
            conn->cache_i->finish_write = true;
            free_conn_info(conn);
            printf("FINISH CONNECT WRITE DATA  %d\n", res);
            if (shutdown_with_wait) {
                check_finish_proxing();
            }
        } else if (need_write == 0 && conn->cache_i->read_from_cache) {
            return proccess_cache(conn, ring);
        } else if (need_write == 0) {
            server->size_http_res = need_write;
            if (conn->prev_type == READ_SERV_BODY) {
                conn->prev_type = WRITE;
                memcpy(server->http_mes_buffer, server->read_buffer, server->read_buffer_size);
                server->size_http_res = server->read_buffer_size;
                server->need_send_size -= server->read_buffer_size;
                server->read_buffer_size = 0;
                if (server->need_send_size == 0) {
                    int err = add_cache_content(conn->cache_i->cache_key, conn->server->http_mes_buffer, conn->server->size_http_res);
                    if (err != 0) {
                        fprintf(stderr, "Failed to write the data to the cache \n");
                    }
                    err = add_socket_write_client(ring, conn->client->fd, conn);
                    if (err != 0) {
                        return PROC_ERR;
                    }
                } else {
                    int err = add_socket_read_server(ring, server->fd, conn, READ_SERV_BODY);
                    if (err != 0) {
                        return PROC_ERR;
                    }
                }
            } else {
                fprintf(stderr, "header so big\n");
                free_conn_info(conn);
            }
        } else {
            char* http_res_coppy = (char*)malloc(need_write * sizeof(char));
            if (http_res_coppy == NULL) {
                fprintf(stderr, "can't malloc: %s\n", strerror(errno));
                return PROC_ERR;
            }
            memcpy(http_res_coppy, conn->server->http_mes_buffer + res, need_write);
            memcpy(conn->server->http_mes_buffer, http_res_coppy, need_write);
            free(http_res_coppy);
            conn->server->size_http_res = need_write;
            int err = add_socket_write_client(ring, conn->client->fd, conn);
            if (err != 0) {
                return PROC_ERR;
            }
        }
    }
    return PROC_OK;
}

proc_status proccess_update_cache(int res, conn_info* conn, struct io_uring* ring) {
    //printf("proccess_update_cache %d\n" , gettid());
    if (res < 0) {
        fprintf(stderr, "WRITE failed %s\n", strerror(-res));
        return PROC_ERR;
    }
    if (res != 1) {
        int err = add_wait_cache(ring, conn);
        if (err != 0 ) {
            return PROC_ERR;
        }

    }

    int err = close(conn->cache_i->pipe_fd[0]);
    if (err == -1) {
        fprintf(stderr, "close: %s\n", strerror(errno));
        return PROC_ERR;
    }

    err = close(conn->cache_i->pipe_fd[1]);
    if (err == -1) {
        fprintf(stderr, "close: %s\n", strerror(errno));
        return PROC_ERR;
    }
    conn->cache_i->pipe_open = false;
    return proccess_cache(conn, ring);
}

void* start_worker(void* argv) {
    shutdown_with_wait = 0;
    int err = init_signals();
    if (err == -1) {
        return NULL;
    }


    worker_info* worker = (worker_info*)argv;

    worker_end* end = (worker_end*)malloc(sizeof(worker_end));
    end->mode = FIN;
    end->conns = NULL;
    end->ring = NULL;
    if (end == NULL) {
        fprintf(stderr, "can't malloc: %s\n", strerror(errno));
        return NULL;
    }

    listen_socket_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    end->s_fd = listen_socket_fd;
    pthread_cleanup_push(cleanup_handler, end);
    if (listen_socket_fd == -1) {
        fprintf(stderr, "socket failed: %s\n", strerror(errno));
        return NULL;
    }

    struct sockaddr_in sockaddr;
    memset(&sockaddr, 0, sizeof(sockaddr));
    sockaddr.sin_family = AF_INET;
    sockaddr.sin_port = htons(worker->port);
    sockaddr.sin_addr.s_addr = INADDR_ANY;

    const int val = 1;
    int err = setsockopt(listen_socket_fd, SOL_SOCKET, SO_REUSEPORT, &val, sizeof(val));
	if (err == -1) {
        fprintf(stderr, "setsockopt: %s\n", strerror(errno));
        finalize(err, listen_socket_fd);
    }

    err = bind(listen_socket_fd, (struct sockaddr*)&sockaddr, sizeof(sockaddr));
    if (err == -1) {
        fprintf(stderr, "bind: %s\n", strerror(errno));
        finalize(err, listen_socket_fd);
    }

    err = listen(listen_socket_fd, BACKLOG_SIZE);
    if (err == -1) {
        fprintf(stderr, "bind: %s\n", strerror(errno));
        finalize(err, listen_socket_fd);
    }

    struct io_uring_params params;
    struct io_uring ring;
   	memset(&params, 0, sizeof(params));
    end->mode = FIN_WITH_RING;
    err = io_uring_queue_init_params(SQ_SIZE, &ring, &params);
	if (err < 0) {
        fprintf(stderr, "close: %s\n", strerror(-err));
        finalize(err, listen_socket_fd);
	}

    end->ring = &ring;
    conns = (conn_info*)calloc(conns_size, sizeof(conn_info));
    if (conns == NULL) {
      	fprintf(stderr, "can't malloc\n");
        finalize(err, listen_socket_fd);
    }
    end->conns = conns;
    if (!(params.features & IORING_FEAT_FAST_POLL)) {
      	fprintf(stderr, "IORING_FEAT_FAST_POLL not available in the kernel, quiting...\n");
        finalize_with_ring(err, listen_socket_fd, ring, conns, end);
    }

    for (int i = 0; i < conns_size; ++i) {
        int err = conn_init(&(conns[i]));
        if (err == -1) {
            finalize_with_ring(err, listen_socket_fd, ring, conns, end);
        }
    }

    err = add_accept(&ring, listen_socket_fd, conns);
    printf("thread %d start accepting \n", gettid());
    if (err == -1) {
		finalize_with_ring(err, listen_socket_fd, ring, conns, end);
    } else if (err == -EAGAIN) {
        fprintf(stderr, "max connection, start accept try again\n");
		finalize_with_ring(err, listen_socket_fd, ring, conns, end);
    }

    while (true) {
		struct io_uring_cqe* cqe;
        int ret;
        err = io_uring_submit(&ring);
        if (err < 0) {
            fprintf(stderr, "io_uring_submit failed: %s\n", strerror(err));
		    finalize_with_ring(err, listen_socket_fd, ring, conns, end);
        }

        ret = io_uring_wait_cqe(&ring, &cqe);
        if (ret < 0) {
            if (shutdown_with_wait == 1) {
                continue;
            }
            fprintf(stderr, "io_uring_wait_cqe failed: %s\n", strerror(err));
            finalize_with_ring(err, listen_socket_fd, ring, conns, end);
        }

        struct io_uring_cqe* cqes[MAX_CONNECTIONS];
        int cqe_count = io_uring_peek_batch_cqe(&ring, cqes, MAX_CONNECTIONS);
        if (cqe_count < 0) {
            fprintf(stderr, "io_uring_peek_batch_cqe failed: %s\n", strerror(err));
            finalize_with_ring(err, listen_socket_fd, ring, conns, end);
        }

        for (int i = 0; i < cqe_count; i++) {

            cqe = cqes[i];
            struct conn_info* conn = (struct conn_info *) io_uring_cqe_get_data(cqe);
            type_ev type = conn->type;
            int res = cqe->res;

            if (type == ACCEPT) {
                proc_status status = proccess_accept(res, conn, &ring, conns);
                if (status == PROC_ERR) {
                    finalize_with_ring(err, listen_socket_fd, ring, conns, end);
                } else if (status == PROC_CON) {
                    continue;
                }
            } else if (type == READ) {
              	proc_status status = proccess_read(res, conn, &ring);
                if (status == PROC_ERR) {
                    free_conn_info(conn);
                }
            } else if (type == WRITE_TO_SERV) {
                proc_status status = proccess_write_to_serv(res, conn, &ring);
                if (status == PROC_ERR) {
                    free_conn_info(conn);
                }
            } else if (type == READ_SERV_HEAD) {;
              	proc_status status = proccess_read_serv_head(res, conn, &ring);
                if (status == PROC_ERR) {
                    free_conn_info(conn);
                }
            } else if (type == READ_SERV_BODY) {
              	proc_status status = proccess_read_serv_body(res, conn, &ring);
                if (status == PROC_ERR) {
                    free_conn_info(conn);
                }
            } else if (type == WRITE) {
              	proc_status status = proccess_write(res, conn, &ring);
                if (status == PROC_ERR) {
                    free_conn_info(conn);
                }
            } else if (type == UPDATE_CACHE) {
                proc_status status = proccess_update_cache(res, conn, &ring);
                if (status == PROC_ERR) {
                    free_conn_info(conn);
                }
            }
        	io_uring_cqe_seen(&ring, cqe);
        }
    }
    pthread_cleanup_pop(1);
    return NULL;
}


int init_workers(int count_worker, int listen_port, pthread_t* tids) {
    int err;
    worker_info* workers = (worker_info*)malloc(count_worker * sizeof(worker_info));
    if (workers == NULL) {
        fprintf(stderr, "can't alloc memmro: %s\n", strerror(errno));
        return -1;
    }
    for (int i = 0; i < count_worker; i++) {
        workers[i].port = listen_port;
        err = pthread_create(&(tids[i]), NULL, start_worker, &(workers[i]));
        if (err) {
            fprintf(stderr, "pthread_create() failed: %s\n", strerror(err));
            return -1;
        }
    }
    for (int i = 0; i < count_worker; i++) {
        err = pthread_join(tids[i], NULL);
        if (err) {
            fprintf(stderr, "pthread_join() failed: %s\n", strerror(err));
            return -1;
        }
        printf("JOIN THREAD \n");
    }
    free(workers);
    return 0;
}
