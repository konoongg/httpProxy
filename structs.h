#ifndef STRUCT_H
#define STRUCT_H

#include <stdbool.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define MAX_MESSAGE_LEN 100 * 1024
#define MAX_HTTP_SIZE 100 * 1024

typedef  enum {
    CLIENT,
    SERVER
} connect_with;

typedef enum {
    ACCEPT,
    READ,
    CONNECT_TO_SERV,
    WRITE_TO_SERV,
    READ_SERV_HEAD,
    READ_SERV_BODY,
    WRITE
} type_ev;

typedef struct http_header {
    char* key;
    char* value;
    struct http_header* next;
} http_header;

typedef struct http_headers {
    struct http_header* first;
    struct http_header* last;
} http_headers;



typedef enum method_type {
    GET,
    OTHER
} method_type;

typedef struct http_mes {
    char* method;
    char* version;
    char* domain;
    char* host;
    method_type m_type;
    http_headers* headers;
    int status;
    char* status_mes;
} http_mes;

typedef struct connection {
    int fd;
    int read_buffer_size;
    char* read_buffer;
    char* write_buffer;
    char* http_mes_buffer;
    int size_http_res;
    int need_send_size;
    http_mes*  http;
} connection;


typedef struct cache_info {
    char* cache_key;
    bool read_from_cache;
    unsigned int count_write;
} cache_info;

typedef struct conn_info {
    type_ev type;
    type_ev prev_type;
    struct sockaddr_in* sockaddr;
    connection* client;
    connection* server;
    cache_info* cache_i;
} conn_info;

typedef enum {
    ALL_PARS,
    PART_PARS,
    ERR,
    FULL_BUFFER,
} pars_status;

#endif
