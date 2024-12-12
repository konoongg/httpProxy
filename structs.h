#ifndef STRUCT_H
#define STRUCT_H

#include <sys/socket.h>
#include <netinet/in.h>

#define MAX_MESSAGE_LEN 100 * 1024
#define MAX_HTTP_SIZE 100 * 1024
#define git 100 * 1024

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
    char read_buffer[MAX_MESSAGE_LEN];
    char write_buffer[MAX_MESSAGE_LEN];
    char http_mes_buffer[MAX_HTTP_SIZE + 1];
    int size_http_res;
    int need_body_size;
    http_mes*  http;
} connection;

    typedef struct conn_info {
        type_ev type;
        struct sockaddr_in* sockaddr;
        connection* client;
        connection* server;
    } conn_info;

typedef enum {
    ALL_PARS,
    PART_PARS,
    ERR
} pars_status;

#endif