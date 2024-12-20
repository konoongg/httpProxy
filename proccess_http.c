#include <arpa/inet.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include "structs.h"
#include "proccess_http.h"


method_type define_http_method(char* method) {
    if (strncmp(method, "GET", 3) == 0) {
        return GET;
    }
    return OTHER;
}

int check_http_req(http_mes* http_mes) {
    method_type m_type = define_http_method(http_mes->method);
    if (m_type == OTHER) {
        fprintf(stderr, "wrong method \n");
        return -1;
    }
    http_mes->m_type = m_type;
    if (strncmp(http_mes->version, "HTTP/1.0", 8) != 0) {
        fprintf(stderr, "wrong version \n");
        return -1;
    }
    return 0;
}

int resolve_domain(const char* hostname, struct sockaddr_in* sockaddr) {
    struct addrinfo hints;
    struct addrinfo* res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    int status;
    if ((status = getaddrinfo(hostname, NULL, &hints, &res)) != 0) {
        fprintf(stderr, "getaddrinfo: %s %s\n", gai_strerror(status), hostname);
        return -1;
    }
    if (res->ai_family == AF_INET) {
        struct sockaddr_in* ipv4 = (struct sockaddr_in *)res->ai_addr;
        memcpy(sockaddr, ipv4, sizeof(struct sockaddr_in));
        sockaddr->sin_port = htons(DEFAULT_HTTP_PORT);

    } else {
        fprintf(stderr, "getaddrinfo: can't resolve %s", hostname);
        return -1;
    }
    freeaddrinfo(res);
    return 0;
}

int create_host_from_domain(char** host, char* domain) {
     if (strncmp(domain, "http:/", 6) == 0) {
        //skip  http:/
        char* end_http_in_domain = domain + 7;
        char* cur_sym = end_http_in_domain;
        int size_host = 0;
        while (*cur_sym != '/') {
            if (*cur_sym == '\0') {
                fprintf(stderr, "wrong url format \n");
                return -1;
            }
            size_host++;
            cur_sym++;
        }
        size_host++; // add \0
        if (*host == NULL) {
            *host = (char*)malloc(size_host * sizeof(char));
                if (*host  == NULL) {
                fprintf(stderr, "can't malloc %s", strerror(errno));
                return -1;
            }
        }
        memcpy(*host, end_http_in_domain, size_host);
        (*host)[size_host - 1] = '\0';
    }
    return 0;
}

int prepare_redirect(conn_info* conn) {
    char* location_head = NULL;
    http_header* cur_header = conn->server->http->headers->first;
    char* location = "Location";

    while (cur_header != NULL) {
        http_header* next_header = (http_header*)cur_header->next;
        cur_header = next_header;
        if (strncmp(cur_header->key, location, strlen(location) + 1)  == 0) {
            location_head = cur_header->value;
            break;
        }
    }
    if (location_head == NULL) {
        fprintf(stderr, "can't redirect, can't find location \n");
        return -1;
    }
    char* proto = "http:/";
    if (strncmp(location_head, proto, strlen(proto)) != 0) {
        fprintf(stderr, "don't support protocol  \n");
        return -1;
    }
    conn->client->http->domain[0] = '/';
    conn->client->http->domain[1] = '\0';
    create_host_from_domain(&(conn->client->http->host), location_head);
    return 0;
}

char* get_url(char* domain, char* host) {
    int size = strlen(domain) + strlen(host) + 1;
    char* url = (char*)malloc(size);
    memcpy(url, domain, strlen(domain));
    memcpy(url + strlen(domain), host, strlen(host));
    url[size - 1] = '\0';
    return url;
}
