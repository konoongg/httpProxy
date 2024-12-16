#ifndef PROCCESS_HTTP_H
#define PROCCESS_HTTP_H

#include "structs.h"

#define DEFAULT_HTTP_PORT 80

int check_http_req(http_mes* http_mes);
int create_host_from_domain(char** host, char* domain);
int resolve_domain(const char* hostname, struct sockaddr_in* sockaddr);
int prepare_redirect(conn_info* conn);
char* get_url(char* domain, char* host);

#endif