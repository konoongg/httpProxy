
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

#include "data_parser.h"
#include "proccess_http.h"
#include "worker.h"

//save_http_res with error check
#define do_save_http_res(size_copy_data, conn) \
    int err = save_http_res(conn->read_buffer, conn->http_mes_buffer, size_copy_data, &conn->size_http_res);\
    conn->read_buffer_size -= size_copy_data;\
    if (err == -1) { \
        return ERR;\
    }

//check if buffer included a http head 
int check_http_mes(char* data, int size) {
    if (size < 4) {
      return -1;
    }
    for (int i = 0; i < size - 3; ++i) {
        if (data[i] == '\r' && data[i + 1] == '\n' && data[i + 2] == '\r' && data[i + 3] == '\n') {
            return i + 3 + 1; // return size http head 
        }
    }
    return -1;
}


int save_http_res(char* read_buffer, char* http_mes_buffer, int copy_size, int* size_http_mes) {
    if (*size_http_mes + copy_size > MAX_HTTP_SIZE) {
        fprintf(stderr, "so big http");
		return -1;
    }
    memcpy(http_mes_buffer + *size_http_mes, read_buffer, copy_size);
   
    char* read_buffer_coppy = (char*)malloc( MAX_MESSAGE_LEN * sizeof(char));;
    if (read_buffer_coppy == NULL) {
        fprintf(stderr, "can't malloc %s", strerror(errno));
        return -1;
    }

    memcpy(read_buffer_coppy, read_buffer + copy_size, MAX_MESSAGE_LEN - copy_size);
    memcpy(read_buffer, read_buffer_coppy, MAX_MESSAGE_LEN - copy_size);
    *size_http_mes += copy_size;
    free(read_buffer_coppy);
    return 0;
}


int pars_cli_head(connection* conn, char* line) {
    char* word = strtok(line, " ");
    int count_word = 0;
    while (word != NULL) {
        int size_word  = strlen(word) + 1;
        if (count_word == 0) {
            conn->http->method = (char*)malloc(size_word * sizeof(char));
            if (conn->http->method == NULL) {
                fprintf(stderr, "can't malloc %s", strerror(errno));
                return -1;
            }
            memcpy(conn->http->method, word, size_word);
        } else if (count_word == 1) {
            conn->http->domain = (char*)malloc(size_word * sizeof(char));
            if (conn->http->domain == NULL) {
                fprintf(stderr, "can't malloc %s", strerror(errno));
                return -1;
            }
            memcpy(conn->http->domain, word, size_word);
        } else if (count_word == 2) {
            conn->http->version = (char*)malloc(size_word * sizeof(char));
            if (conn->http->domain == NULL) {
                fprintf(stderr, "can't malloc %s", strerror(errno));
                return -1;
            }
            memcpy(conn->http->version, word, size_word);
        } else {
            fprintf(stderr, "wrong http header wormat, uncnown %s \n", word);
            return -1;
        }
        word = strtok(NULL, " ");
        count_word++;
    }
    if (count_word != 3) {
        fprintf(stderr, "wrong http header wormat, in first line %d words \n", count_word - 1);
        return -1;
    }
    int err = create_host_from_domain(&(conn->http->host), conn->http->domain);
    if (err == -1) {
        return -1;
    }
    conn->http->domain[0] = '/';
    conn->http->domain[1] = '\0';
    return 0;
}

int pars_serv_head(connection* conn, char* line) {
    char* word = strtok(line, " ");
    int count_word = 0;
    int line_size = strlen(line);
    int count_sym = 0;
    while (word != NULL) {
        int size_word  = strlen(word) + 1;
        count_sym += size_word;
        if (count_word == 0) {
            conn->http->version = (char*)malloc(size_word * sizeof(char));
            if (conn->http->version  == NULL) {
                fprintf(stderr, "can't malloc %s", strerror(errno));
                return -1;
            }   
            memcpy(conn->http->version, word, size_word);
        } else if (count_word == 1) {
            errno = 0;
            char* endptr;
            int val =  (int)strtol(word, &endptr, 10);
            if (endptr == word) {
                fprintf(stderr, "http head parsing: No digits were found\n");
                return -1;
            }
            if (errno != 0) {
                fprintf(stderr, "http head parsing: %s\n", strerror(errno));
                return -1;
            }
            if (val > 599 || val < 100) {
                fprintf(stderr, "http head parsing: val is %d, but min_val: %d, max_val: %d\n", val, 100, 500);
                return -1;
            }
            conn->http->status = val;
            break;
        }
        word = strtok(NULL, " ");
        count_word++;
    }
    conn->http->status_mes = (char*)malloc( line_size + 1);
    if (conn->http->status_mes == NULL) {
        fprintf(stderr, "can't malloc %s", strerror(errno));
        return -1;
    }
    memcpy(conn->http->status_mes, line + count_sym , line_size + 1);
    return 0; 
}

int pars_http_header(connection* conn, connect_with src) {
    char* http_mes_buffer_coppy = (char*)malloc(conn->size_http_res * sizeof(char));
    if (http_mes_buffer_coppy == NULL) {
        fprintf(stderr, "can't calloc  %s\n", strerror(errno));
        return -1;
    }
    
    memcpy(http_mes_buffer_coppy, conn->http_mes_buffer, conn->size_http_res);
    conn->http_mes_buffer[conn->size_http_res] = '\0';
    char** lines = (char**)calloc(MAX_COUNT_HEADERS, sizeof(char*));
    if (lines == NULL) {
        free(http_mes_buffer_coppy);
        fprintf(stderr, "can't calloc  %s\n", strerror(errno));
        return -1;
    }
    char* line = strtok(http_mes_buffer_coppy, "\r\n");
    int num_line = 0;
    while (line != NULL) {
        if (num_line == MAX_COUNT_HEADERS) {
            fprintf(stderr, "Parsing the message is not possible, the header limit has been exceeded \n");
            free(lines);
            free(http_mes_buffer_coppy);
            return -1;
        }
        int size_line  = strlen(line) + 1;
        lines[num_line] = (char*)malloc( size_line * sizeof(line));
        if (lines[num_line] == NULL) {
            fprintf(stderr, "can't malloc %s\n", strerror(errno));
            free(lines);
            free(http_mes_buffer_coppy);
            return -1;
        }

        memcpy(lines[num_line], line, size_line);
        line = strtok(NULL, "\r\n");
        num_line++;
    }

    int err = 0;
    if (src == CLIENT) {
        err = pars_cli_head(conn, lines[0]);
    } else if (src == SERVER) {
        err = pars_serv_head(conn, lines[0]);
    }

    if (err == -1) {
        for (int i = 0; i < num_line; ++i) {
            free(lines[i]);
        }
        free(lines);
        free(http_mes_buffer_coppy);
        return -1;
    }
    free(lines[0]);

    for (int i = 1; i < num_line; ++i) {
        int count_word = 0;
        int line_size = strlen(lines[i]);
        char* word = strtok(lines[i], ":");

        if (conn->http->headers == NULL) {

            conn->http->headers = (http_headers*)malloc(sizeof(http_headers));
            if (conn->http->headers == NULL) {
                for (int i = 0; i < num_line; ++i) {
                    free(lines[i]);
                }
                fprintf(stderr, "can't malloc %s\n", strerror(errno));
                free(lines);
                free(http_mes_buffer_coppy);
                return -1;
            }

            conn->http->headers->first = (http_header*)malloc(sizeof(http_header));
            if (conn->http->headers->first == NULL) {
                fprintf(stderr, "can't malloc %s\n", strerror(errno));
                for (int i = 0; i < num_line; ++i) {
                    free(lines[i]);
                }
                free(lines);
                free(http_mes_buffer_coppy);
                return -1;
            }         
            conn->http->headers->last = conn->http->headers->first; 
        } else { 
            conn->http->headers->last->next = (http_header*)malloc(sizeof(http_header));
            if (conn->http->headers->last->next == NULL) {
                fprintf(stderr, "can't malloc %s\n", strerror(errno));
                for (int i = 0; i < num_line; ++i) {
                    free(lines[i]);
                }
                free(lines);
                free(http_mes_buffer_coppy);
                return -1;
            }
            conn->http->headers->last = conn->http->headers->last->next;
        }
        conn->http->headers->last->next = NULL;
        int key_size = strlen(word);

        conn->http->headers->last->key = (char*)malloc(key_size + 1);
        if (conn->http->headers->last->key == NULL) {
            fprintf(stderr, "can't malloc %s\n", strerror(errno));
            for (int i = 0; i < num_line; ++i) {
                    free(lines[i]);
            }
            free(lines);
            free(http_mes_buffer_coppy);
            return -1;
        }
        
        memcpy(conn->http->headers->last->key, word, key_size + 1);
            
             
        int val_size =  line_size - key_size;

        conn->http->headers->last->value = (char*)malloc(val_size + 1);
        if (conn->http->headers->last->value == NULL) {
            fprintf(stderr, "can't malloc %s\n", strerror(errno));
            for (int i = 0; i < num_line; ++i) {
                    free(lines[i]);
            }
            free(lines);
            free(http_mes_buffer_coppy);
            return -1;
        }
        memcpy(conn->http->headers->last->value, lines[i] + key_size + 1, val_size + 1);            
        char content_length[15] = "Content-Length";
        char host[5] = "Host";
        if (strncmp(conn->http->headers->last->key, content_length, 15) == 0) {
            char* endptr;
            conn->need_body_size =  (int)strtol(word + key_size + 1, &endptr, 10);         
            if (endptr == word) {
                fprintf(stderr, "http head parsing: No digits were found\n");
                for (int i = 0; i < num_line; ++i) {
                    free(lines[i]);
                }
                free(lines);
                free(http_mes_buffer_coppy);
                return -1;
            }
            if (errno != 0) {
                fprintf(stderr, "http head parsing: %s\n", strerror(errno));
                for (int i = 0; i < num_line; ++i) {
                    free(lines[i]);
                } 
                free(lines);
                free(http_mes_buffer_coppy);                           
                return -1;                    
            }
        } else if (strncmp(conn->http->headers->last->key, host, 5) == 0) {
            free(conn->http->host);
            int host_size = val_size ;
            conn->http->host = (char*)malloc(host_size * sizeof(char));
            if (conn->http->host == NULL) {
                for (int i = 0; i < num_line; ++i) {
                    free(lines[i]);
                }
                free(lines);
                free(http_mes_buffer_coppy);                           
                return -1; 
            }
            memcpy(conn->http->host, conn->http->headers->last->value + 1, val_size);
        }
        count_word++; 
        free(lines[i]);
        lines[i] = NULL;
    }
    free(lines);
    free(http_mes_buffer_coppy);
    return 0;
}

pars_status pars_head(connection* conn, connect_with src) {
    int http_mes_size = check_http_mes(conn->read_buffer, conn->read_buffer_size);
    if (http_mes_size == -1) {
        do_save_http_res(conn->read_buffer_size, conn);
        return PART_PARS;
    } else {
        do_save_http_res(http_mes_size, conn);
        int error = pars_http_header(conn, src);
        if (error == -1) {
            return ERR;
        }
    	return ALL_PARS;
    }
}

pars_status pars_body(connection* conn) {
    int data_size = conn->read_buffer_size;
    do_save_http_res(conn->read_buffer_size, conn);
    conn->need_body_size -= data_size;
    if (conn->need_body_size == 0) {
        return ALL_PARS;
    }
    assert(conn->need_body_size >= 0);
    return PART_PARS;
}