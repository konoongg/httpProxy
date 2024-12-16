#ifndef DATA_PARSER_H
#define DATA_PARSER_H

#include "structs.h"

#define MAX_COUNT_HEADERS 100

pars_status pars_head(connection* conn, connect_with src);
pars_status pars_body(connection* conn);

#endif
