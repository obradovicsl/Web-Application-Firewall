#ifndef MODELS_H
#define MODELS_H

#include <stddef.h>

typedef struct{
    char *url;
    char *headers;
    char *body;
}request_t;

typedef enum {
    HTTP_REQUEST_URL,
    HTTP_REQUEST_HEADERS,
    HTTP_REQUEST_BODY,
}http_request_part;

typedef enum{
    CLEAN = 0,
    SQL_INJECTION = 1,
    XSS = 2,
    DIRECTORY_TRAVERSAL = 3
}attack_type_t;

typedef enum{
    SEVERITY_NONE = 0,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
    SEVERITY_HIGH
}severity_t;

typedef struct {
    const char *attack;
    const char *severity;
    const char *location;
}finding_t;

typedef struct {
    finding_t *items;
    size_t count;
}findings_t;

#endif