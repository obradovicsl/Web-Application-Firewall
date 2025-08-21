#ifndef MODELS_H
#define MODELS_H

#include <stddef.h>

#include "re2_wrapper.h"



// ---------------- ENUMS ----------------

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

// ---------------- STRUCTS ----------------

typedef struct{
    char *url;
    char *headers;
    char *body;
}request_t;

typedef struct {
    attack_type_t attack;
    http_request_part location;
    const char *description;
}finding_t;

typedef struct {
    finding_t *items;
    size_t count;
}findings_t;

typedef struct {
    char *pattern;
    char *description;
    int severity;
    attack_type_t attack;
} RawRegexPattern;

typedef struct {
    re2_pattern_t *compiled_regex;
    attack_type_t attack;
    const char *description;
    int severity;
} CompiledRegexPattern;





#endif