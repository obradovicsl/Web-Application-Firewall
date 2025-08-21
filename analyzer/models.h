#ifndef MODELS_H
#define MODELS_H

#include <stddef.h>

#include "re2_wrapper.h"

// ---------------- STRUCTS ----------------

typedef struct{
    char *url;
    char *headers;
    char *body;
}request_t;

typedef struct {
    const char *attack;
    const char *severity;
    const char *location;
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
} RawRegexPattern;

typedef struct {
    re2_pattern_t *compiled_regex;
    const char *description;
    int severity;
} CompiledRegexPattern;


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


#endif