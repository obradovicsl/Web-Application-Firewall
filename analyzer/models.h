#ifndef MODELS_H
#define MODELS_H

#include <stddef.h>

#include "re2_wrapper.h"


// ---------------- STRUCTS ----------------

typedef struct{
    char *id;
    char *url;
    char *headers;
    char *body;
}request_t;

typedef struct {
    const char *name;
    uint32_t codepoint;
} Entity;

typedef struct {
    const char *attack;
    const char *location;
    const char *description;
}detection_t;

typedef struct {
    detection_t *items;
    size_t count;
}detection_report_t;

typedef struct {
    re2_pattern_t *compiled_regex;
    const char *attack;
    const char *description;
    int severity;
} CompiledRegexPattern;





#endif