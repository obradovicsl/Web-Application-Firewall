#ifndef DETECTION
#define DETECTION

#include <json-c/json.h>

#include "re2_wrapper.h"
#include "models.h"

extern CompiledRegexPattern compiled_patterns[128];

int init_regex_patterns();
void cleanup_regex_patterns();
void analyze(const char *input, const char *location, detection_report_t *findings);
char* read_file(const char* filename);

#endif