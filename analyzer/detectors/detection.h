#ifndef DETECTION
#define DETECTION

#include "re2_wrapper.h"
#include "models.h"

extern RawRegexPattern raw_patterns[];
extern CompiledRegexPattern compiled_patterns[128];

int init_regex_patterns();
void cleanup_regex_patterns();
void analyze(const char *input, http_request_part location, findings_t *findings);

#endif