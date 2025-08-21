#ifndef SQL_DETECTION
#define SQL_DETECTION

#include <regex.h>
#include "re2_wrapper.h"

#include "models.h"


// --------------------------- REGEX -----------------
extern RawRegexPattern sqli_patterns[];
extern CompiledRegexPattern sqli_compiled_patterns[64];


int init_sqli_patterns();
void cleanup_sqli_patterns();
severity_t detect_sqli_optimized(const char *input);

#endif