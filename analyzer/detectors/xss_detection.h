#ifndef XSS_DETECTION
#define XSS_DETECTION

#include "models.h"


// ---------------- REGEX -----------------------

extern RawRegexPattern xss_raw_patterns[];
extern CompiledRegexPattern xss_compiled_patterns[64];

int init_xss_patterns();
void cleanup_xss_patterns();
severity_t detect_xss_optimized(const char *input);



#endif