#ifndef SQL_DETECTION
#define SQL_DETECTION

#include <regex.h>
#include "re2_wrapper.h"

#include "models.h"


severity_t check_sql_injection(const char *input, http_request_part location);
severity_t calculate_sql_heuristic(int quote_count, int sql_keywords_count, int comment_found, http_request_part location);

int check_pattern(const char *input, const char *pattern);
severity_t detect_sqli_comprehensive(const char *input);

// --------------------------- REGEX -----------------------------
// Comprehensive SQL Injection regex patterns
extern SQLiRegexPattern sqli_patterns[];

// --------------------------- PATTERNS --------------------------

extern const char *sql_keywords[];

extern const char *sql_operators[];

extern const char *sql_comment_patterns[];

extern const char *sql_dangerous_functions[];

extern const char *sql_injection_patterns[];

#endif