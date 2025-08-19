#include <string.h>

#include "models.h"
#include "sqli_detection.h"


severity_t check_sql_injection(const char *input, http_request_part location){
    if (!input || strlen(input) == 0) {
        return SEVERITY_NONE;
    }

    // Check for exact SQL injection pattern
    for (int i = 0; sql_injection_patterns[i] != NULL; i++) {
        if (strstr(input, sql_injection_patterns[i])) {
            return SEVERITY_HIGH;
        }
    }

    // Check for common SQL functions
    for (int i = 0; sql_dangerous_functions[i] != NULL; i++) {
        if (strstr(input, sql_dangerous_functions[i])) {
            return SEVERITY_HIGH;
        }
    }

    // Check for suspict combinations
    int quote_count = 0;
    int sql_keywords_count = 0;
    int comment_found = 0;

    // Count single and double quotes (' and ")
    for (const char *p = input; *p; p++){
        if (*p == '\'' || *p == '"') quote_count++;
    }

    // Count SQL keywords
    for (int i = 0; sql_keywords[i] != NULL; i++){
        if(strstr(input, sql_keywords[i])){
            sql_keywords_count++;
        }
    }

    // Count SQL operators
    for (int i = 0; sql_operators[i] != NULL; i++){
        if (strstr(input, sql_operators[i])){
            sql_keywords_count++;
        }
    }

    // Check for SQL comments
    for (int i = 0; sql_comment_patterns[i] != NULL; i++) {
        if (strstr(input, sql_comment_patterns[i])) {
            comment_found = 1;
            break;
        }
    }

    return calculate_sql_heuristic(quote_count, sql_keywords_count, comment_found, location);
}

severity_t calculate_sql_heuristic(int quote_count, int sql_keywords_count, int comment_found, http_request_part location) {
    if (location == HTTP_REQUEST_URL) {

    } else if (location == HTTP_REQUEST_HEADERS)
    {
        
    } else {

    }
    
    if (sql_keywords_count == 0 && quote_count == 0) return SEVERITY_NONE;
    if (sql_keywords_count >= 2 && quote_count > 0 && comment_found) return SEVERITY_MEDIUM;
    if (sql_keywords_count >= 1 && quote_count >= 2) return SEVERITY_MEDIUM;
    if (sql_keywords_count >= 3) return SEVERITY_MEDIUM;    
    return SEVERITY_NONE;
}
