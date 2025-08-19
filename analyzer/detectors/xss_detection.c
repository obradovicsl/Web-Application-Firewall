#include <string.h>

#include "xss_detection.h"

severity_t check_xss(const char *input, http_request_part location) {
    if (!input || strlen(input) == 0) {
        return SEVERITY_NONE;
    }
    
    severity_t max_severity = SEVERITY_NONE;
    
    for (int i = 0; xss_patterns[i] != NULL; i++) {
        if (strstr(input, xss_patterns[i])) {
            if (max_severity < SEVERITY_HIGH) {
                max_severity = SEVERITY_HIGH;
            }
        }
    }
    
    if (max_severity == SEVERITY_NONE) {
        // Proveri za sumnjive kombinacije karaktera
        if (input && 
            (strstr(input, "<") && strstr(input, ">")) ||
            (strstr(input, "&#") && (strstr(input, "<") || strstr(input, ">"))) ||
            (strstr(input, "%3c") && strstr(input, "%3e"))) {
            max_severity = SEVERITY_MEDIUM;
        }
        
        // Proveri za event handlere bez eksplicitnih tag-ova
        if (input &&
            (strstr(input, "on") && 
             (strstr(input, "=") || strstr(input, "%3d")))) {
            
            char* event_handlers[] = {"onclick", "onload", "onerror", "onmouseover", NULL};
            for (int i = 0; event_handlers[i]; i++) {
                if (strstr(input, event_handlers[i])) {
                    if (max_severity < SEVERITY_MEDIUM) {
                        max_severity = SEVERITY_MEDIUM;
                    }
                    break;
                }
            }
        }
    }
    return max_severity;
    
}