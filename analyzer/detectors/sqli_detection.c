#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "models.h"
#include "sqli_detection.h"
#include "html-decoder.h"


// ---------------------------- REGEX ------------------------------------------
SQLiRegexPattern sqli_patterns[] = {
    // === BOOLEAN INJECTIONS (radi u path-u i query-ju) ===
    {".*([[:space:]]|%20|\\+)+([Oo][Rr]|[Aa][Nn][Dd])([[:space:]]|%20|\\+)+[0-9]+([[:space:]]|%20|\\+)*=([[:space:]]|%20|\\+)*[0-9]+.*", "Boolean n=n anywhere", 5},
    {".*[0-9]+([[:space:]]|%20|\\+)+([Oo][Rr]|[Aa][Nn][Dd])([[:space:]]|%20|\\+)+[0-9]+([[:space:]]|%20|\\+)*=([[:space:]]|%20|\\+)*[0-9]+.*", "Number THEN boolean n=n", 5},
    {".*(^|/|\\?|&)([Oo][Rr]|[Aa][Nn][Dd])([[:space:]]|%20|\\+)+[0-9]+([[:space:]]|%20|\\+)*=([[:space:]]|%20|\\+)*[0-9]+.*", "Segment starts with OR/AND n=n", 5},

    // Classic 1=1 / 1=2 varijante
    {".*([[:space:]]|%20|\\+)+[Oo][Rr]([[:space:]]|%20|\\+)+1([[:space:]]|%20|\\+)*=([[:space:]]|%20|\\+)*1.*", "OR 1=1", 5},
    {".*([[:space:]]|%20|\\+)+[Aa][Nn][Dd]([[:space:]]|%20|\\+)+1([[:space:]]|%20|\\+)*=([[:space:]]|%20|\\+)*1.*", "AND 1=1", 4},
    {".*([[:space:]]|%20|\\+)+[Oo][Rr]([[:space:]]|%20|\\+)+1([[:space:]]|%20|\\+)*=([[:space:]]|%20|\\+)*2.*", "OR 1=2 (false)", 4},
    {".*([[:space:]]|%20|\\+)+[Aa][Nn][Dd]([[:space:]]|%20|\\+)+1([[:space:]]|%20|\\+)*=([[:space:]]|%20|\\+)*2.*", "AND 1=2 (false)", 3},

    // Boolean sa stringovima
    {".*([[:space:]]|%20|\\+)+([Oo][Rr]|[Aa][Nn][Dd])([[:space:]]|%20|\\+)*'[^']*'([[:space:]]|%20|\\+)*=([[:space:]]|%20|\\+)*'[^']*'.*", "OR/AND string compare (')", 4},
    {".*([[:space:]]|%20|\\+)+([Oo][Rr]|[Aa][Nn][Dd])([[:space:]]|%20|\\+)*\"[^\"]*\"([[:space:]]|%20|\\+)*=([[:space:]]|%20|\\+)*\"[^\"]*\".*", "OR/AND string compare (\")", 4},

    // === UNION-BASED ===
    {".*[Uu][Nn][Ii][Oo][Nn]([[:space:]]|%20|\\+)+[Aa][Ll][Ll]([[:space:]]|%20|\\+)+[Ss][Ee][Ll][Ee][Cc][Tt].*", "UNION ALL SELECT", 5},
    {".*[Uu][Nn][Ii][Oo][Nn]([[:space:]]|%20|\\+)+[Dd][Ii][Ss][Tt][Ii][Nn][Cc][Tt]([[:space:]]|%20|\\+)+[Ss][Ee][Ll][Ee][Cc][Tt].*", "UNION DISTINCT SELECT", 4},
    {".*['\")]*([[:space:]]|%20|\\+)*[Uu][Nn][Ii][Oo][Nn]([[:space:]]|%20|\\+)*[Ss][Ee][Ll][Ee][Cc][Tt].*", "Quoted/Paren UNION SELECT", 5},
    {".*([[:space:]]|%20|\\+)*([Uu][Nn][Ii][Oo][Nn]((%20|\\+)+|[[:space:]]+)[Ss][Ee][Ll][Ee][Cc][Tt]).*", "UNION SELECT (encoded spaces)", 5},

    // === TIME-BASED / BLIND ===
    {".*[Ss][Ll][Ee][Ee][Pp]([[:space:]]|%20|\\+)*\\(([[:space:]]|%20|\\+)*[0-9]+([[:space:]]|%20|\\+)*\\).*", "SLEEP()", 5},
    {".*[Ww][Aa][Ii][Tt][Ff][Oo][Rr]([[:space:]]|%20|\\+)+[Dd][Ee][Ll][Aa][Yy]([[:space:]]|%20|\\+)+['\"][^'\"]+['\"].*", "WAITFOR DELAY", 5},
    {".*[Pp][Gg]_[Ss][Ll][Ee][Ee][Pp]([[:space:]]|%20|\\+)*\\(([[:space:]]|%20|\\+)*[0-9]+([[:space:]]|%20|\\+)*\\).*", "pg_sleep()", 5},
    {".*[Bb][Ee][Nn][Cc][Hh][Mm][Aa][Rr][Kk]([[:space:]]|%20|\\+)*\\(([[:space:]]|%20|\\+)*[0-9]+.*", "BENCHMARK()", 5},

    // === ERROR-BASED / CAST ===
    {".*[Ee][Xx][Tt][Rr][Aa][Cc][Tt][Vv][Aa][Ll][Uu][Ee]([[:space:]]|%20|\\+)*\\(", "EXTRACTVALUE(", 5},
    {".*[Uu][Pp][Dd][Aa][Tt][Ee][Xx][Mm][Ll]([[:space:]]|%20|\\+)*\\(", "UPDATEXML(", 5},
    {".*[Cc][Aa][Ss][Tt]([[:space:]]|%20|\\+)*\\([^)]*[[:space:]]+[Aa][Ss][[:space:]]+[Ii][Nn][Tt][[:space:]]*\\)", "CAST(... AS INT)", 4},
    {".*[Cc][Oo][Nn][Vv][Ee][Rr][Tt]([[:space:]]|%20|\\+)*\\([[:space:]]*[Ii][Nn][Tt][[:space:]]*,", "CONVERT(int,...", 4},

    // === STACKED QUERIES ===
    {".*(;|%3[Bb])([[:space:]]|%20|\\+)*[Ss][Ee][Ll][Ee][Cc][Tt].*", "Stacked SELECT", 5},
    {".*(;|%3[Bb])([[:space:]]|%20|\\+)*[Ii][Nn][Ss][Ee][Rr][Tt].*", "Stacked INSERT", 5},
    {".*(;|%3[Bb])([[:space:]]|%20|\\+)*[Uu][Pp][Dd][Aa][Tt][Ee].*", "Stacked UPDATE", 5},
    {".*(;|%3[Bb])([[:space:]]|%20|\\+)*[Dd][Ee][Ll][Ee][Tt][Ee].*", "Stacked DELETE", 5},
    {".*(;|%3[Bb])([[:space:]]|%20|\\+)*[Dd][Rr][Oo][Pp].*", "Stacked DROP", 5},
    {".*(;|%3[Bb])([[:space:]]|%20|\\+)*[Cc][Rr][Ee][Aa][Tt][Ee].*", "Stacked CREATE", 5},
    {".*(;|%3[Bb])([[:space:]]|%20|\\+)*[Ee][Xx][Ee][Cc][Uu]?[Tt][Ee]?.*", "Stacked EXEC/EXECUTE", 5},

    // === KOMENTARI ===
    {".*(--|%2[Dd]%2[Dd])[^\\r\\n]*", "SQL line comment --", 3},
    {".*(#|%23)[^\\r\\n]*", "MySQL hash comment #", 3},
    {".*/\\*.*?\\*/", "SQL block comment /* */", 3},
    {".*['\"][[:space:]]*(--|#|%23).*", "Quote + comment", 4},

    // === INFO-GATHERING ===
    {".*[Ii][Nn][Ff][Oo][Rr][Mm][Aa][Tt][Ii][Oo][Nn]_?[Ss][Cc][Hh][Ee][Mm][Aa].*", "information_schema", 4},
    {".*[Ii][Nn][Ff][Oo][Rr][Mm][Aa][Tt][Ii][Oo][Nn]_?[Ss][Cc][Hh][Ee][Mm][Aa]([[:space:]]|%20|\\+)*\\.[Tt][Aa][Bb][Ll][Ee][Ss].*", "information_schema.tables", 4},
    {".*[Ii][Nn][Ff][Oo][Rr][Mm][Aa][Tt][Ii][Oo][Nn]_?[Ss][Cc][Hh][Ee][Mm][Aa]([[:space:]]|%20|\\+)*\\.[Cc][Oo][Ll][Uu][Mm][Nn][Ss].*", "information_schema.columns", 4},
    {".*[Mm][Yy][Ss][Qq][Ll]\\.user.*", "mysql.user", 5},
    {".*[Ss][Yy][Ss]\\.tables.*", "sys.tables", 4},
    {".*([Pp][Gg]_tables|[Pp][Gg]_catalog).*", "PostgreSQL catalogs", 4},

    // === FUNKCIJE / FILE IO ===
    {".*[Cc][Oo][Nn][Cc][Aa][Tt]\\(", "CONCAT(", 3},
    {".*[Gg][Rr][Oo][Uu][Pp]_?[Cc][Oo][Nn][Cc][Aa][Tt]\\(", "GROUP_CONCAT(", 3},
    {".*[Ss][Tt][Rr][Ii][Nn][Gg]_?[Aa][Gg][Gg]\\(", "STRING_AGG(", 3},
    {".*[Ll][Oo][Aa][Dd]_[Ff][Ii][Ll][Ee]\\(", "LOAD_FILE(", 5},
    {".*[Ii][Nn][Tt][Oo]([[:space:]]|%20|\\+)+[Oo][Uu][Tt][Ff][Ii][Ll][Ee].*", "INTO OUTFILE", 5},
    {".*[Ii][Nn][Tt][Oo]([[:space:]]|%20|\\+)+[Dd][Uu][Mm][Pp][Ff][Ii][Ll][Ee].*", "INTO DUMPFILE", 5},

    // === ENKODING / OBFUSKACIJA ===
    {".*0x[0-9A-Fa-f]+.*", "Hex literal 0x...", 3},
    {".*%25[0-9A-Fa-f]{2}.*", "Double URL-encoding (%25XX)", 3},

    // === NoSQL (osnovno) ===
    {".*\\$((where)|(ne)|(gt)|(lt)|(regex)|(in)|(nin)).*", "MongoDB operators in input", 3},

    // === END ===
    {NULL, NULL, 0}
};



int check_pattern(const char *input, const char *pattern) {
regex_t regex;
int reti;
// Compile regex with case insensitive flag
reti = regcomp(&regex, pattern, REG_EXTENDED | REG_ICASE);
if (reti) {
return 0; // Compilation failed
 }
// Execute regex
reti = regexec(&regex, input, 0, NULL, 0);
regfree(&regex);
return !reti; // Return 1 if match found
}

typedef struct {
    int total_score;
    int pattern_count;
    int max_severity;
    char detected_patterns[1024];
} sqli_result_t;


severity_t detect_sqli_comprehensive(const char *input) {
    sqli_result_t result = {0, 0, 0, ""};
    
    if (!input || strlen(input) == 0) {
        return SEVERITY_NONE;
    }
    
    // printf("Analyzing: \"%s\"\n", input);
    
    for (int i = 0; sqli_patterns[i].pattern != NULL; i++) {
        if (check_pattern(input, sqli_patterns[i].pattern)) {
            result.pattern_count++;
            result.total_score += sqli_patterns[i].severity * 10;
            
            if (sqli_patterns[i].severity > result.max_severity) {
                result.max_severity = sqli_patterns[i].severity;
            }
            
            fprintf(stderr, "✓ MATCH: %s (Severity: %d)\n", 
                   sqli_patterns[i].description, sqli_patterns[i].severity);
            fprintf(stderr, "  Pattern: %s\n", sqli_patterns[i].pattern);
            
            // Add to detected patterns string
            if (strlen(result.detected_patterns) < 900) {
                if (strlen(result.detected_patterns) > 0) {
                    strcat(result.detected_patterns, "; ");
                }
                strcat(result.detected_patterns, sqli_patterns[i].description);
            }
        }
    }

    if (result.total_score >= 100) {
        return SEVERITY_HIGH;
    } else if (result.total_score >= 50) {
        return SEVERITY_MEDIUM;
    } else if (result.total_score > 0) {
        return SEVERITY_LOW;
    }

    fprintf(stderr, "%s", input);
    return SEVERITY_NONE;
}

// ---------------------------- PATTERN MATCHING -------------------------------

const char *sql_keywords[] = {
    "select", "union", "insert", "update", "delete", "drop", "create", "alter",
    "exec", "execute", "declare", "cast", "convert", "having", "group",
    "order", "where", "from", "into", "values", "table", "database",
    "schema", "column", "index", "view", "trigger", "procedure", "function",
    NULL
};

const char *sql_operators[] = {
    "or", "and", "not", "like", "between", "in", "exists", "any", "all",
    NULL
};

const char *sql_comment_patterns[] = {
    "--", "-- ", "--+", "/*", "*/", "#", ";--",
    NULL
};

const char *sql_dangerous_functions[] = {
    "concat(", "version(", "database(", "user(", "@@", "information_schema",
    "sys.", "master.", "pg_", "mysql.", "sqlite_", NULL
};

const char *sql_injection_patterns[] = {
    // Classic patterns
    "' or 1=1",
    "' or '1'='1",
    "' or 1=1--",
    "' or 1=1#",
    "' or 1=1/*",
    "\" or 1=1",
    "\" or \"1\"=\"1",
    
    // Union-based
    "union select",
    "union all select",
    "' union select",
    "\" union select",
    
    // Boolean-based blind
    "' and 1=1",
    "' and 1=2",
    "and (select",
    "or (select",
    
    // Time-based blind
    "sleep(",
    "waitfor delay",
    "pg_sleep(",
    "benchmark(",
    
    // Error-based
    "extractvalue(",
    "updatexml(",
    "exp(~(select",
    
    // Stacked queries
    "'; insert",
    "'; update",
    "'; delete",
    "'; drop",
    
    // Hex/Char encoding
    "0x",
    "char(",
    "ascii(",
    "substring(",
    "mid(",
    "left(",
    "right(",

    "admin'--", "admin'#",           // Auth bypass
    "' having 1=1--", " having 1=1", // Having clause
    "1' waitfor delay '00:00:05",    // Time delay
    "' and (select count(*)",        // Blind injection
    "convert(int,(select",           // Error-based
    
    NULL
};




severity_t check_sql_injection(const char *input, http_request_part location){
    if (!input || strlen(input) == 0) {
        return SEVERITY_NONE;
    }

    char *in = strdup(input);
    // fprintf(stderr, "%s", in);
    if (location == HTTP_REQUEST_HEADERS) {
        in = extract_json_values(input);
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

    free(in);
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
