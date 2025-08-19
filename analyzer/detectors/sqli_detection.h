#ifndef SQL_DETECTION
#define SQL_DETECTION

#include "models.h"



severity_t check_sql_injection(const char *input, http_request_part location);
severity_t calculate_sql_heuristic(int quote_count, int sql_keywords_count, int comment_found, http_request_part location);


static const char *sql_keywords[] = {
    "select", "union", "insert", "update", "delete", "drop", "create", "alter",
    "exec", "execute", "declare", "cast", "convert", "having", "group",
    "order", "where", "from", "into", "values", "table", "database",
    "schema", "column", "index", "view", "trigger", "procedure", "function",
    NULL
};

static const char *sql_operators[] = {
    "or", "and", "not", "like", "between", "in", "exists", "any", "all",
    NULL
};

static const char *sql_comment_patterns[] = {
    "--", "-- ", "--+", "/*", "*/", "#", ";--",
    NULL
};

static const char *sql_dangerous_functions[] = {
    "concat(", "version(", "database(", "user(", "@@", "information_schema",
    "sys.", "master.", "pg_", "mysql.", "sqlite_", NULL
};

static const char *sql_injection_patterns[] = {
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


#endif