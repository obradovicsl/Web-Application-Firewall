#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <json-c/json.h>
#include <unistd.h>
#include <ctype.h>
#include <uri_encode.h>

typedef struct{
    char *url;
    char *headers;
    char *body;
}request_t;


typedef enum{
    CLEAN = 0,
    SQL_INJECTION = 1,
    XSS = 2,
    DIRECTORY_TRAVERSAL = 3
}attack_type_t;

typedef enum{
    SEVERITY_NONE = 0,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
    SEVERITY_HIGH
}severity_t;

typedef struct {
    const char *attack;
    const char *severity;
    const char *location;
}finding_t;

typedef struct {
    finding_t *items;
    size_t count;
}findings_t;


size_t html_entity_decode(const char *src, size_t len, char *dst);
char *normalize_str(const char *src);
void process_request(const char *json_input);
void analyze_request(request_t *req, findings_t *findings);
void print_result(findings_t *findings);
void check_component(const char *input, const char *location, findings_t *findings);
const char *attack_type_to_str(attack_type_t type);
const char *severity_to_str(severity_t type);
severity_t check_sql_injection(const char *input);
severity_t calculate_sql_heuristic(int quote_count, int sql_keywords_count, int comment_found);

int main(){

    setvbuf(stdout, NULL, _IONBF, 0); // Unbuffered stdout
    setvbuf(stderr, NULL, _IONBF, 0); // Unbuffered stderr
    
    size_t buffer_size = 1024 * 1024;
    char *buffer = malloc(buffer_size);
    if (!buffer) {
        fprintf(stderr, "{\"error\":\"Memory allocation failed\"}\n");    
        return 1;
    }

    // Ready signal
    printf("{\"status\":\"ready\"}\n");
    fflush(stdout);

    char *line = NULL;
    size_t len = 0;
    ssize_t read;

    // Waiting for JSON req
    while((read = getline(&line, &len, stdin)) != -1){

        // fprintf(stderr, "DEBUG: Received %zd bytes\n", read);

        if (read > 0 && line[read - 1] == '\n'){
            line[read - 1] = '\0';
            read--;
        }

        if (read > 0) {
            // fprintf(stderr, "DEBUG: Processing request\n");
            process_request(line);
            // fprintf(stderr, "DEBUG: Request processed\n");
        }

        if (line) {
            free(line);
            line = NULL;
            len = 0;
        }
    }

    if (line) free(line);
    free(buffer);

    // fprintf(stderr, "DEBUG: Main loop ended\n");
    return 0;
}

size_t html_entity_decode(const char *src, size_t len, char *dst) {
    size_t i = 0, j = 0;

    while (i < len) {
        if (src[i] == '&') {
            // decimal &#123;
            if (i + 2 < len && src[i+1] == '#') {
                int base = 10;
                size_t k = i + 2;

                if (k < len && (src[k] == 'x' || src[k] == 'X')) {
                    base = 16;
                    k++;
                }

                char *endptr;
                long code = strtol(src + k, &endptr, base);

                if (endptr && *endptr == ';') {
                    dst[j++] = (char)(code & 0xFF);
                    i = (endptr - src) + 1;
                    continue;
                }
            }
            // named &lt; &gt; &amp; &quot; &apos;
            else if (strncmp(src + i, "&lt;", 4) == 0) {
                dst[j++] = '<'; i += 4; continue;
            } else if (strncmp(src + i, "&gt;", 4) == 0) {
                dst[j++] = '>'; i += 4; continue;
            } else if (strncmp(src + i, "&amp;", 5) == 0) {
                dst[j++] = '&'; i += 5; continue;
            } else if (strncmp(src + i, "&quot;", 6) == 0) {
                dst[j++] = '"'; i += 6; continue;
            } else if (strncmp(src + i, "&apos;", 6) == 0) {
                dst[j++] = '\''; i += 6; continue;
            }
        }

        // default: kopiraj znak
        dst[j++] = src[i++];
    }

    dst[j] = '\0';
    return j;
}

char *normalize_str(const char *src) {
    if (!src) return NULL;
    size_t len = strlen(src);

    // URI decode
    char *buf1 = malloc(len + 1);  // +1 za '\0'
    if (!buf1) return NULL;
    size_t out_len = uri_decode(src, len, buf1);
    buf1[out_len] = '\0'; // dodaj terminator

    // HTML entity decode
    char *buf2 = malloc(out_len + 1);
    if (!buf2) {
        free(buf1);
        return NULL;
    }
    size_t html_len = html_entity_decode(buf1, out_len, buf2);
    buf2[html_len] = '\0';
    free(buf1);

    // whitespace + lowercase
    char *dst = malloc(html_len + 1);
    if (!dst) {
        free(buf2);
        return NULL;
    }

    size_t j = 0;
    int in_space = 0;
    for (size_t i = 0; i < html_len; i++) {
        unsigned char c = (unsigned char)buf2[i];
        if (iscntrl(c)) continue;
        if (isspace(c)) {
            if (!in_space) dst[j++] = ' ';
            in_space = 1;
            continue;
        }
        dst[j++] = (char)tolower(c);
        in_space = 0;
    }
    dst[j] = '\0';
    free(buf2);

    return dst;
}

void process_request(const char *json_input){
    json_object *root = json_tokener_parse(json_input);
    if(!root){
        fprintf(stderr, "{\"error\":\"Invalid JSON\"}\n");
        return;
    }

    request_t req = {0};

    json_object *url_obj;
    if (json_object_object_get_ex(root, "url", &url_obj)){
        const char *raw = json_object_get_string(url_obj);
        req.url = strdup(normalize_str(raw));
    }

    json_object *headers_obj;
    if (json_object_object_get_ex(root, "headers", &headers_obj)){
        const char *raw = json_object_get_string(headers_obj);
        req.headers = strdup(normalize_str(raw));
    }

    json_object *body_obj;
    if (json_object_object_get_ex(root, "body", &body_obj)){
        const char *raw = json_object_get_string(body_obj);
        req.body = strdup(normalize_str(raw));
    }

    findings_t findings;
    findings.count=0;
    findings.items=NULL;

    analyze_request(&req, &findings);

    print_result(&findings);

    free(findings.items);
    free(req.url);
    free(req.headers);
    free(req.body);
    json_object_put(root);
}

void analyze_request(request_t *req, findings_t *findings){
    attack_type_t result;
    // Analyze URL
    if (req->url) check_component(req->url, "url", findings);

    // Analyze Header
    if (req->headers) check_component(req->headers, "headers", findings);

    // Analyze Body
    if (req->body) check_component(req->body, "body", findings);
}

void check_component(const char *input, const char *location, findings_t *findings) {
    if (!input) return;
    severity_t res[10] = {SEVERITY_NONE};
    severity_t r;

    res[SQL_INJECTION - 1] = check_sql_injection(input);
    // res[XSS - 1] = check_xss(input);

    for (int i = 0; i < 10; i++) {
        if (res[i] != SEVERITY_NONE) {
            findings->items = realloc(findings->items, (findings->count + 1) * sizeof(finding_t));
            findings->items[findings->count++] = (finding_t){
                .attack = attack_type_to_str(i + 1),
                .severity = severity_to_str(res[i]),
                .location = location
            };
        }
    }
}

const char *attack_type_to_str(attack_type_t type) {
    switch (type) {
        case SQL_INJECTION: 
            return "SQL_INJECTION";
            break;
        case XSS: 
            return "XSS";
            break;
        case DIRECTORY_TRAVERSAL: 
            return "DIRECTORY_TRAVERSAL";
            break;
        default: 
            break;
    }
    return "";
}

const char *severity_to_str(severity_t type) {
    switch (type)
    {
    case SEVERITY_LOW:
        return "LOW";
        break;
    case SEVERITY_MEDIUM:
        return "MEDIUM";
        break;
    case SEVERITY_HIGH:
        return "HIGH";
        break;
    
    default:
        break;
    }
    return "";
}

void print_result(findings_t *findings) {

    char *output = NULL;
    size_t output_size = 0;
    size_t output_capacity = 1024; // 1KB

    output = malloc(output_capacity);
    if (!output) return;

    if (findings->count == 0) {
        strcpy(output, "{\"status\":\"clean\",\"findings\":[]}");
    } else {
        output_size = snprintf(output, output_capacity, "{\"status\":\"attack\",\"findings\":[");

        for (size_t i = 0; i < findings->count; i++) {
            int needed = snprintf(NULL, 0,
                "%s{\"attack\":\"%s\",\"severity\":\"%s\",\"location\":\"%s\"}",
                (i > 0 ? "," : ""),
                findings->items[i].attack,
                findings->items[i].severity,
                findings->items[i].location);
            
            if (output_size + needed >= output_capacity) {
                output_capacity = (output_size + needed + 1) * 2;
                output = realloc(output, output_capacity);
                if (!output) return;
            }

            output_size += snprintf(output + output_size, output_capacity - output_size,
                                   "%s{\"attack\":\"%s\",\"severity\":\"%s\",\"location\":\"%s\"}",
                                   (i > 0 ? "," : ""),
                                   findings->items[i].attack,
                                   findings->items[i].severity,
                                   findings->items[i].location);
        }
        if (output_size + 3 < output_capacity) {
            strcat(output, "]}");
        }
    }

    fprintf(stdout, "%s\n", output);
    fflush(stdout);

    free(output);
}

// -------------------------------------  SQL INJECTION  -------------------------------------------- 

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
    "--", "/*", "*/", "#",
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
    
    NULL
};


severity_t check_sql_injection(const char *input){
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

    return calculate_sql_heuristic(quote_count, sql_keywords_count, comment_found);
}

severity_t calculate_sql_heuristic(int quote_count, int sql_keywords_count, int comment_found) {
    if (sql_keywords_count == 0 && quote_count == 0) return SEVERITY_NONE;
    if (sql_keywords_count >= 2 && quote_count > 0 && comment_found) return SEVERITY_MEDIUM;
    if (sql_keywords_count >= 1 && quote_count >= 2) return SEVERITY_MEDIUM;
    if (sql_keywords_count >= 3) return SEVERITY_MEDIUM;    
    return SEVERITY_NONE;
}


// -------------------------------------  XSS  -------------------------------------------- 