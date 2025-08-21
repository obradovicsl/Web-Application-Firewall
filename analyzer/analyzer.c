#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>

#include <json-c/json.h>


#include "models.h"
#include "sqli_detection.h"
#include "xss_detection.h"
#include "html-decoder.h"

void process_request(const char *json_input);
void analyze_request(request_t *req, findings_t *findings);
void print_result(findings_t *findings);
const char *http_part_to_str(http_request_part part);
void check_component(const char *input, http_request_part location, findings_t *findings);
const char *attack_type_to_str(attack_type_t type);
const char *severity_to_str(severity_t type);


int main(){

    setvbuf(stdout, NULL, _IONBF, 0); // Unbuffered stdout
    setvbuf(stderr, NULL, _IONBF, 0); // Unbuffered stderr
    
    size_t buffer_size = 1024 * 1024;
    char *buffer = malloc(buffer_size);
    if (!buffer) {
        fprintf(stderr, "{\"error\":\"Memory allocation failed\"}\n");    
        return 1;
    }


    // Compile REGEX patterns
    init_sqli_patterns();
    init_xss_patterns();

    
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


    cleanup_sqli_patterns();
    cleanup_xss_patterns();

    // fprintf(stderr, "DEBUG: Main loop ended\n");
    return 0;
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
        req.url = normalize_str(raw);
    }

    json_object *headers_obj;
    if (json_object_object_get_ex(root, "headers", &headers_obj)){
        const char *raw = json_object_get_string(headers_obj);
        req.headers = normalize_str(raw);
    }

    json_object *body_obj;
    if (json_object_object_get_ex(root, "body", &body_obj)){
        const char *raw = json_object_get_string(body_obj);
        req.body = normalize_str(raw);
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
    if (req->url) check_component(req->url, HTTP_REQUEST_URL, findings);

    // Analyze Header
    if (req->headers) check_component(req->headers, HTTP_REQUEST_HEADERS, findings);

    // Analyze Body
    if (req->body) check_component(req->body, HTTP_REQUEST_BODY, findings);
}

void check_component(const char *input, http_request_part location, findings_t *findings) {
    if (!input) return;
    severity_t res[10] = {SEVERITY_NONE};
    severity_t r;
    // fprintf(stderr, "%s, %s", http_part_to_str(location), input);

    // res[SQL_INJECTION - 1] = check_sql_injection(input, location);
    res[SQL_INJECTION - 1] = detect_sqli_optimized(input);
    res[XSS - 1] = detect_xss_optimized(input);

    for (int i = 0; i < 4; i++) {
        if (res[i] != SEVERITY_NONE) {
            findings->items = realloc(findings->items, (findings->count + 1) * sizeof(finding_t));
            findings->items[findings->count++] = (finding_t){
                .attack = attack_type_to_str(i + 1),
                .severity = severity_to_str(res[i]),
                .location = http_part_to_str(location),
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

const char *http_part_to_str(http_request_part part) {
    switch (part)
    {
    case HTTP_REQUEST_URL:
        return "url";
        break;
    case HTTP_REQUEST_HEADERS:
        return "headers";
        break;
    case HTTP_REQUEST_BODY:
        return "body";
        break;
    
    default:
        break;
    }
    return "";
}

void print_result(findings_t *findings) {
    struct json_object *root = json_object_new_object();

    if (findings->count == 0) {
        json_object_object_add(root, "status", json_object_new_string("clean"));
        json_object_object_add(root, "findings", json_object_new_array());
    } else {
        json_object_object_add(root, "status", json_object_new_string("attack"));

        struct json_object *arr = json_object_new_array();

        for (size_t i = 0; i < findings->count; i++) {
            struct json_object *item = json_object_new_object();

            json_object_object_add(item, "attack",
                                   json_object_new_string(findings->items[i].attack));
            json_object_object_add(item, "severity",
                                   json_object_new_string(findings->items[i].severity));
            json_object_object_add(item, "location",
                                   json_object_new_string(findings->items[i].location));

            json_object_array_add(arr, item);
        }

        json_object_object_add(root, "findings", arr);
    }

    const char *output = json_object_to_json_string_ext(root, JSON_C_TO_STRING_PLAIN);
    fprintf(stdout, "%s\n", output);
    fflush(stdout);

    json_object_put(root);
}
