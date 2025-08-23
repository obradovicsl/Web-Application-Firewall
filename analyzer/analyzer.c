#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>

#include <json-c/json.h>


#include "detection.h"
#include "html-decoder.h"

request_t *parse_input_array(const char *json_input, size_t *out_count);
char *process_request(request_t *request);
void analyze_request(request_t *req, findings_t *findings);
char *print_result(findings_t *findings);
char *process_array_and_build_output(request_t *requests, size_t count);
const char *http_part_to_str(http_request_part part);
const char *attack_type_to_str(attack_type_t type);
const char *severity_to_str(severity_t type);


int main(){
    setvbuf(stdout, NULL, _IONBF, 0); // Unbuffered stdout
    setvbuf(stderr, NULL, _IONBF, 0); // Unbuffered stderr
    
    // Compile REGEX patterns
    init_regex_patterns();

    // Ready signal
    fprintf(stdout, "{\"status\":\"ready\"}\n");
    fflush(stdout);

    char *line = NULL;
    size_t len = 0;
    ssize_t read;

    // Waiting for JSON req
    while((read = getline(&line, &len, stdin)) != -1){

        if (read > 0 && line[read - 1] == '\n'){
            line[read - 1] = '\0';
            read--;
        }

        if (read > 0) {
            
            size_t requests_len = 0;
            request_t *requests = parse_input_array(line, &requests_len);
            // fprintf(stderr, "%zu Zahteva se obradjuje", requests_len);
            if (requests) {
                char *output = process_array_and_build_output(requests, requests_len);
                if (output) {
                    fprintf(stdout, "%s\n", output);
                    free(output);
                }

                for (int i = 0; i < requests_len; i++) {
                    free(requests[i].id);
                    free(requests[i].url);
                    free(requests[i].headers);
                    free(requests[i].body);
                }
                free(requests);
            }
        }

        if (line) {
            free(line);
            line = NULL;
            len = 0;
        }
    }

    if (line) free(line);
    cleanup_regex_patterns();
    return 0;
}

request_t *parse_input_array(const char *json_input, size_t *out_count) {
    // Initialize JSON parser, and check is input typeof arr
    json_object *root = json_tokener_parse(json_input);
    if(!root || !json_object_is_type(root, json_type_array)){
        fprintf(stderr, "{\"error\":\"Invalid JSON array\"}\n");
        if (root) json_object_put(root);
        *out_count = 0;
        return NULL;
    }

    // Get the length of array
    size_t len = json_object_array_length(root);
    request_t *requests = calloc(len, sizeof(request_t));
    if (!requests) {
        fprintf(stderr, "{\"error\":\"Memory allocation failed\"}\n");
        json_object_put(root);
        *out_count = 0;
        return NULL;
    }

    // Iterate through input req by req
    for (size_t i = 0; i < len; i++) {
        struct json_object *obj = json_object_array_get_idx(root, i);
        if (!obj || !json_object_is_type(obj, json_type_object)) {
            continue; // continue if its not an object
        }

        request_t *req = &requests[i];
        memset(req, 0, sizeof(request_t));

        struct json_object *id_obj;
        if (json_object_object_get_ex(obj, "id", &id_obj)) {
            const char *raw = json_object_get_string(id_obj);
            req->id = normalize_str(raw);
        }

        struct json_object *url_obj;
        if (json_object_object_get_ex(obj, "url", &url_obj)) {
            const char *raw = json_object_get_string(url_obj);
            req->url = normalize_str(raw);
        }

        struct json_object *headers_obj;
        if (json_object_object_get_ex(obj, "headers", &headers_obj)) {
            const char *raw = json_object_get_string(headers_obj);
            req->headers = normalize_str(raw);
        }

        struct json_object *body_obj;
        if (json_object_object_get_ex(obj, "body", &body_obj)) {
            const char *raw = json_object_get_string(body_obj);
            req->body = normalize_str(raw);
        }
    }

    json_object_put(root);
    *out_count = len;
    return requests;
}

char *process_request(request_t *request){
    findings_t findings;
    findings.count=0;
    findings.items=NULL;

    analyze_request(request, &findings);

    return print_result(&findings);
}

void analyze_request(request_t *req, findings_t *findings){
    attack_type_t result;
    // Analyze URL
    if (req->url) analyze(req->url, HTTP_REQUEST_URL, findings);

    // Analyze Header
    if (req->headers) analyze(req->headers, HTTP_REQUEST_HEADERS, findings);

    // Analyze Body
    if (req->body) analyze(req->body, HTTP_REQUEST_BODY, findings);
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
        case COMMAND_INJECTION: 
            return "COMMAND_TRAVERSAL";
            break;
        case LDAP_INJECTION: 
            return "LDAP_INJECTION";
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

char *print_result(findings_t *findings) {
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
                                   json_object_new_string(attack_type_to_str(findings->items[i].attack)));
            json_object_object_add(item, "location",
                                   json_object_new_string(http_part_to_str(findings->items[i].location)));
            json_object_object_add(item, "severity",
                                   json_object_new_string(findings->items[i].description));

            json_object_array_add(arr, item);
        }

        json_object_object_add(root, "findings", arr);
    }

    const char *tmp = json_object_to_json_string_ext(root, JSON_C_TO_STRING_PLAIN);
    char *output = strdup(tmp);
    json_object_put(root);
    return output;
}

char *process_array_and_build_output(request_t *requests, size_t count) {
    struct json_object *jarray = json_object_new_array();

    for (size_t i = 0; i < count; i++) {
        char *req_output = process_request(&requests[i]);

        struct json_object *jobj = json_object_new_object();

        if (requests[i].id) {
            json_object_object_add(jobj, "id", json_object_new_string(requests[i].id));
        } else {
            json_object_object_add(jobj, "id", json_object_new_string(""));
        }

        if (req_output) {
            json_object_object_add(jobj, "result", json_object_new_string(req_output));
            free(req_output); // oslobodi ako process_request alocira
        } else {
            json_object_object_add(jobj, "result", json_object_new_string(""));
        }

        json_object_array_add(jarray, jobj);
    }

    // Konvertuj ceo niz u string
    const char *json_str = json_object_to_json_string_ext(jarray, JSON_C_TO_STRING_PLAIN);
    char *output = strdup(json_str); // napravi kopiju jer ćemo sada osloboditi jarray
    json_object_put(jarray); // free json-c strukture

    return output;
}