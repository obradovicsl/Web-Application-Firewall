#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>

#include <json-c/json.h>

#include "detection.h"
#include "html-decoder.h"

request_t *parse_input(const char *json_input, size_t *out_count);
void analyze_request(request_t *req, detection_report_t *detection_report);
char *generate_result(detection_report_t *detection_report);
char *process_requests(request_t *requests, size_t count);

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
            request_t *requests = parse_input(line, &requests_len);
            // fprintf(stderr, "Analyzing %zu requests", requests_len);

            if (requests) {
                char *result = process_requests(requests, requests_len);
                if (result) {
                    fprintf(stdout, "%s\n", result);
                    free(result);
                }

                // Free
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

    cleanup_regex_patterns();
    return 0;
}

request_t *parse_input(const char *json_input, size_t *out_count) {
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

char *process_requests(request_t *requests, size_t req_count) {
    struct json_object *jarray = json_object_new_array();

    detection_report_t detection_report;
    detection_report.count=0;
    detection_report.items=NULL;


    for (size_t i = 0; i < req_count; i++) {
        analyze_request(&requests[i], &detection_report);
        char *req_output = generate_result(&detection_report);

        struct json_object *jobj = json_object_new_object();

        if (requests[i].id) {
            json_object_object_add(jobj, "id", json_object_new_string(requests[i].id));
        } else {
            json_object_object_add(jobj, "id", json_object_new_string(""));
        }

        if (req_output) {
            json_object_object_add(jobj, "result", json_object_new_string(req_output));
            free(req_output);
        } else {
            json_object_object_add(jobj, "result", json_object_new_string(""));
        }

        json_object_array_add(jarray, jobj);
        free(detection_report.items);
        detection_report.items = NULL;
        detection_report.count = 0;
    }

    // Conver JSON array to string
    const char *json_str = json_object_to_json_string_ext(jarray, JSON_C_TO_STRING_PLAIN);
    char *output = strdup(json_str); // hard copy

    // Free memory
    json_object_put(jarray);
    return output;
}

void analyze_request(request_t *request, detection_report_t *detection_report){

    if (request->url) {
        analyze(request->url, "url", detection_report);
        // Add other functions
    }

    if (request->headers) {
        analyze(request->headers, "headers", detection_report);
        // Add other functions
    }

    if (request->body) {
        analyze(request->body, "body", detection_report);
        // Add other functions
    }
}

char *generate_result(detection_report_t *detection_report) {
    struct json_object *root = json_object_new_object();

    if (detection_report->count == 0) {
        json_object_object_add(root, "status", json_object_new_string("clean"));
        json_object_object_add(root, "findings", json_object_new_array());
    } else {
        json_object_object_add(root, "status", json_object_new_string("attack"));

        struct json_object *arr = json_object_new_array();

        for (size_t i = 0; i < detection_report->count; i++) {
            struct json_object *item = json_object_new_object();

            json_object_object_add(item, "attack",
                                   json_object_new_string(detection_report->items[i].attack));
            json_object_object_add(item, "location",
                                   json_object_new_string(detection_report->items[i].location));
            json_object_object_add(item, "severity",
                                   json_object_new_string(detection_report->items[i].description));

            json_object_array_add(arr, item);
        }

        json_object_object_add(root, "findings", arr);
    }

    const char *tmp = json_object_to_json_string_ext(root, JSON_C_TO_STRING_PLAIN);
    char *output = strdup(tmp);
    json_object_put(root);
    return output;
}