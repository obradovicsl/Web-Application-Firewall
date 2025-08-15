#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <json-c/json.h>
#include <unistd.h>

typedef struct{
    char *url;
    char *headers;
    char *body;
}request_t;

typedef enum{
    CLEAN = 0,
    SQL_INJECTION = 1,
    XSS = 2,
    DIRECTORY_TRAVERSAL = 3,
}attack_type_t;

void process_request(const char *json_input);
attack_type_t analyze_request(request_t *req);
attack_type_t check_sql_injection(const char *input);

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

void process_request(const char *json_input){
    json_object *root = json_tokener_parse(json_input);
    if(!root){
        fprintf(stderr, "{\"error\":\"Invalid JSON\"}\n");
        return;
    }

    request_t req = {0};

    json_object *url_obj;
    if (json_object_object_get_ex(root, "url", &url_obj)){
        req.url = strdup(json_object_get_string(url_obj));
    }

    json_object *headers_obj;
    if (json_object_object_get_ex(root, "headers", &headers_obj)){
        req.headers = strdup(json_object_get_string(headers_obj));
    }

    json_object *body_obj;
    if (json_object_object_get_ex(root, "body", &body_obj)){
        req.body = strdup(json_object_get_string(body_obj));
    }

    attack_type_t attack = analyze_request(&req);

    if (attack == CLEAN) {
        // fprintf(stderr, "DEBUG: Sending clean response\n");
        fprintf(stdout, "{\"status\":\"clean\",\"attack\":null}\n");
        // fprintf(stderr, "DEBUG: Clean response sent\n");
    }else {
        fprintf(stdout, "{\"status\":\"attack\",\"attack\":%d}\n", attack);
    }
    fflush(stdout);
    fsync(STDOUT_FILENO);

    free(req.url);
    free(req.headers);
    free(req.body);
    json_object_put(root);
}

attack_type_t analyze_request(request_t *req){
    attack_type_t result;

    // Analyze URL
    if (req->url && (result = check_sql_injection(req->url)) != CLEAN) {
        return result;
    }

    // Analyze Header
    if (req->headers && (result = check_sql_injection(req->headers)) != CLEAN){
        return result;
    }

    // Analyze Body
    if (req->body && (result = check_sql_injection(req->body)) != CLEAN){
        return result;
    }

    return CLEAN;
}

attack_type_t check_sql_injection(const char *input){
    const char *sql_patterns[] = {
        "UNION", "SELECT", "DROP", "INSERT", "DELETE",
        "OR 1=1", "' OR '", "-- ", "/*", NULL
    };

    for (int i = 0; sql_patterns[i] != NULL; i++){
        if (strcasestr(input, sql_patterns[i])) {
            return SQL_INJECTION;
        }
    }
    return CLEAN;
}