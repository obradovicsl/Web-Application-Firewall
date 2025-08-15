#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <json-c/json.h>

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

    char buffer[65536]; // 64KB buffer

    // Ready signal
    printf("{\"status\":\"ready\"}\n");
    fflush(stdout);

    // Waiting for JSON req
    while(fgets(buffer, sizeof(buffer), stdin)){
        buffer[strcspn(buffer, "\n")] = 0;

        if(strlen(buffer) > 0){
            process_request(buffer);
        }
    }

    return 0;
}

void process_request(const char *json_input){
    json_object *root = json_tokener_parse(json_input);
    if(!root){
        printf("{\"error\":\"Invalid JSON\"}\n");
        fflush(stdout);
        return;
    }

    request_t req;

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
        printf("{\"status\":\"clean\",\"attack\":null}\n");
    }else {
        printf("{\"status\":\"attack\",\"attack\":%d}\n", attack);
    }
    fflush(stdout);

    free(req.url);
    free(req.headers);
    free(req.body);
    json_object_put(root);
}

attack_type_t analyze_request(request_t *req){
    attack_type_t result;

    // Analyze URL
    if ((result = check_sql_injection(req->url)) != CLEAN) return result;

    // Analyze Header
    if (req->headers){
        if ((result = check_sql_injection(req->headers)) != CLEAN) return result;
    }

    // Analyze Body
    if (req->body){
        if ((result = check_sql_injection(req->body)) != CLEAN) return result;
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