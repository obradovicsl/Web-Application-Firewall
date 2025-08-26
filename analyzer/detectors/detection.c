#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "detection.h"
#include "html-decoder.h"


CompiledRegexPattern compiled_patterns[128];

static int patterns_initialized = 0;
static int pattern_count = 0;


int init_regex_patterns() {
    if (patterns_initialized) {
        return 1;
    }
    
    pattern_count = 0;

    char* json_data = read_file("proxy/rules/regex_patterns.json");
    if (!json_data) {
        fprintf(stderr, "Could not read regex_patterns.json\n");
        return 0;
    }

    struct json_object* root = json_tokener_parse(json_data);
    free(json_data);
    if (!root) {
        fprintf(stderr, "JSON parse error\n");
        return 0;
    }

    struct json_object* rules;
    if (!json_object_object_get_ex(root, "rules", &rules) ||
        !json_object_is_type(rules, json_type_array)) {
        fprintf(stderr, "rules is not array\n");
        json_object_put(root);
        return 0;
    }

    int n_rules = json_object_array_length(rules);
    for (int i = 0; i < n_rules; i++) {
        struct json_object *rule = json_object_array_get_idx(rules, i);
        struct json_object *pattern, *desc, *severity, *category;

        if (json_object_object_get_ex(rule, "pattern", &pattern) &&
            json_object_object_get_ex(rule, "description", &desc) &&
            json_object_object_get_ex(rule, "severity", &severity) &&
            json_object_object_get_ex(rule, "category", &category)) {

            const char* pat = json_object_get_string(pattern);
            const char* dsc = json_object_get_string(desc);
            int sev = json_object_get_int(severity);
            const char* cat = json_object_get_string(category);

            // fprintf(stderr, "Pattern: %s\nDesc: %s\nSeverity: %d\nCategory: %s\n\n",
            //        pat, dsc, sev, cat);

            re2_pattern_t* regex = re2_compile(pat);
        
            if (regex && re2_is_valid(regex)) {
                compiled_patterns[pattern_count].compiled_regex = regex;
                compiled_patterns[pattern_count].description = strdup(dsc);
                compiled_patterns[pattern_count].attack = strdup(cat); // Attack type
                compiled_patterns[pattern_count].severity = sev;
                pattern_count++;
            } else {
                fprintf(stderr, "Failed to compile pattern: %s\n", pat);
                if (regex) re2_free(regex);
            }
        }        
    }
    
    json_object_put(root);
    patterns_initialized = 1;
    return 1;
}

void cleanup_regex_patterns() {
    if (!patterns_initialized) return;
    
    for (int i = 0; i < pattern_count; i++) {
        if (compiled_patterns[i].compiled_regex) {
            re2_free(compiled_patterns[i].compiled_regex);
            compiled_patterns[i].compiled_regex = NULL;
        }

        if (compiled_patterns[i].description) {
            free((void*)compiled_patterns[i].description);
            compiled_patterns[i].description = NULL;
        }
        if (compiled_patterns[i].attack) {
            free((void*)compiled_patterns[i].attack);
            compiled_patterns[i].attack = NULL;
        }
    }
    
    patterns_initialized = 0;
    pattern_count = 0;
}

void analyze(const char *input, const char *location, detection_report_t *findings) {
    
    if (!input || strlen(input) == 0) {
        return;
    }

    if (!patterns_initialized) {
        init_regex_patterns();
    }

    for (int i = 0; i < pattern_count; i++) {
        int start, end;
   
        if (re2_find(compiled_patterns[i].compiled_regex, input, &start, &end)) {

            findings->items = realloc(findings->items, (findings->count + 1) * sizeof(detection_t));

            findings->items[findings->count++] = (detection_t){
                .attack = compiled_patterns[i].attack,
                .description = compiled_patterns[i].description,
                .location = location,
            };

            // fprintf(stderr, "✓ MATCH: %s\n", compiled_patterns[i].description);
        }
    }
}

// HELPERS

char* read_file(const char* filename) {
    FILE* f = fopen(filename, "rb");
    if (!f) {
        perror("fopen failed");
        return NULL;
    }
    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    rewind(f);

    char* data = malloc(len + 1);
    if (!data) {
        fclose(f);
        return NULL;
    }
    fread(data, 1, len, f);
    data[len] = '\0';
    fclose(f);
    return data;
}