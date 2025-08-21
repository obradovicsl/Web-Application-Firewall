#include "re2_wrapper.h"
#include <re2/re2.h>
#include <string>
#include <cstring>
#include <cstdlib>

struct re2_pattern {
    RE2* regex;
    bool is_valid;
};

extern "C" {

re2_pattern_t* re2_compile(const char* pattern) {
    if (!pattern) return nullptr;
    
    re2_pattern_t* p = new re2_pattern_t;
    p->regex = new RE2(pattern);
    p->is_valid = p->regex->ok();
    
    if (!p->is_valid) {
        return p;
    }
    
    return p;
}

void re2_free(re2_pattern_t* pattern) {
    if (pattern) {
        delete pattern->regex;
        delete pattern;
    }
}

int re2_is_valid(re2_pattern_t* pattern) {
    return (pattern && pattern->is_valid) ? 1 : 0;
}

int re2_match(re2_pattern_t* pattern, const char* text) {
    if (!pattern || !pattern->is_valid || !text) return 0;
    
    return RE2::FullMatch(text, *pattern->regex) ? 1 : 0;
}

int re2_find(re2_pattern_t* pattern, const char* text, int* start, int* end) {
    if (!pattern || !pattern->is_valid || !text || !start || !end) return 0;
    
    re2::StringPiece input(text);
    re2::StringPiece match;
    
    if (RE2::FindAndConsume(&input, *pattern->regex, &match)) {
        size_t original_len = strlen(text);
        size_t remaining_len = input.size();
        
        *start = original_len - remaining_len - match.size();
        *end = *start + match.size();
        return 1;
    }
    
    return 0;
}

char* re2_replace(re2_pattern_t* pattern, const char* text, const char* replacement) {
    if (!pattern || !pattern->is_valid || !text || !replacement) return nullptr;
    
    std::string input(text);
    std::string result = input;
    
    RE2::GlobalReplace(&result, *pattern->regex, replacement);
    
    size_t len = result.length();
    char* c_result = (char*)malloc(len + 1);
    if (c_result) {
        memcpy(c_result, result.c_str(), len + 1);
    }
    
    return c_result;
}

}