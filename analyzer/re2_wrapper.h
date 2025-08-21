// re2_wrapper.h
#ifndef RE2_WRAPPER_H
#define RE2_WRAPPER_H

#ifdef __cplusplus
extern "C" {
#endif

typedef struct re2_pattern re2_pattern_t;

// Kreira novi regex pattern
re2_pattern_t* re2_compile(const char* pattern);

// Oslobađa memoriju
void re2_free(re2_pattern_t* pattern);

// Match funkcije
int re2_match(re2_pattern_t* pattern, const char* text);
int re2_find(re2_pattern_t* pattern, const char* text, int* start, int* end);

// Replace funkcija
char* re2_replace(re2_pattern_t* pattern, const char* text, const char* replacement);

// Provjera da li je pattern validan
int re2_is_valid(re2_pattern_t* pattern);

#ifdef __cplusplus
}
#endif

#endif // RE2_WRAPPER_H