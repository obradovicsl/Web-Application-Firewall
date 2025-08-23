#ifndef HTML_DECODER
#define HTML_DECODER
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include "models.h"

size_t html_entity_decode(const char *src, size_t len, char *dst, size_t dst_size);
static size_t utf8_encode(uint32_t cp, char *out, size_t out_size);
static bool lookup_entity(const char *src, size_t len, uint32_t *out_cp, size_t *consumed);
char *normalize_str(const char *src);
char *extract_json_values(const char *text);

#endif