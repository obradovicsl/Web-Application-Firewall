#ifndef HTML_DECODER
#define HTML_DECODER

#include "models.h"

size_t html_entity_decode(const char *src, size_t len, char *dst, size_t dst_size);
char *normalize_str(const char *src);

#endif