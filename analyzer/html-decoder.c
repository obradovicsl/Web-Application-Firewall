#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <uri_encode.h>
#include <ctype.h>


#include "html-decoder.h"

static size_t utf8_encode(uint32_t cp, char *out, size_t out_size) {
    if (cp <= 0x7F) {
        if (out_size < 1) return 0;
        out[0] = (char)cp;
        return 1;
    } else if (cp <= 0x7FF) {
        if (out_size < 2) return 0;
        out[0] = (char)(0xC0 | (cp >> 6));
        out[1] = (char)(0x80 | (cp & 0x3F));
        return 2;
    } else if (cp <= 0xFFFF) {
        if (out_size < 3) return 0;
        out[0] = (char)(0xE0 | (cp >> 12));
        out[1] = (char)(0x80 | ((cp >> 6) & 0x3F));
        out[2] = (char)(0x80 | (cp & 0x3F));
        return 3;
    } else if (cp <= 0x10FFFF) {
        if (out_size < 4) return 0;
        out[0] = (char)(0xF0 | (cp >> 18));
        out[1] = (char)(0x80 | ((cp >> 12) & 0x3F));
        out[2] = (char)(0x80 | ((cp >> 6) & 0x3F));
        out[3] = (char)(0x80 | (cp & 0x3F));
        return 4;
    }
    return 0; // nevalidan codepoint
}


typedef struct {
    const char *name;
    uint32_t codepoint;
} Entity;

static const Entity entities[] = {
    {"lt", '<'}, {"gt", '>'}, {"amp", '&'},
    {"quot", '"'}, {"apos", '\''},
    {"nbsp", 0x00A0}, {"copy", 0x00A9}, {"euro", 0x20AC},
};

static bool lookup_entity(const char *src, size_t len, uint32_t *out_cp, size_t *consumed) {
    for (size_t i = 0; i < sizeof(entities)/sizeof(entities[0]); i++) {
        size_t nlen = strlen(entities[i].name);
        if (len >= nlen + 2 && src[0] == '&' &&
            strncmp(src + 1, entities[i].name, nlen) == 0 &&
            src[1+nlen] == ';') {
            *out_cp = entities[i].codepoint;
            *consumed = nlen + 2;
            return true;
        }
    }
    return false;
}


size_t html_entity_decode(const char *src, size_t len, char *dst, size_t dst_size) {
    size_t i = 0, j = 0;

    while (i < len) {
        if (src[i] == '&') {
            // 1. Named entities
            uint32_t cp;
            size_t consumed;
            if (lookup_entity(src + i, len - i, &cp, &consumed)) {
                size_t written = utf8_encode(cp, dst + j, dst_size - j);
                if (!written) break;
                j += written;
                i += consumed;
                continue;
            }

            // 2. Numeric entities
            if (i + 3 < len && src[i+1] == '#') {
                int base = 10;
                size_t k = i + 2;
                if (k < len && (src[k] == 'x' || src[k] == 'X')) {
                    base = 16;
                    k++;
                }

                char *endptr;
                long cp_long = strtol(src + k, &endptr, base);
                if (endptr && *endptr == ';' && cp_long > 0 && cp_long <= 0x10FFFF) {
                    cp = (uint32_t)cp_long;
                    size_t written = utf8_encode(cp, dst + j, dst_size - j);
                    if (!written) break;
                    j += written;
                    i = (endptr - src) + 1;
                    continue;
                }
            }
        }

        // default: copy char as an UTF-8 byte
        if (j + 1 < dst_size) {
            dst[j++] = src[i++];
        } else {
            break;
        }
    }

    if (j < dst_size) dst[j] = '\0';
    return j;
}


char *normalize_str(const char *src) {
    if (!src) return NULL;
    size_t len = strlen(src);

    // URI decode
    char *buf1 = malloc(len + 1);  // +1 za '\0'
    if (!buf1) return NULL;
    size_t out_len = uri_decode(src, len, buf1);
    buf1[out_len] = '\0'; 

    // HTML entity decode
    char *buf2 = malloc(out_len + 1);
    if (!buf2) {
        free(buf1);
        return NULL;
    }
    size_t html_len = html_entity_decode(buf1, out_len, buf2, out_len + 1);
    buf2[html_len] = '\0';
    free(buf1);

    // whitespace + lowercase
    char *dst = malloc(html_len + 1);
    if (!dst) {
        free(buf2);
        return NULL;
    }

    size_t j = 0;
    int in_space = 0;
    for (size_t i = 0; i < html_len; i++) {
        unsigned char c = (unsigned char)buf2[i];
        if (iscntrl(c)) continue;
        if (isspace(c)) {
            if (!in_space) dst[j++] = ' ';
            in_space = 1;
            continue;
        }
        dst[j++] = (char)tolower(c);
        in_space = 0;
    }
    dst[j] = '\0';
    free(buf2);

    return dst;
}
