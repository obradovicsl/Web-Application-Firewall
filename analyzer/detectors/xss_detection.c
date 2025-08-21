#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "xss_detection.h"


CompiledRegexPattern xss_compiled_patterns[64];
RawRegexPattern xss_raw_patterns[] = {
    // 1) <script> tag (svi case-ovi, sa ili bez closing /)
    {"(?i).*<(\\s)*script>.*", "Opening <script> tag present", 10},
    {"(?i).*<(\\s)*/\\s*script>.*", "Closing </script> tag present", 10},

    // 2) Inline event handler (onclick, onerror, onload, etc.)
    {"(?i).*<[^>]+(\\s)(on[a-z]{2,})(\\s)*=(\\s)*(\"[^\"]*\"|'[^']*'|[^(\\s)>]+).*", "Inline event handler attribute", 9},

    // 3) javascript: URI
    {"(?i).*(href|src|xlink:href|formaction|data|action)(\\s)*=(\\s)*(\"|'|)?(\\s)*javascript(\\s)*:.*", "javascript: URI in attribute", 10},

    // 4) vbscript: URI
    {"(?i).*(href|src|xlink:href|formaction)(\\s)*=(\\s)*(\"|'|)?(\\s)*vbscript(\\s)*:.*", "vbscript: URI in attribute", 8},

    // 5) data: URI with HTML/SVG/XML content
    {"(?i).*(href|src|xlink:href|formaction|srcset)(\\s)*=(\\s)*(\"[^\"]*\"|'[^']*'|[^(\\s)>]+)?(\\s)*data(\\s)*:(text/html|image/svg\\+xml|application/xml|application/xhtml\\+xml).*", "data: URI in attribute", 9},

    // 6) <img> with onerror/onload or src=javascript/data
    {"(?i).*<(\\s)*img\\b[^>]*\\b(onerror|onload)(\\s)*=(\\s)*(\"[^\"]*\"|'[^']*'|[^(\\s)>]+).*", "IMG with event handler", 9},
    {"(?i).*<(\\s)*img\\b[^>]*\\bsrc(\\s)*=(\\s)*(\"|'|)?(\\s)*(javascript(\\s)*:|data(\\s)*:).*", "IMG src javascript:/data:", 9},

    // 7) SVG elements or event handlers
    {"(?i).*<(\\s)*svg\\b[^>]*(\\s)on[a-z]{2,}(\\s)*=(\\s)*(\"[^\"]*\"|'[^']*'|[^(\\s)>]+).*", "SVG with event handler", 9},
    {"(?i).*<(\\s)*(svg|animate|set|foreignObject).*", "Potentially dangerous SVG element", 8},

    // 8) MathML/XML
    {"(?i).*<(\\s)*(math|xml).*", "MathML/XML container", 7},

    // 9) iframe/object/embed/applet
    {"(?i).*<(\\s)*(iframe|object|embed|applet).*", "Active content tag", 8},
    {"(?i).*<(\\s)*iframe\\b[^>]*\\bsrcdoc(\\s)*=.*", "Iframe with srcdoc", 9},

    // 10) meta refresh with javascript
    {"(?i).*<(\\s)*meta\\b[^>]*http-equiv(\\s)*=(\\s)*(\"refresh\"|'refresh'|refresh)[^>]*content(\\s)*=(\\s)*\"[^\"]*javascript(\\s)*:.*", "Meta refresh javascript (double quotes)", 8},
    {"(?i).*<(\\s)*meta\\b[^>]*http-equiv(\\s)*=(\\s)*(\"refresh\"|'refresh'|refresh)[^>]*content(\\s)*=(\\s)*'[^']*javascript(\\s)*:.*", "Meta refresh javascript (single quotes)", 8},
    {"(?i).*<(\\s)*meta\\b[^>]*http-equiv(\\s)*=(\\s)*(\"refresh\"|'refresh'|refresh)[^>]*content(\\s)*=[^(\\s)>]*javascript(\\s)*:.*", "Meta refresh javascript (no quotes)", 8},

    // 11) <base> href
    {"(?i).*<(\\s)*base\\b[^>]*href(\\s)*=.*", "Base href present", 5},

    // 12) CSS expression() in style
    {"(?i).*style(\\s)*=(\\s)*(\"[^\"]*\"|'[^']*'|[^(\\s)>]+).*expression(\\s)*\\(.*", "CSS expression() in style", 8},

    // 13) CSS url(javascript:)
    {"(?i).*style(\\s)*=(\\s)*(\"[^\"]*\"|'[^']*'|[^(\\s)>]+).*url(\\s)*\\((\\s)*javascript(\\s)*:.*", "CSS url(javascript:)", 9},

    // 14) -moz-binding
    {"(?i).*style(\\s)*=(\\s)*(\"[^\"]*\"|'[^']*'|[^(\\s)>]+).*\\-moz-binding(\\s)*:(\\s)*url(\\s)*\\(.*", "CSS -moz-binding", 7},

    // 15) formaction/javascript
    {"(?i).*formaction(\\s)*=(\\s)*(\"|'|)?(\\s)*javascript(\\s)*:.*", "formaction=javascript:", 8},

    // 16) srcset/javascript
    {"(?i).*srcset(\\s)*=(\\s)*(\"[^\"]*\"|'[^']*').*javascript(\\s)*:.*", "srcset javascript:", 7},

    // 17) DOM sinks / PoC JS
    {"(?i).*(document(\\s)*\\.(\\s)*cookie|document(\\s)*\\.(\\s)*location|window(\\s)*\\.(\\s)*location).*", "DOM sink", 5},
    {"(?i).*(alert(\\s)*\\(|prompt(\\s)*\\(|confirm(\\s)*\\().*", "Common PoC JS functions", 4},

    // 18) Event handler koji sadrži <script>
    {"(?i).*<[^>]+(\\s)(on[a-z]{2,})(\\s)*=(\\s)*(\"[^\"]*<(\\s)*script\\b|\'[^\']*<(\\s)*script\\b).*", "Event handler contains <script>", 9},

    {NULL, NULL, 0},
};


static int patterns_initialized = 0;
static int pattern_count = 0;

int init_xss_patterns() {
    if (patterns_initialized) {
        return 1;
    }
    
    pattern_count = 0;
    
    for (int i = 0; xss_raw_patterns[i].pattern != NULL; i++) {
        re2_pattern_t* regex = re2_compile(xss_raw_patterns[i].pattern);
        
        if (regex && re2_is_valid(regex)) {
            xss_compiled_patterns[pattern_count].compiled_regex = regex;
            xss_compiled_patterns[pattern_count].description = xss_raw_patterns[i].description;
            xss_compiled_patterns[pattern_count].severity = xss_raw_patterns[i].severity;
            pattern_count++;
        } else {
            fprintf(stderr, "Failed to compile pattern: %s\n", xss_raw_patterns[i].pattern);
            if (regex) re2_free(regex);
        }
    }
    
    patterns_initialized = 1;
    // printf("Initialized %d SQLi patterns\n", pattern_count);
    return 1;
}

void cleanup_xss_patterns() {
    if (!patterns_initialized) return;
    
    for (int i = 0; i < pattern_count; i++) {
        if (xss_compiled_patterns[i].compiled_regex) {
            re2_free(xss_compiled_patterns[i].compiled_regex);
            xss_compiled_patterns[i].compiled_regex = NULL;
        }
    }
    
    patterns_initialized = 0;
    pattern_count = 0;
}

severity_t detect_xss_optimized(const char *input) {
    if (!input || strlen(input) == 0) {
        return SEVERITY_NONE;
    }

    // printf("Analyzing: \"%s\"\n", input);
    int total_score = 0;
    int pattern_matches = 0;
    int max_severity = 0;

    if (!patterns_initialized) {
        init_xss_patterns();
    }

    for (int i = 0; i < pattern_count; i++) {
        int start, end;
   
        if (re2_find(xss_compiled_patterns[i].compiled_regex, input, &start, &end)) {
            pattern_matches++;
            total_score += xss_compiled_patterns[i].severity * 10;
            
            if (xss_compiled_patterns[i].severity > max_severity) {
                max_severity = xss_compiled_patterns[i].severity;
            }

            fprintf(stderr, "✓ MATCH: %s\n", xss_compiled_patterns[i].description);
        }
    }

    if (total_score >= 100) {
        return SEVERITY_HIGH;
    } else if (total_score >= 50) {
        return SEVERITY_MEDIUM;
    } else if (total_score > 0) {
        return SEVERITY_LOW;
    }

    // fprintf(stderr, "%s", input);
    return SEVERITY_NONE;
}