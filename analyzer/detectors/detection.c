#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "detection.h"
#include "html-decoder.h"


CompiledRegexPattern compiled_patterns[128];
RawRegexPattern raw_patterns[] = {
    // (?i) - case-insensitive
    // (\\s|%20|\\+)* - 0 or more space chars (\\s - space, %20 - encoded, + - in url)
    // d+ - one or more digits
    // . - any character
    // [] - character group -> [abc] - a or b or c -> [^'] -> every possible character beside '


    // ------------------------------------------ SQLi ------------------------------------------

    // === BOOLEAN INJECTIONS ===
    // Boolean with numbers - or 1=1, and 32=32
    {"(?i).*(\\s|%20|\\+)*(or|and)(\\s|%20|\\+)*\\d+(\\s|%20|\\+)*=(\\s|%20|\\+)*\\d+.*", "and/or n=n anywhere", 5, SQL_INJECTION},


    // Boolean with strings - or '1'='1'
    {"(?i).*(\\s|%20|\\+)*(or|and)(\\s|%20|\\+)*'[^']*'(\\s|%20|\\+)*=(\\s|%20|\\+)*'[^']*'.*", "OR/AND string compare (')", 4, SQL_INJECTION},
    {"(?i).*(\\s|%20|\\+)+(or|and)(\\s|%20|\\+)*\"[^\"]*\"(\\s|%20|\\+)*=(\\s|%20|\\+)*\"[^\"]*\".*", "OR/AND string compare (\")", 4, SQL_INJECTION},


    // === UNION-BASED ===
    {"(?i).*union(\\s|%20|\\+)+all(\\s|%20|\\+)+select.*", "UNION ALL SELECT", 5, SQL_INJECTION},
    {"(?i).*union(\\s|%20|\\+)+distinct(\\s|%20|\\+)+select.*", "UNION DISTINCT SELECT", 4, SQL_INJECTION},
    {"(?i).*['\"\\)]*(\\s|%20|\\+)*union(\\s|%20|\\+)*select.*", "Quoted/Paren UNION SELECT", 5, SQL_INJECTION},
    {"(?i).*(\\s|%20|\\+)*(union((%20|\\+)+|\\s+)select).*", "UNION SELECT (encoded spaces)", 5, SQL_INJECTION},

    // === TIME-BASED / BLIND ===
    {"(?i).*sleep(\\s|%20|\\+)*\\((\\s|%20|\\+)*\\d*(\\s|%20|\\+)*\\).*", "SLEEP()", 5, SQL_INJECTION},
    {"(?i).*waitfor(\\s|%20|\\+)+delay(\\s|%20|\\+)+['\"][^'\"]+['\"].*", "WAITFOR DELAY", 5, SQL_INJECTION},
    {"(?i).*pg_sleep(\\s|%20|\\+)*\\((\\s|%20|\\+)*\\d+(\\s|%20|\\+)*\\).*", "pg_sleep()", 5, SQL_INJECTION},
    {"(?i).*benchmark(\\s|%20|\\+)*\\((\\s|%20|\\+)*\\d+.*", "BENCHMARK()", 5, SQL_INJECTION},

    // === ERROR-BASED / CAST ===
    {"(?i).*extractvalue(\\s|%20|\\+)*\\(", "EXTRACTVALUE(", 5, SQL_INJECTION},
    {"(?i).*updatexml(\\s|%20|\\+)*\\(", "UPDATEXML(", 5, SQL_INJECTION},
    {"(?i).*cast(\\s|%20|\\+)*\\([^)]*\\s+as\\s+int\\s*\\)", "CAST(... AS INT)", 4, SQL_INJECTION},
    {"(?i).*convert(\\s|%20|\\+)*\\(\\s*int\\s*,", "CONVERT(int,...", 4, SQL_INJECTION},

    // === STACKED QUERIES ===
    {"(?i).*(;|%3b)(\\s|%20|\\+)*select.*", "Stacked SELECT", 5, SQL_INJECTION},
    {"(?i).*(;|%3b)(\\s|%20|\\+)*insert.*", "Stacked INSERT", 5, SQL_INJECTION},
    {"(?i).*(;|%3b)(\\s|%20|\\+)*update.*", "Stacked UPDATE", 5, SQL_INJECTION},
    {"(?i).*(;|%3b)(\\s|%20|\\+)*delete.*", "Stacked DELETE", 5, SQL_INJECTION},
    {"(?i).*(;|%3b)(\\s|%20|\\+)*drop.*", "Stacked DROP", 5, SQL_INJECTION},
    {"(?i).*(;|%3b)(\\s|%20|\\+)*create.*", "Stacked CREATE", 5, SQL_INJECTION},
    {"(?i).*(;|%3b)(\\s|%20|\\+)*exec(ute)?.*", "Stacked EXEC/EXECUTE", 5, SQL_INJECTION},

    // === KOMENTARI ===
    {".*(--|%2d%2d)[^\\r\\n]*", "SQL line comment --", 3, SQL_INJECTION},
    {".*(#|%23)[^\\r\\n]*", "MySQL hash comment #", 3, SQL_INJECTION},
    {".*/\\*.*?\\*/", "SQL block comment /* */", 3, SQL_INJECTION},
    {".*['\"](\\s)*(--|#|%23).*", "Quote + comment", 4, SQL_INJECTION},

    // === INFO-GATHERING ===
    {"(?i).*information_schema.*", "information_schema", 4, SQL_INJECTION},
    {"(?i).*information_schema(\\s|%20|\\+)*\\.tables.*", "information_schema.tables", 4, SQL_INJECTION},
    {"(?i).*information_schema(\\s|%20|\\+)*\\.columns.*", "information_schema.columns", 4, SQL_INJECTION},
    {"(?i).*mysql\\.user.*", "mysql.user", 5, SQL_INJECTION},
    {"(?i).*sys\\.tables.*", "sys.tables", 4, SQL_INJECTION},
    {"(?i).*(pg_tables|pg_catalog).*", "PostgreSQL catalogs", 4, SQL_INJECTION},

    // === FUNKCIJE / FILE IO ===
    {"(?i).*concat\\(", "CONCAT(", 3, SQL_INJECTION},
    {"(?i).*group_concat\\(", "GROUP_CONCAT(", 3, SQL_INJECTION},
    {"(?i).*string_agg\\(", "STRING_AGG(", 3, SQL_INJECTION},
    {"(?i).*load_file\\(", "LOAD_FILE(", 5, SQL_INJECTION},
    {"(?i).*into(\\s|%20|\\+)+outfile.*", "INTO OUTFILE", 5, SQL_INJECTION},
    {"(?i).*into(\\s|%20|\\+)+dumpfile.*", "INTO DUMPFILE", 5, SQL_INJECTION},

    // === ENKODING / OBFUSKACIJA ===
    {".*0x[0-9A-Fa-f]+.*", "Hex literal 0x...", 3, SQL_INJECTION},
    {".*%25[0-9A-Fa-f]{2}.*", "Double URL-encoding (%25XX)", 3, SQL_INJECTION},

    // === NoSQL (osnovno) ===
    {".*\\$(where|ne|gt|lt|regex|in|nin).*", "MongoDB operators in input", 3, SQL_INJECTION},


    // -------------------------------------- XSS ---------------------------------------------------------------


     // 1) <script> tag (svi case-ovi, sa ili bez closing /)
    {"(?i).*<(\\s)*script>.*", "Opening <script> tag present", 10, XSS},
    {"(?i).*<(\\s)*/\\s*script>.*", "Closing </script> tag present", 10, XSS},

    // 2) Inline event handler (onclick, onerror, onload, etc.)
    {"(?i).*<[^>]+(\\s)(on[a-z]{2,})(\\s)*=(\\s)*(\"[^\"]*\"|'[^']*'|[^(\\s)>]+).*", "Inline event handler attribute", 9, XSS},

    // 3) javascript: URI
    {"(?i).*(href|src|xlink:href|formaction|data|action)(\\s)*=(\\s)*(\"|'|)?(\\s)*javascript(\\s)*:.*", "javascript: URI in attribute", 10, XSS},

    // 4) vbscript: URI
    {"(?i).*(href|src|xlink:href|formaction)(\\s)*=(\\s)*(\"|'|)?(\\s)*vbscript(\\s)*:.*", "vbscript: URI in attribute", 8, XSS},

    // 5) data: URI with HTML/SVG/XML content
    {"(?i).*(href|src|xlink:href|formaction|srcset)(\\s)*=(\\s)*(\"[^\"]*\"|'[^']*'|[^(\\s)>]+)?(\\s)*data(\\s)*:(text/html|image/svg\\+xml|application/xml|application/xhtml\\+xml).*", "data: URI in attribute", 9, XSS},

    // 6) <img> with onerror/onload or src=javascript/data
    {"(?i).*<(\\s)*img\\b[^>]*\\b(onerror|onload)(\\s)*=(\\s)*(\"[^\"]*\"|'[^']*'|[^(\\s)>]+).*", "IMG with event handler", 9, XSS},
    {"(?i).*<(\\s)*img\\b[^>]*\\bsrc(\\s)*=(\\s)*(\"|'|)?(\\s)*(javascript(\\s)*:|data(\\s)*:).*", "IMG src javascript:/data:", 9, XSS},

    // 7) SVG elements or event handlers
    {"(?i).*<(\\s)*svg\\b[^>]*(\\s)on[a-z]{2,}(\\s)*=(\\s)*(\"[^\"]*\"|'[^']*'|[^(\\s)>]+).*", "SVG with event handler", 9, XSS},
    {"(?i).*<(\\s)*(svg|animate|set|foreignObject).*", "Potentially dangerous SVG element", 8, XSS},

    // 8) MathML/XML
    {"(?i).*<(\\s)*(math|xml).*", "MathML/XML container", 7, XSS},

    // 9) iframe/object/embed/applet
    {"(?i).*<(\\s)*(iframe|object|embed|applet).*", "Active content tag", 8, XSS},
    {"(?i).*<(\\s)*iframe\\b[^>]*\\bsrcdoc(\\s)*=.*", "Iframe with srcdoc", 9, XSS},

    // 10) meta refresh with javascript
    {"(?i).*<(\\s)*meta\\b[^>]*http-equiv(\\s)*=(\\s)*(\"refresh\"|'refresh'|refresh)[^>]*content(\\s)*=(\\s)*\"[^\"]*javascript(\\s)*:.*", "Meta refresh javascript (double quotes)", 8, XSS},
    {"(?i).*<(\\s)*meta\\b[^>]*http-equiv(\\s)*=(\\s)*(\"refresh\"|'refresh'|refresh)[^>]*content(\\s)*=(\\s)*'[^']*javascript(\\s)*:.*", "Meta refresh javascript (single quotes)", 8, XSS},
    {"(?i).*<(\\s)*meta\\b[^>]*http-equiv(\\s)*=(\\s)*(\"refresh\"|'refresh'|refresh)[^>]*content(\\s)*=[^(\\s)>]*javascript(\\s)*:.*", "Meta refresh javascript (no quotes)", 8, XSS},

    // 11) <base> href
    {"(?i).*<(\\s)*base\\b[^>]*href(\\s)*=.*", "Base href present", 5, XSS},

    // 12) CSS expression() in style
    {"(?i).*style(\\s)*=(\\s)*(\"[^\"]*\"|'[^']*'|[^(\\s)>]+).*expression(\\s)*\\(.*", "CSS expression() in style", 8, XSS},

    // 13) CSS url(javascript:)
    {"(?i).*style(\\s)*=(\\s)*(\"[^\"]*\"|'[^']*'|[^(\\s)>]+).*url(\\s)*\\((\\s)*javascript(\\s)*:.*", "CSS url(javascript:)", 9, XSS},

    // 14) -moz-binding
    {"(?i).*style(\\s)*=(\\s)*(\"[^\"]*\"|'[^']*'|[^(\\s)>]+).*\\-moz-binding(\\s)*:(\\s)*url(\\s)*\\(.*", "CSS -moz-binding", 7, XSS},

    // 15) formaction/javascript
    {"(?i).*formaction(\\s)*=(\\s)*(\"|'|)?(\\s)*javascript(\\s)*:.*", "formaction=javascript:", 8, XSS},

    // 16) srcset/javascript
    {"(?i).*srcset(\\s)*=(\\s)*(\"[^\"]*\"|'[^']*').*javascript(\\s)*:.*", "srcset javascript:", 7, XSS},

    // 17) DOM sinks / PoC JS
    {"(?i).*(document(\\s)*\\.(\\s)*cookie|document(\\s)*\\.(\\s)*location|window(\\s)*\\.(\\s)*location).*", "DOM sink", 5, XSS},
    {"(?i).*(alert(\\s)*\\(|prompt(\\s)*\\(|confirm(\\s)*\\().*", "Common PoC JS functions", 4, XSS},

    // 18) Event handler koji sadrži <script>
    {"(?i).*<[^>]+(\\s)(on[a-z]{2,})(\\s)*=(\\s)*(\"[^\"]*<(\\s)*script\\b|\'[^\']*<(\\s)*script\\b).*", "Event handler contains <script>", 9, XSS},


    // --------------------------- DIRECTORY TRAVERSAL -----------------------------

    {"(?i).*(\\.|%2e){2}(\\/|%2f|\\\\|%5c).*", "directory traversal attempt (../)", 5, DIRECTORY_TRAVERSAL},

    {"(?i).*(\\.|%2e){2}(\\\\|%5c).*", "directory traversal attempt (..\\)", 5, DIRECTORY_TRAVERSAL},

    // --------------------------- COMMAND INJECTION -----------------------------

    // Common commands
    {"(?i).*(\\s|^|;|%3b)(cat|ls|dir|whoami|id|uname|pwd|ps|netstat|ping|curl|wget)(\\s|$|;|%3b|\\||%7c|&|%26).*", "System command", 8, COMMAND_INJECTION},

    // Windows commands  
    {"(?i).*(\\s|^|;|%3b)(cmd|powershell|net|systeminfo|tasklist|ipconfig)(\\s|$|;|%3b|\\||%7c|&|%26).*", "Windows command", 8, COMMAND_INJECTION},

    // === END ===
    {NULL, NULL, 0}
};

static int patterns_initialized = 0;
static int pattern_count = 0;


int init_regex_patterns() {
    if (patterns_initialized) {
        return 1;
    }
    
    pattern_count = 0;
    
    for (int i = 0; raw_patterns[i].pattern != NULL; i++) {
        re2_pattern_t* regex = re2_compile(raw_patterns[i].pattern);
        
        if (regex && re2_is_valid(regex)) {
            compiled_patterns[pattern_count].compiled_regex = regex;
            compiled_patterns[pattern_count].description = raw_patterns[i].description;
            compiled_patterns[pattern_count].attack = raw_patterns[i].attack;
            compiled_patterns[pattern_count].severity = raw_patterns[i].severity;
            pattern_count++;
        } else {
            fprintf(stderr, "Failed to compile pattern: %s\n", raw_patterns[i].pattern);
            if (regex) re2_free(regex);
        }
    }
    
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
    }
    
    patterns_initialized = 0;
    pattern_count = 0;
}

void analyze(const char *input, http_request_part location, findings_t *findings) {
    
    if (!input || strlen(input) == 0) {
        return;
    }
    
    // printf("Analyzing: \"%s\"\n", input);

    if (!patterns_initialized) {
        init_regex_patterns();
    }

    for (int i = 0; i < pattern_count; i++) {
        int start, end;
   
        if (re2_find(compiled_patterns[i].compiled_regex, input, &start, &end)) {

            findings->items = realloc(findings->items, (findings->count + 1) * sizeof(finding_t));

            findings->items[findings->count++] = (finding_t){
                .attack = compiled_patterns[i].attack,
                .description = compiled_patterns[i].description,
                .location = location,
            };

            fprintf(stderr, "✓ MATCH: %s\n", compiled_patterns[i].description);
        }
    }
}
