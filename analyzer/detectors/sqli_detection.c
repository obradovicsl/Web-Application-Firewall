#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "sqli_detection.h"
#include "html-decoder.h"


// ---------------------------- REGEX ------------------------------------------
CompiledRegexPattern sqli_compiled_patterns[64];
RawRegexPattern sqli_raw_patterns[] = {
    // (?i) - case-insensitive
    // (\\s|%20|\\+)* - 0 or more space chars (\\s - space, %20 - encoded, + - in url)
    // d+ - one or more digits
    // . - any character
    // [] - character group -> [abc] - a or b or c -> [^'] -> every possible character beside '

    // === BOOLEAN INJECTIONS ===
    // Boolean with numbers - or 1=1, and 32=32
    {"(?i).*(\\s|%20|\\+)*(or|and)(\\s|%20|\\+)*\\d+(\\s|%20|\\+)*=(\\s|%20|\\+)*\\d+.*", "and/or n=n anywhere", 5},


    // Boolean with strings - or '1'='1'
    {"(?i).*(\\s|%20|\\+)*(or|and)(\\s|%20|\\+)*'[^']*'(\\s|%20|\\+)*=(\\s|%20|\\+)*'[^']*'.*", "OR/AND string compare (')", 4},
    {"(?i).*(\\s|%20|\\+)+(or|and)(\\s|%20|\\+)*\"[^\"]*\"(\\s|%20|\\+)*=(\\s|%20|\\+)*\"[^\"]*\".*", "OR/AND string compare (\")", 4},


    // === UNION-BASED ===
    {"(?i).*union(\\s|%20|\\+)+all(\\s|%20|\\+)+select.*", "UNION ALL SELECT", 5},
    {"(?i).*union(\\s|%20|\\+)+distinct(\\s|%20|\\+)+select.*", "UNION DISTINCT SELECT", 4},
    {"(?i).*['\"\\)]*(\\s|%20|\\+)*union(\\s|%20|\\+)*select.*", "Quoted/Paren UNION SELECT", 5},
    {"(?i).*(\\s|%20|\\+)*(union((%20|\\+)+|\\s+)select).*", "UNION SELECT (encoded spaces)", 5},

    // === TIME-BASED / BLIND ===
    {"(?i).*sleep(\\s|%20|\\+)*\\((\\s|%20|\\+)*\\d*(\\s|%20|\\+)*\\).*", "SLEEP()", 5},
    {"(?i).*waitfor(\\s|%20|\\+)+delay(\\s|%20|\\+)+['\"][^'\"]+['\"].*", "WAITFOR DELAY", 5},
    {"(?i).*pg_sleep(\\s|%20|\\+)*\\((\\s|%20|\\+)*\\d+(\\s|%20|\\+)*\\).*", "pg_sleep()", 5},
    {"(?i).*benchmark(\\s|%20|\\+)*\\((\\s|%20|\\+)*\\d+.*", "BENCHMARK()", 5},

    // === ERROR-BASED / CAST ===
    {"(?i).*extractvalue(\\s|%20|\\+)*\\(", "EXTRACTVALUE(", 5},
    {"(?i).*updatexml(\\s|%20|\\+)*\\(", "UPDATEXML(", 5},
    {"(?i).*cast(\\s|%20|\\+)*\\([^)]*\\s+as\\s+int\\s*\\)", "CAST(... AS INT)", 4},
    {"(?i).*convert(\\s|%20|\\+)*\\(\\s*int\\s*,", "CONVERT(int,...", 4},

    // === STACKED QUERIES ===
    {"(?i).*(;|%3b)(\\s|%20|\\+)*select.*", "Stacked SELECT", 5},
    {"(?i).*(;|%3b)(\\s|%20|\\+)*insert.*", "Stacked INSERT", 5},
    {"(?i).*(;|%3b)(\\s|%20|\\+)*update.*", "Stacked UPDATE", 5},
    {"(?i).*(;|%3b)(\\s|%20|\\+)*delete.*", "Stacked DELETE", 5},
    {"(?i).*(;|%3b)(\\s|%20|\\+)*drop.*", "Stacked DROP", 5},
    {"(?i).*(;|%3b)(\\s|%20|\\+)*create.*", "Stacked CREATE", 5},
    {"(?i).*(;|%3b)(\\s|%20|\\+)*exec(ute)?.*", "Stacked EXEC/EXECUTE", 5},

    // === KOMENTARI ===
    {".*(--|%2d%2d)[^\\r\\n]*", "SQL line comment --", 3},
    {".*(#|%23)[^\\r\\n]*", "MySQL hash comment #", 3},
    {".*/\\*.*?\\*/", "SQL block comment /* */", 3},
    {".*['\"](\\s)*(--|#|%23).*", "Quote + comment", 4},

    // === INFO-GATHERING ===
    {"(?i).*information_schema.*", "information_schema", 4},
    {"(?i).*information_schema(\\s|%20|\\+)*\\.tables.*", "information_schema.tables", 4},
    {"(?i).*information_schema(\\s|%20|\\+)*\\.columns.*", "information_schema.columns", 4},
    {"(?i).*mysql\\.user.*", "mysql.user", 5},
    {"(?i).*sys\\.tables.*", "sys.tables", 4},
    {"(?i).*(pg_tables|pg_catalog).*", "PostgreSQL catalogs", 4},

    // === FUNKCIJE / FILE IO ===
    {"(?i).*concat\\(", "CONCAT(", 3},
    {"(?i).*group_concat\\(", "GROUP_CONCAT(", 3},
    {"(?i).*string_agg\\(", "STRING_AGG(", 3},
    {"(?i).*load_file\\(", "LOAD_FILE(", 5},
    {"(?i).*into(\\s|%20|\\+)+outfile.*", "INTO OUTFILE", 5},
    {"(?i).*into(\\s|%20|\\+)+dumpfile.*", "INTO DUMPFILE", 5},

    // === ENKODING / OBFUSKACIJA ===
    {".*0x[0-9A-Fa-f]+.*", "Hex literal 0x...", 3},
    {".*%25[0-9A-Fa-f]{2}.*", "Double URL-encoding (%25XX)", 3},

    // === NoSQL (osnovno) ===
    {".*\\$(where|ne|gt|lt|regex|in|nin).*", "MongoDB operators in input", 3},

    // === END ===
    {NULL, NULL, 0}
};

static int patterns_initialized = 0;
static int pattern_count = 0;


int init_sqli_patterns() {
    if (patterns_initialized) {
        return 1;
    }
    
    pattern_count = 0;
    
    for (int i = 0; sqli_raw_patterns[i].pattern != NULL; i++) {
        re2_pattern_t* regex = re2_compile(sqli_raw_patterns[i].pattern);
        
        if (regex && re2_is_valid(regex)) {
            sqli_compiled_patterns[pattern_count].compiled_regex = regex;
            sqli_compiled_patterns[pattern_count].description = sqli_raw_patterns[i].description;
            sqli_compiled_patterns[pattern_count].severity = sqli_raw_patterns[i].severity;
            pattern_count++;
        } else {
            fprintf(stderr, "Failed to compile pattern: %s\n", sqli_raw_patterns[i].pattern);
            if (regex) re2_free(regex);
        }
    }
    
    patterns_initialized = 1;
    // printf("Initialized %d SQLi patterns\n", pattern_count);
    return 1;
}

void cleanup_sqli_patterns() {
    if (!patterns_initialized) return;
    
    for (int i = 0; i < pattern_count; i++) {
        if (sqli_compiled_patterns[i].compiled_regex) {
            re2_free(sqli_compiled_patterns[i].compiled_regex);
            sqli_compiled_patterns[i].compiled_regex = NULL;
        }
    }
    
    patterns_initialized = 0;
    pattern_count = 0;
}

severity_t detect_sqli_optimized(const char *input) {
    
    if (!input || strlen(input) == 0) {
        return SEVERITY_NONE;
    }
    
    // printf("Analyzing: \"%s\"\n", input);
    int total_score = 0;
    int pattern_matches = 0;
    int max_severity = 0;

    if (!patterns_initialized) {
        init_sqli_patterns();
    }

    for (int i = 0; i < pattern_count; i++) {
        int start, end;
   
        if (re2_find(sqli_compiled_patterns[i].compiled_regex, input, &start, &end)) {
            pattern_matches++;
            total_score += sqli_compiled_patterns[i].severity * 10;
            
            if (sqli_compiled_patterns[i].severity > max_severity) {
                max_severity = sqli_compiled_patterns[i].severity;
            }

            fprintf(stderr, "✓ MATCH: %s\n", sqli_compiled_patterns[i].description);
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
