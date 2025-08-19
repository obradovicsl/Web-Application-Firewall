#ifndef XSS_DETECTION
#define XSS_DETECTION

#include "models.h"


severity_t check_xss(const char *input, http_request_part location);

// XSS payloads
static const char* xss_patterns[] = {
    // Script and event handlers
    "<script", "</script>", "javascript:", "vbscript:", "livescript:",
    "onload=", "onerror=", "onclick=", "onmouseover=", "onfocus=", "onblur=",
    "onchange=", "onsubmit=", "onreset=", "onkeydown=", "onkeyup=", "onkeypress=",
    "onmouseenter=", "onmouseleave=", "ondblclick=", "oncontextmenu=",
    
    // JS functions
    "document.cookie", "document.write", "document.domain", "document.location",
    "window.location", "window.open", "window.parent", "window.top",
    "eval(", "settimeout(", "setinterval(", "function(", "alert(", "prompt(", "confirm(",
    
    // HTML tags
    "<iframe", "<object", "<embed", "<applet", "<meta", "<link", "<svg", "<math",
    "<style", "<base", "<body", "<video", "<audio", "<source", "<track",
    
    // CSS/JS injection
    "expression(", "style=", "background:", "srcdoc=", "data:text/html",
    
    "<img", "<input", "<textarea", "<button", "<form", "<marquee", "<isindex",
    NULL
};


#endif