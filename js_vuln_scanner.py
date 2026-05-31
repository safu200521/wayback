#!/usr/bin/env python3
"""
JS Vulnerability Scanner v1 - Sinks, Sources & Dangerous Patterns
Inspired by: https://kpwn.de/blog/javascript-analysis-for-pentesters/
             https://portswigger.net/research/server-side-prototype-pollution
             https://portswigger.net/web-security/dom-based

Scans JavaScript files for security-relevant patterns:
- DOM XSS sinks & sources
- Prototype pollution gadgets
- Open redirect patterns
- Insecure postMessage usage
- Dangerous eval patterns
- CORS misconfigurations
- JSONP callback abuse
- Template injection (client-side)
- Insecure storage of secrets
- Unsafe URL handling
- Information disclosure
- Insecure crypto usage
- Supply chain / dynamic script loading

Each finding includes severity, exploitation guide, and remediation.

Usage:
    python js_vuln_scanner.py --js-dir js_files/
    python js_vuln_scanner.py --urls js_urls.txt
    python js_vuln_scanner.py --js-dir js_files/ --urls js.txt -o report.html -v
"""

import os
import re
import sys
import argparse
import time
from datetime import datetime
from html import escape as html_escape
from urllib.parse import urlparse

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


# ============================================================
# VULNERABILITY PATTERNS
# ============================================================

# Format: (name, regex, severity, category, description, how_to_test, remediation, bounty_worthy)

VULN_PATTERNS_RAW = [
    # ================================================================
    # DOM XSS SINKS (Critical/High)
    # Properties and methods that render/execute content
    # ================================================================
    ("innerHTML Assignment",
     r'\.(innerHTML|outerHTML)\s*[+]?=(?!=)\s*[^;]{1,200}',
     "critical", "DOM XSS Sink",
     "innerHTML/outerHTML assignment detected. If attacker-controlled data flows here, it leads to DOM XSS.",
     "1. Trace the value being assigned — does it come from URL params, hash, referrer, postMessage?\n"
     "2. Try injecting: <img src=x onerror=alert(1)> via the source\n"
     "3. Check if any sanitization (DOMPurify) is applied before assignment\n"
     "4. Test in browser with DOM Invader (Burp) or manual payload",
     "Use textContent instead of innerHTML for text. If HTML is needed, sanitize with DOMPurify.sanitize() before assignment.",
     True),

    ("document.write()",
     r'document\.write(?:ln)?\s*\([^)]{0,300}',
     "critical", "DOM XSS Sink",
     "document.write() executes HTML/JS. If user input reaches it, DOM XSS is guaranteed.",
     "1. Check what's passed to document.write()\n"
     "2. Trace if location.search, location.hash, referrer, or postMessage data flows in\n"
     "3. Payload: <script>alert(document.domain)</script> via the source\n"
     "4. Even partial control (inside an attribute) can be exploited",
     "Avoid document.write entirely. Use DOM APIs (createElement, appendChild) instead.",
     True),

    ("eval() Call",
     r'\beval\s*\(\s*[^)]{1,300}',
     "critical", "Dangerous Eval",
     "eval() executes arbitrary JavaScript. If any user input reaches eval(), it is RCE in the browser context.",
     "1. Trace the argument — where does the evaluated string come from?\n"
     "2. Check if URL parameters, hash, cookies, or API responses feed into it\n"
     "3. Try: eval('alert(1)') equivalent via the input source\n"
     "4. Even indirect eval (window['eval']) counts",
     "Never use eval(). Use JSON.parse() for JSON data. Refactor to avoid dynamic code execution.",
     True),

    ("new Function() Constructor",
     r'new\s+Function\s*\([^)]{0,300}',
     "critical", "Dangerous Eval",
     "new Function() is equivalent to eval(). Creates a function from a string, enabling code injection.",
     "1. Check what string is passed to Function()\n"
     "2. If user-controlled data is concatenated into the string, it's exploitable\n"
     "3. Test by injecting: }); alert(1); // via the source",
     "Avoid new Function(). Use named functions or arrow functions instead.",
     True),

    ("setTimeout/setInterval with String",
     r'(?:setTimeout|setInterval)\s*\(\s*(?:(?![\w$]\s*(?:=>|\()))[\'"`]',
     "high", "Dangerous Eval",
     "setTimeout/setInterval with a string argument acts like eval(). Executes the string as code.",
     "1. Check if a string (not function reference) is passed as first argument\n"
     "2. If the string contains user input, it's DOM XSS\n"
     "3. Payload via source: ');alert(1)//",
     "Always pass a function reference to setTimeout/setInterval, never a string.",
     True),

    ("jQuery .html() Sink",
     r'\$\([^)]*\)\s*\.\s*html\s*\([^)]{1,200}',
     "high", "DOM XSS Sink",
     "jQuery .html() method sets innerHTML. User-controlled input leads to DOM XSS.",
     "1. Trace what's passed to .html()\n"
     "2. Check for concatenation with URL params, hash, user data\n"
     "3. Payload: <img src=x onerror=alert(1)>\n"
     "4. Also check .append(), .prepend(), .after(), .before(), .replaceWith()",
     "Use .text() instead of .html() for text content. Sanitize HTML input with DOMPurify before .html().",
     True),

    ("jQuery DOM Manipulation Sinks",
     r'\$\([^)]*\)\s*\.\s*(?:append|prepend|after|before|replaceWith|wrap|wrapAll|wrapInner)\s*\([^)]{1,200}',
     "high", "DOM XSS Sink",
     "jQuery DOM manipulation method that can inject HTML. XSS if user-controlled data is passed.",
     "1. Trace the argument — does user input flow in?\n"
     "2. These methods accept HTML strings, not just text\n"
     "3. Test: $('body').append(userInput) with <img onerror=alert(1)>",
     "Sanitize all user input before passing to jQuery DOM methods. Use .text() or DOMPurify.",
     True),

    ("jQuery Constructor with HTML",
     r'\$\s*\(\s*[\'"`][^\'"`]*<[^)]{0,200}',
     "high", "DOM XSS Sink",
     "jQuery $() with HTML string creates DOM elements. If user input is in the string, DOM XSS occurs.",
     "1. Check if the HTML string inside $() contains user-controlled values\n"
     "2. $('<div>' + userInput + '</div>') is vulnerable\n"
     "3. Even partial injection in attributes is exploitable",
     "Never pass user input to jQuery $(). Create elements with $('<div>') then set content with .text().",
     True),

    # ================================================================
    # DOM XSS SOURCES
    # Where user input enters the application
    # ================================================================
    ("location.hash Source",
     r'(?:window\.)?location\.hash',
     "high", "DOM XSS Source",
     "location.hash is a DOM XSS source. Value after # is user-controlled and never sent to server.",
     "1. This is a SOURCE — trace where this value flows TO (sinks)\n"
     "2. Check if it reaches innerHTML, eval, document.write, jQuery.html()\n"
     "3. Craft URL: https://target.com/page#<img src=x onerror=alert(1)>\n"
     "4. Hash-based XSS bypasses many WAFs since # isn't sent to server",
     "Always sanitize location.hash before using in DOM operations. Validate against allowlist.",
     True),

    ("location.search Source",
     r'(?:window\.)?location\.(?:search|href)',
     "high", "DOM XSS Source",
     "location.search/href contains user-controlled query parameters. Classic DOM XSS source.",
     "1. Trace where this value is used — does it reach a sink?\n"
     "2. Check URL parameter parsing code for injection points\n"
     "3. Test: ?param=<script>alert(1)</script> or ?param=javascript:alert(1)\n"
     "4. Use DOM Invader to auto-trace source-to-sink flows",
     "Parse URL parameters safely. Validate and sanitize before DOM insertion. Use URLSearchParams API.",
     True),

    ("document.referrer Source",
     r'document\.referrer',
     "medium", "DOM XSS Source",
     "document.referrer is attacker-controllable (by linking from attacker's page). DOM XSS source.",
     "1. Trace where referrer value is used\n"
     "2. Create page on attacker domain that links to the target\n"
     "3. The referrer URL can contain XSS payloads in query/fragment",
     "Validate document.referrer against expected origins before any DOM use.",
     True),

    ("window.name Source",
     r'window\.name',
     "medium", "DOM XSS Source",
     "window.name persists across navigations and is attacker-controllable. Powerful XSS source.",
     "1. Attacker sets window.name on their page, then redirects to target\n"
     "2. window.name retains the value across the navigation\n"
     "3. If target uses window.name in a sink → XSS\n"
     "4. window.open('target', '<img onerror=alert(1)>')",
     "Never trust window.name. Always validate/sanitize before use.",
     True),

    ("document.cookie Source",
     r'document\.cookie(?!\s*=)',
     "low", "DOM XSS Source",
     "Reading document.cookie. If cookie values are user-controllable (via injection) and flow to sinks, DOM XSS.",
     "1. Check if cookie values are used in innerHTML, eval, or other sinks\n"
     "2. If cookies can be set via CRLF injection or subdomain, this becomes exploitable",
     "Don't use cookie values in DOM rendering. If needed, sanitize first.",
     False),

    ("URL Parameter Extraction",
     r'(?:URLSearchParams|getParameter|get\([\'"]\w+[\'"]\)|searchParams\.get|url\.searchParams|location\.search\.(?:split|match|replace|substring))',
     "medium", "DOM XSS Source",
     "URL parameter extraction detected. If the extracted value flows to a sink, DOM XSS.",
     "1. Trace the extracted parameter value through the code\n"
     "2. Check if it reaches innerHTML, eval, document.write, jQuery methods\n"
     "3. Test each URL parameter with XSS payloads",
     "Validate and sanitize all URL parameters before use in DOM operations.",
     True),

    # ================================================================
    # PROTOTYPE POLLUTION
    # ================================================================
    ("__proto__ Access",
     r'__proto__',
     "critical", "Prototype Pollution",
     "__proto__ reference found. If user input can set __proto__ properties via merge/assign, prototype pollution occurs.",
     "1. Check if __proto__ appears in a merge/deep-copy/extend function\n"
     "2. Test: {\"__proto__\": {\"polluted\": true}} in JSON body\n"
     "3. Verify: check if ({}).polluted === true after the request\n"
     "4. Server-side: use json spaces, exposed headers, or status techniques (PortSwigger)\n"
     "5. Client-side: check Object.prototype for unexpected properties",
     "Sanitize keys before merge: reject __proto__, constructor, prototype. Use Object.create(null) or Map.",
     True),

    ("constructor.prototype Access",
     r'constructor\s*(?:\[\s*[\'"]prototype[\'"]\s*\]|\.\s*prototype)',
     "critical", "Prototype Pollution",
     "constructor.prototype access. Alternative prototype pollution vector that bypasses __proto__ filters.",
     "1. Test: {\"constructor\": {\"prototype\": {\"polluted\": true}}}\n"
     "2. This bypasses __proto__ blocklists\n"
     "3. Check if merged/assigned into objects without key sanitization",
     "Block constructor and prototype keys in merge operations. Use Object.create(null).",
     True),

    ("Recursive/Deep Merge Function",
     r'(?:function\s+)?(?:deepMerge|deepExtend|deepCopy|recursiveMerge|mergeDeep|merge|extend|assign|defaults)\s*(?:=\s*(?:function)?|\()',
     "high", "Prototype Pollution",
     "Recursive/deep merge function detected. These are the #1 cause of prototype pollution vulnerabilities.",
     "1. Review the merge function — does it check for __proto__ / constructor keys?\n"
     "2. If it recursively sets properties from untrusted input → vulnerable\n"
     "3. Test by passing {\"__proto__\": {\"test\": 1}} and checking ({}).test\n"
     "4. Known vulnerable: lodash.merge (old), jQuery.extend (deep), hoek.merge",
     "Add key filtering: skip __proto__, constructor, prototype. Better: use Map/Set or Object.create(null).",
     True),

    ("Lodash merge/extend (vulnerable)",
     r'_\.(?:merge|defaultsDeep|mergeWith|set|setWith)\s*\(',
     "high", "Prototype Pollution",
     "Lodash merge/set function. Older versions are vulnerable to prototype pollution.",
     "1. Check Lodash version — < 4.17.12 is vulnerable\n"
     "2. Test: _.merge({}, JSON.parse('{\"__proto__\": {\"polluted\": true}}'))\n"
     "3. For _.set: _.set({}, '__proto__.polluted', true)",
     "Update Lodash to latest. Use _.merge with sanitized input or switch to structuredClone().",
     True),

    ("jQuery.extend (deep copy)",
     r'\$\.extend\s*\(\s*true',
     "high", "Prototype Pollution",
     "jQuery.extend with deep=true flag. Older jQuery versions are vulnerable to prototype pollution.",
     "1. Deep extend copies nested objects recursively\n"
     "2. Test: $.extend(true, {}, JSON.parse('{\"__proto__\": {\"xss\": true}}'))\n"
     "3. jQuery < 3.4.0 is vulnerable",
     "Update jQuery to ≥3.4.0. Avoid deep extend with untrusted data.",
     True),

    ("Object.assign with spread",
     r'Object\.assign\s*\(\s*[^,]+,\s*(?:req\.body|req\.query|req\.params|JSON\.parse|input|data|params|args|options|config)',
     "medium", "Prototype Pollution",
     "Object.assign with potentially untrusted source. While Object.assign is shallow, it can still overwrite properties.",
     "1. Check if the source object is user-controlled\n"
     "2. Shallow assign doesn't set __proto__ but can overwrite other sensitive properties\n"
     "3. Combined with other vulns, can be chained",
     "Validate/filter keys from untrusted objects before Object.assign().",
     False),

    # ================================================================
    # OPEN REDIRECT
    # ================================================================
    ("window.location Assignment",
     r'(?:window|document)\.location(?:\.href)?\s*=\s*(?![\'\"](https?://[^\s]*)?[\'\"]\s*;)',
     "high", "Open Redirect",
     "Dynamic location assignment. If user input controls the URL, open redirect or javascript: XSS.",
     "1. Trace the assigned value — is it user-controlled?\n"
     "2. Test with: ?url=https://evil.com or ?url=javascript:alert(1)\n"
     "3. For javascript: protocol, this becomes XSS, not just redirect\n"
     "4. Bypasses: //evil.com, /\\evil.com, https://target.com@evil.com",
     "Validate redirect URLs against an allowlist of absolute paths. Block javascript: and data: protocols.",
     True),

    ("location.assign()/replace()",
     r'(?:window\.)?location\.(?:assign|replace)\s*\([^)]{1,200}',
     "high", "Open Redirect",
     "location.assign/replace called with potentially user-controlled URL.",
     "1. Check if the argument comes from user input\n"
     "2. location.replace() won't leave history entry — stealthier\n"
     "3. Test: ?redirect=javascript:alert(1)\n"
     "4. Check for ?next=, ?url=, ?redirect=, ?return= parameters",
     "Validate URL against allowlist. Use relative paths only. Block javascript:/data: protocols.",
     True),

    ("window.open()",
     r'window\.open\s*\([^)]{1,200}',
     "medium", "Open Redirect",
     "window.open() with potentially user-controlled URL.",
     "1. Check if the first argument is user-controlled\n"
     "2. If so: redirect, XSS via javascript: protocol\n"
     "3. Also check window.opener — reverse tabnapping possible if target=_blank",
     "Validate URL in first arg. Set rel=\"noopener noreferrer\" for links.",
     True),

    # ================================================================
    # INSECURE postMessage
    # ================================================================
    ("postMessage Listener (no origin check)",
     r'addEventListener\s*\(\s*[\'"]message[\'"]\s*,\s*function\s*\([^)]*\)\s*\{(?:(?!origin).){0,500}\}',
     "high", "Insecure postMessage",
     "Message event listener without origin validation. Attacker can send messages from any origin.",
     "1. Check if event.origin or e.origin is validated BEFORE using event.data\n"
     "2. If no origin check: create attacker page with iframe pointing to target\n"
     "3. Use postMessage to send malicious data from attacker page\n"
     "4. If event.data flows to innerHTML/eval → XSS",
     "Always validate event.origin against expected origins before processing event.data.",
     True),

    ("postMessage with Wildcard Origin",
     r'\.postMessage\s*\([^)]*[\'"]\*[\'"]\s*\)',
     "high", "Insecure postMessage",
     "postMessage sent to wildcard origin '*'. Any page can receive this message.",
     "1. The message can be intercepted by any iframe/opener\n"
     "2. If sensitive data is in the message (tokens, user data) → leak\n"
     "3. Create attacker page that listens for messages from target",
     "Replace '*' with specific trusted origin in postMessage calls.",
     True),

    ("postMessage Event Handler",
     r'(?:on|add[Ee]vent[Ll]istener).*[\'"]message[\'"]',
     "medium", "Insecure postMessage",
     "Message event handler detected. Review for origin validation and safe data handling.",
     "1. Check if origin is validated before data is used\n"
     "2. Check what happens with event.data — does it reach a sink?\n"
     "3. postMessage is one of the most common DOM XSS vectors",
     "Validate event.origin strictly. Sanitize event.data before DOM operations.",
     True),

    # ================================================================
    # CORS MISCONFIGURATION (client-side indicators)
    # ================================================================
    ("CORS Wildcard Origin",
     r'[\'"]Access-Control-Allow-Origin[\'"]\s*[,:=]\s*[\'"]\*[\'"]',
     "high", "CORS Misconfiguration",
     "CORS header set to wildcard (*). Any origin can read responses.",
     "1. Check if credentials (cookies) are also allowed\n"
     "2. Wildcard + credentials is blocked by browsers, but wildcard alone leaks public data\n"
     "3. Create attacker page with fetch() to read target's responses",
     "Set specific trusted origins instead of *. Never combine * with credentials.",
     True),

    ("Dynamic Origin Reflection",
     r'(?:req\.headers?\.origin|request\.headers?\[?[\'"]origin[\'"]|origin\s*=\s*req)',
     "high", "CORS Misconfiguration",
     "Origin header reflected dynamically into CORS response. If unvalidated, any origin can read data.",
     "1. Send request with Origin: https://evil.com header\n"
     "2. Check if response has Access-Control-Allow-Origin: https://evil.com\n"
     "3. If yes + credentials allowed → full cross-origin data theft",
     "Validate origin against an explicit allowlist before reflecting.",
     True),

    ("CORS Credentials True",
     r'[\'"]Access-Control-Allow-Credentials[\'"]\s*[,:=]\s*[\'"]?true',
     "medium", "CORS Misconfiguration",
     "CORS credentials enabled. Combined with weak origin validation, attacker can steal authenticated data.",
     "1. Check how Access-Control-Allow-Origin is set\n"
     "2. If origin is reflected or too permissive + credentials=true → critical\n"
     "3. Exploit: fetch(target, {credentials: 'include'}) from attacker origin",
     "Only allow credentials with strictly validated origin allowlist.",
     True),

    # ================================================================
    # JSONP CALLBACKS
    # ================================================================
    ("JSONP Callback Parameter",
     r'[\?&](?:callback|jsonp|cb|jsonpcallback|json_callback)\s*=',
     "medium", "JSONP",
     "JSONP callback parameter. If it returns sensitive data, it can be stolen cross-origin.",
     "1. Check: ?callback=alert — does it execute?\n"
     "2. JSONP bypasses CORS because it uses <script> tags\n"
     "3. If authenticated data is returned: create attacker page with <script src='target?callback=steal'>\n"
     "4. The callback wraps the data: steal({\"user\": \"admin\", \"email\": ...})",
     "Migrate from JSONP to CORS-based JSON APIs. If JSONP is needed, use CSRF tokens.",
     True),

    ("Dynamic JSONP Script Loading",
     r'createElement\s*\(\s*[\'"]script[\'"]\s*\)[\s\S]{0,200}(?:callback|jsonp|cb)\s*=',
     "high", "JSONP",
     "Dynamic JSONP script element creation. Classic cross-origin data theft vector.",
     "1. JSONP wraps sensitive data in a callback function\n"
     "2. Any page can include the script and steal the data\n"
     "3. Check what data the JSONP endpoint returns",
     "Replace JSONP with fetch() + CORS. Use CSRF tokens if JSONP is unavoidable.",
     True),

    # ================================================================
    # INSECURE STORAGE
    # ================================================================
    ("localStorage/sessionStorage Token Storage",
     r'(?:localStorage|sessionStorage)\.(?:setItem|getItem)\s*\(\s*[\'"](?:token|auth|jwt|session|secret|api[_-]?key|access[_-]?token|refresh[_-]?token|bearer|credential|password)',
     "medium", "Insecure Storage",
     "Sensitive token stored in localStorage/sessionStorage. Accessible to any XSS on the same origin.",
     "1. If XSS exists anywhere on this origin, attacker can steal the token\n"
     "2. localStorage persists even after browser close\n"
     "3. Exploit chain: find XSS → read localStorage → steal token",
     "Store tokens in HttpOnly Secure cookies instead of localStorage. If localStorage is needed, encrypt the value.",
     True),

    ("Cookie Set with Sensitive Data",
     r'document\.cookie\s*=\s*[^;]*(?:token|auth|session|jwt|secret|api[_-]?key|password)',
     "medium", "Insecure Storage",
     "Setting cookie with sensitive data via JavaScript. Missing HttpOnly flag means XSS can steal it.",
     "1. Check if HttpOnly and Secure flags are set\n"
     "2. If set via document.cookie, HttpOnly is NOT possible\n"
     "3. Any XSS can read document.cookie",
     "Set cookies server-side with HttpOnly and Secure flags. Never set auth cookies via JavaScript.",
     True),

    # ================================================================
    # UNSAFE URL HANDLING
    # ================================================================
    ("javascript: Protocol in URL",
     r'[\'"]javascript:(?!void)',
     "high", "Unsafe URL",
     "javascript: protocol found in a URL string. Can lead to XSS when used in href, location, src.",
     "1. Check if the javascript: URL is user-injectable\n"
     "2. Even <a href='javascript:alert(1)'> is XSS\n"
     "3. Check for javascript: in dynamically set URLs",
     "Block javascript: and data: protocols. Use URL validation with allowlisted schemes (https:, http:).",
     True),

    ("User-controlled fetch/XHR URL",
     r'(?:fetch|XMLHttpRequest\.prototype\.open|\$\.(?:ajax|get|post|getJSON))\s*\(\s*(?![\'\"](https?://|/)[^\'"]+([\'\"])).*(?:location|search|hash|params|query|url|href|input|data)',
     "high", "Unsafe URL",
     "Network request with potentially user-controlled URL. Can lead to SSRF or data exfiltration.",
     "1. Check if the URL parameter comes from user input\n"
     "2. Can potentially redirect API calls to attacker's server\n"
     "3. SSRF if the request is made server-side",
     "Validate request URLs against allowlist. Use relative paths for same-origin requests.",
     True),

    ("Dynamic Script Src (Supply Chain)",
     r'(?:createElement\s*\(\s*[\'"]script[\'"]\s*\)|script\.src\s*=)\s*[^;]{1,200}(?:(?:location|search|hash|params|url|href|input|data|domain|host|cdn))',
     "high", "Supply Chain",
     "Dynamic script loading with potentially user-controlled URL. Attacker can inject malicious JS.",
     "1. If script src is user-controlled → full XSS via external script\n"
     "2. Check if domain/path can be manipulated\n"
     "3. Even CDN control gives full JS execution in target's origin",
     "Use Subresource Integrity (SRI) for external scripts. Never load scripts from user-controlled URLs.",
     True),

    # ================================================================
    # TEMPLATE INJECTION (Client-Side)
    # ================================================================
    ("Angular Template Expression",
     r'\{\{[^}]*(?:constructor|__proto__|\$eval|\$parse|\$apply|\$digest|\$watch)',
     "high", "Template Injection",
     "Angular template expression with dangerous keywords. Can lead to client-side template injection.",
     "1. AngularJS sandbox escape: {{constructor.constructor('alert(1)')()}}\n"
     "2. Check Angular version — older versions have more bypasses\n"
     "3. ng-app or ng-controller in the page confirms Angular",
     "Upgrade to Angular (not AngularJS). Use ng-bind instead of {{}}. Sanitize user input.",
     True),

    ("React dangerouslySetInnerHTML",
     r'dangerouslySetInnerHTML\s*=\s*\{\{\s*__html\s*:',
     "high", "Template Injection",
     "React's dangerouslySetInnerHTML with potentially user-controlled HTML. Equivalent to innerHTML.",
     "1. Trace where __html value comes from\n"
     "2. If user input flows in without sanitization → XSS\n"
     "3. React explicitly warns about this (hence the name 'dangerously')",
     "Sanitize HTML with DOMPurify before passing to dangerouslySetInnerHTML.",
     True),

    ("Vue v-html Directive",
     r'v-html\s*=\s*[\'"]',
     "high", "Template Injection",
     "Vue v-html directive renders raw HTML. If user input is bound, it leads to XSS.",
     "1. Check what data is bound to v-html\n"
     "2. If user-controlled → direct XSS\n"
     "3. Vue itself warns: only use v-html with trusted content",
     "Use v-text or {{ }} interpolation (which escapes HTML) instead of v-html.",
     True),

    # ================================================================
    # INFORMATION DISCLOSURE
    # ================================================================
    ("Console Log of Sensitive Data",
     r'console\.(?:log|debug|info|warn|error)\s*\([^)]*(?:token|secret|password|key|auth|credential|bearer|jwt|session)',
     "low", "Info Disclosure",
     "Sensitive data logged to console. Accessible to any JS (including XSS payloads) and browser extensions.",
     "1. Open browser DevTools → Console\n"
     "2. Check if tokens, secrets, or credentials are logged\n"
     "3. An XSS can override console.log to exfiltrate",
     "Remove or redact sensitive data from console.log in production.",
     False),

    ("Source Map Reference",
     r'//[#@]\s*sourceMappingURL\s*=\s*[^\s]+\.map',
     "low", "Info Disclosure",
     "Source map reference found. Source maps expose original unminified source code.",
     "1. Download the .map file\n"
     "2. Use source-map-explorer or browser DevTools to reconstruct original code\n"
     "3. Original code may reveal: API keys, internal logic, hidden endpoints, auth bypasses",
     "Remove source maps from production builds. Block .map files at the web server.",
     True),

    ("Debug/Development Mode Flag",
     r'(?:DEBUG|debug|DEV_MODE|DEVELOPMENT|isDebug|isDev|enableDebug|devMode)\s*[=:]\s*(?:true|1|[\'"]true[\'"])',
     "medium", "Info Disclosure",
     "Debug/development mode enabled. May expose verbose errors, hidden functionality, or bypass security.",
     "1. Debug mode often enables: detailed error messages, stack traces, extra logging\n"
     "2. May disable security features (CSRF, auth checks)\n"
     "3. Check for hidden admin/debug endpoints",
     "Ensure debug/dev flags are false in production. Use environment variables.",
     True),

    ("Stack Trace Exposure",
     r'(?:stack|stackTrace|stack_trace|stacktrace)\s*[=:]',
     "low", "Info Disclosure",
     "Stack trace handling. If exposed to users, reveals internal code structure and file paths.",
     "1. Trigger errors and check if stack traces appear in responses\n"
     "2. Stack traces reveal: file paths, framework versions, function names\n"
     "3. Useful for mapping internal architecture",
     "Catch errors and return generic messages in production. Log stack traces server-side only.",
     False),

    # ================================================================
    # INSECURE CRYPTOGRAPHY
    # ================================================================
    ("Math.random() for Security",
     r'Math\.random\s*\(\)(?:[\s\S]{0,100}(?:token|nonce|secret|key|auth|csrf|random|uuid|id|session))',
     "medium", "Insecure Crypto",
     "Math.random() used for security-sensitive value. Math.random() is NOT cryptographically secure.",
     "1. Math.random() output is predictable (PRNG)\n"
     "2. If used for tokens, session IDs, CSRF tokens → they can be predicted/brute-forced\n"
     "3. Test: generate many values and check for patterns",
     "Use crypto.getRandomValues() or crypto.randomUUID() for security-sensitive random values.",
     True),

    ("Weak Hash Algorithm",
     r'(?:createHash|CryptoJS|crypto\.subtle\.digest)\s*\(\s*[\'\"](md5|sha1|sha-1)[\'\"]',
     "medium", "Insecure Crypto",
     "Weak hash algorithm (MD5/SHA1). Vulnerable to collision attacks.",
     "1. Check what is being hashed — passwords? tokens?\n"
     "2. MD5/SHA1 have known collision attacks\n"
     "3. For password hashing: neither is acceptable (use bcrypt/scrypt/argon2)",
     "Use SHA-256 or higher for hashing. Use bcrypt/scrypt/argon2id for passwords.",
     True),

    # ================================================================
    # MISC DANGEROUS PATTERNS
    # ================================================================
    ("Iframe srcdoc/src Dynamic",
     r'(?:iframe\.(?:srcdoc|src)|[\'"]srcdoc[\'"]\s*[=:])\s*[^;]{1,200}(?:location|search|hash|params|query|url|href|input|data)',
     "high", "DOM XSS Sink",
     "Dynamic iframe src/srcdoc with potentially user-controlled content.",
     "1. If iframe content is user-controlled → XSS in the iframe context\n"
     "2. srcdoc accepts full HTML including <script> tags\n"
     "3. sandbox attribute can mitigate but check if allow-scripts is set",
     "Use sandbox attribute without allow-scripts. Validate src against allowlist.",
     True),

    ("document.domain Manipulation",
     r'document\.domain\s*=',
     "high", "Unsafe URL",
     "document.domain is being set, relaxing same-origin policy. Enables cross-subdomain attacks.",
     "1. Setting document.domain allows sibling subdomains to access each other\n"
     "2. If attacker controls any subdomain (XSS, takeover) → full access to this page\n"
     "3. Deprecated in modern browsers but still works in some",
     "Remove document.domain usage. Use postMessage for cross-origin communication.",
     True),

    ("Unsafe Regex (ReDoS)",
     r'new\s+RegExp\s*\(\s*[^)]{1,100}(?:location|search|hash|params|query|url|href|input|data)',
     "medium", "ReDoS",
     "RegExp created from user input. Can cause ReDoS (Regular Expression Denial of Service).",
     "1. If user input is passed to new RegExp(), craft a catastrophic backtracking pattern\n"
     "2. Payload: (a+)+$ with input aaaa...a! freezes the regex engine\n"
     "3. Can DoS the browser tab or server",
     "Never create RegExp from user input. If unavoidable, use a timeout or limit input length.",
     True),

    ("WebSocket without TLS",
     r'new\s+WebSocket\s*\(\s*[\'"]ws://',
     "medium", "Insecure Transport",
     "WebSocket over unencrypted ws:// protocol. Data transmitted in plaintext.",
     "1. All WebSocket traffic can be intercepted (MITM)\n"
     "2. Check what data flows over the WebSocket\n"
     "3. If auth tokens or sensitive data → critical",
     "Use wss:// (WebSocket Secure) instead of ws://.",
     True),

    ("Insecure Deserialization Hint",
     r'(?:JSON\.parse|deserialize|unserialize|fromJSON|decode)\s*\([^)]*(?:location|search|hash|params|query|url|href|input|data|body|cookie)',
     "medium", "Insecure Deserialization",
     "Deserialization of potentially user-controlled data.",
     "1. If the parsed data drives application logic → injection possible\n"
     "2. For JSON.parse: check if the result is used in merge/assign (→ prototype pollution)\n"
     "3. For other deserializers: check for RCE gadgets",
     "Validate deserialized data schema. Use safe parsers. Avoid deserializing untrusted data.",
     True),

    ("Service Worker Registration",
     r'navigator\.serviceWorker\.register\s*\(',
     "medium", "Supply Chain",
     "Service Worker registration. If the SW script URL is user-controlled, attacker gets persistent code execution.",
     "1. Check if the registered script path can be influenced\n"
     "2. Service Workers persist even after page close\n"
     "3. SW can intercept ALL requests from the origin → full control",
     "Only register Service Workers from static, trusted paths. Never use dynamic URLs.",
     True),

    ("Blob URL Creation from User Data",
     r'URL\.createObjectURL\s*\(\s*new\s+Blob\s*\([^)]*(?:location|search|hash|params|query|url|href|input|data)',
     "high", "DOM XSS Sink",
     "Blob URL created from user-controlled data. Can be used for XSS if rendered as HTML.",
     "1. If the Blob is type text/html and rendered in iframe/window → XSS\n"
     "2. Blob URLs have same origin as the creating page\n"
     "3. CSP bypass: blob: URLs may bypass some CSP policies",
     "Don't create Blob URLs from user data. If needed, sanitize content and use text/plain mimetype.",
     True),
]


# ============================================================
# COMPILE PATTERNS
# ============================================================

COMPILED_VULNS = []
for entry in VULN_PATTERNS_RAW:
    name, regex_str, severity, category, desc, how_to_test, remediation, bounty = entry
    try:
        compiled = re.compile(regex_str, re.IGNORECASE)
        COMPILED_VULNS.append((name, compiled, severity, category, desc, how_to_test, remediation, bounty))
    except re.error as e:
        print(f"[!] Skipping broken regex for '{name}': {e}")

print(f"[*] {len(COMPILED_VULNS)} vulnerability patterns compiled.")


# ============================================================
# FILE PARSER
# ============================================================

def get_file_size_mb(filepath):
    try:
        return os.path.getsize(filepath) / (1024 * 1024)
    except OSError:
        return 0


def extract_lines(filepath, max_line_len=102400):
    results = []
    try:
        with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
            content = f.read()
    except Exception as e:
        print(f"\n  [!] Error reading {filepath}: {e}")
        return results

    if content.count('\n') < 10 and len(content) > 1000:
        chunks = content.split(';')
        for i, chunk in enumerate(chunks):
            chunk = chunk.strip()
            if chunk and len(chunk) >= 5 and len(chunk) <= max_line_len:
                results.append((i + 1, chunk))
    else:
        for line_no, line in enumerate(content.split('\n'), 1):
            line = line.strip()
            if not line or len(line) < 3:
                continue
            if len(line) > max_line_len:
                for j in range(0, len(line), max_line_len):
                    sub = line[j:j + max_line_len]
                    if len(sub) >= 5:
                        results.append((line_no, sub))
            else:
                results.append((line_no, line))

    del content
    return results


# ============================================================
# DOWNLOADER
# ============================================================

def download_js_files(urls, output_dir, timeout=20, proxy=None):
    if not HAS_REQUESTS:
        print("[!] 'requests' required for URL downloads. pip install requests")
        return []

    os.makedirs(output_dir, exist_ok=True)
    session = requests.Session()
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
                      ' AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36',
    })
    retry = Retry(total=2, backoff_factor=1, status_forcelist=[500, 502, 503, 504])
    adapter = HTTPAdapter(max_retries=retry)
    session.mount('https://', adapter)
    session.mount('http://', adapter)
    if proxy:
        session.proxies = {'http': proxy, 'https': proxy}

    downloaded = []
    total = len(urls)
    for i, url in enumerate(urls, 1):
        try:
            parsed = urlparse(url)
            name = os.path.basename(parsed.path) or 'index.js'
            # Make unique filename
            safe_name = re.sub(r'[^a-zA-Z0-9._-]', '_', name)[:100]
            out_path = os.path.join(output_dir, f"{i:04d}_{safe_name}")

            print(f"  [{i}/{total}] {url[:80]}...", end='', flush=True)
            resp = session.get(url, timeout=timeout, allow_redirects=True)
            if resp.status_code == 200 and len(resp.text) > 50:
                with open(out_path, 'w', encoding='utf-8') as f:
                    f.write(resp.text)
                size_kb = len(resp.text) / 1024
                print(f" -> {size_kb:.0f}KB")
                downloaded.append(out_path)
            else:
                print(f" -> HTTP {resp.status_code} (skipped)")
        except Exception as e:
            print(f" -> ERROR: {str(e)[:40]}")

    return downloaded


# ============================================================
# SCANNER
# ============================================================

def scan_file(filepath, verbose=False):
    findings = []
    seen = set()
    lines = extract_lines(filepath)
    if not lines:
        return findings

    for line_no, text in lines:
        for name, compiled_re, severity, category, desc, how_to_test, remediation, bounty in COMPILED_VULNS:
            try:
                for match in compiled_re.finditer(text):
                    matched = match.group(0)
                    dedup = f"{name}|{matched[:80]}"
                    if dedup in seen:
                        continue
                    seen.add(dedup)

                    start = max(0, match.start() - 80)
                    end = min(len(text), match.end() + 80)
                    context = text[start:end]

                    findings.append({
                        'name': name,
                        'severity': severity,
                        'category': category,
                        'description': desc,
                        'how_to_test': how_to_test,
                        'remediation': remediation,
                        'bounty_worthy': bounty,
                        'matched_text': matched[:300],
                        'context': context[:500],
                        'line_no': line_no,
                        'source_file': filepath,
                        'full_line': text[:600],
                    })

                    if verbose:
                        tag = " [BOUNTY]" if bounty else ""
                        print(f"    [{severity.upper()}]{tag} {name}: {matched[:60]}")
            except re.error:
                continue

    return findings


# ============================================================
# HTML REPORT
# ============================================================

SEVERITY_ORDER = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
SEVERITY_COLORS = {
    'critical': '#dc3545', 'high': '#fd7e14', 'medium': '#ffc107',
    'low': '#17a2b8', 'info': '#6c757d',
}
CATEGORY_ICONS = {
    'DOM XSS Sink': '\U0001f4a5', 'DOM XSS Source': '\U0001f50d',
    'Prototype Pollution': '\U0001f9ea', 'Open Redirect': '\U0001f500',
    'Insecure postMessage': '\U0001f4e8', 'CORS Misconfiguration': '\U0001f310',
    'JSONP': '\U0001f4e6', 'Dangerous Eval': '\u26a1',
    'Insecure Storage': '\U0001f4be', 'Unsafe URL': '\U0001f517',
    'Template Injection': '\U0001f489', 'Info Disclosure': '\U0001f4cb',
    'Insecure Crypto': '\U0001f512', 'Supply Chain': '\U0001f4e6',
    'ReDoS': '\U0001f4a3', 'Insecure Transport': '\U0001f513',
    'Insecure Deserialization': '\U0001f4e5',
}


def generate_report(all_findings, scanned_files, output_path, scan_duration):
    all_findings.sort(key=lambda x: (SEVERITY_ORDER.get(x['severity'], 99), x['category'], x['name']))

    total = len(all_findings)
    bounty_count = sum(1 for f in all_findings if f['bounty_worthy'])
    sev_counts = {}
    cat_counts = {}
    for f in all_findings:
        sev_counts[f['severity']] = sev_counts.get(f['severity'], 0) + 1
        cat_counts[f['category']] = cat_counts.get(f['category'], 0) + 1

    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    dur = f"{scan_duration:.1f}s"

    html = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>JS Vulnerability Scanner - Report</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,monospace;background:#0d1117;color:#c9d1d9;padding:2rem;line-height:1.6}}
.container{{max-width:1400px;margin:0 auto}}
h1{{color:#58a6ff;margin-bottom:.5rem;font-size:1.8rem}}
h2{{color:#58a6ff;margin:2rem 0 1rem;font-size:1.4rem;border-bottom:1px solid #30363d;padding-bottom:.5rem}}
h3{{color:#c9d1d9;margin:1rem 0 .5rem;font-size:1.1rem}}
h4{{color:#8b949e;margin:.6rem 0 .3rem;font-size:.9rem;text-transform:uppercase}}
.meta{{color:#8b949e;margin-bottom:2rem;font-size:.9rem}}
.meta a{{color:#58a6ff}}
.stats{{display:flex;gap:1rem;flex-wrap:wrap;margin:1.5rem 0}}
.stat-card{{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:1rem 1.5rem;min-width:110px;text-align:center}}
.stat-card .num{{font-size:2rem;font-weight:bold}}
.stat-card .label{{font-size:.7rem;color:#8b949e;text-transform:uppercase}}
.sev-badge{{display:inline-block;padding:2px 10px;border-radius:12px;font-size:.75rem;font-weight:bold;text-transform:uppercase;color:#fff}}
.sev-critical{{background:#dc3545}}
.sev-high{{background:#fd7e14}}
.sev-medium{{background:#ffc107;color:#000}}
.sev-low{{background:#17a2b8}}
.sev-info{{background:#6c757d}}
.bounty-badge{{display:inline-block;padding:2px 10px;border-radius:12px;font-size:.75rem;font-weight:bold;background:#238636;color:#fff;margin-left:6px}}
.cat-badge{{display:inline-block;padding:2px 10px;border-radius:12px;font-size:.75rem;background:#1f2937;color:#58a6ff;border:1px solid #30363d;margin-left:6px}}
.finding{{background:#161b22;border:1px solid #30363d;border-radius:8px;margin:1.2rem 0;border-left:4px solid #30363d;overflow:hidden}}
.finding.critical{{border-left-color:#dc3545}}.finding.high{{border-left-color:#fd7e14}}.finding.medium{{border-left-color:#ffc107}}.finding.low{{border-left-color:#17a2b8}}
.finding-hdr{{display:flex;align-items:center;gap:.8rem;padding:1rem 1.2rem .6rem;flex-wrap:wrap;background:#0d1117;border-bottom:1px solid #30363d}}
.finding-title{{font-weight:bold;color:#f0f6fc}}
.finding-body{{display:grid;grid-template-columns:1fr 1fr;gap:0}}
.finding-left{{padding:1rem 1.2rem;border-right:1px solid #21262d}}
.finding-right{{padding:1rem 1.2rem;background:#0d1117}}
.finding-desc{{color:#8b949e;font-size:.9rem;margin-bottom:.7rem}}
.finding-meta{{color:#6e7681;font-size:.8rem;margin-bottom:.3rem}}
pre.code{{background:#010409;border:1px solid #30363d;border-radius:6px;padding:.8rem;overflow-x:auto;font-size:.8rem;color:#e6edf3;white-space:pre-wrap;word-break:break-all;margin-top:.4rem}}
pre.code .match{{background:#5c3320;color:#ffa657;padding:1px 3px;border-radius:3px;font-weight:bold}}
.howto{{background:#0d1117;border:1px solid #30363d;border-radius:6px;padding:.8rem;font-size:.82rem;color:#c9d1d9;white-space:pre-wrap;margin-top:.4rem;line-height:1.5}}
.fix{{background:#0d2818;border:1px solid #238636;border-radius:6px;padding:.8rem;font-size:.82rem;color:#3fb950;white-space:pre-wrap;margin-top:.4rem}}
.file-name{{color:#58a6ff;font-family:monospace;font-size:.95rem}}
.toc{{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:1rem 1.5rem;margin:1.5rem 0;max-height:500px;overflow-y:auto}}
.toc a{{color:#58a6ff;text-decoration:none}}.toc a:hover{{text-decoration:underline}}
.toc ul{{list-style:none;padding-left:1rem}}.toc li{{margin:.2rem 0;font-size:.85rem}}
.no-findings{{background:#161b22;border:1px solid #238636;border-radius:8px;padding:2rem;text-align:center;color:#3fb950;font-size:1.1rem}}
.cat-section{{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:1rem 1.5rem;margin:1rem 0}}
@media(max-width:900px){{.finding-body{{grid-template-columns:1fr}}.finding-left{{border-right:none;border-bottom:1px solid #21262d}}}}
</style></head><body><div class="container">
<h1>\U0001f6e1\ufe0f JS Vulnerability Scanner</h1>
<p class="meta">Generated: {timestamp} | Files: {len(scanned_files)} | Patterns: {len(COMPILED_VULNS)} | Duration: {dur}<br>
Sinks, sources & dangerous patterns. Based on <a href="https://kpwn.de/blog/javascript-analysis-for-pentesters/">kpwn.de pentester guide</a> + <a href="https://portswigger.net/research/server-side-prototype-pollution">PortSwigger prototype pollution</a></p>
"""

    # Verdict
    if bounty_count > 0:
        html += f'<div style="background:#161b22;border:2px solid #dc3545;border-radius:8px;padding:1.5rem;margin:1.5rem 0;font-size:1.05rem">\u26a0\ufe0f <strong>{bounty_count} exploitable vulnerability pattern(s)</strong> found. Review each finding for exploitation steps.</div>'
    elif total > 0:
        html += f'<div style="background:#161b22;border:2px solid #ffc107;border-radius:8px;padding:1.5rem;margin:1.5rem 0;font-size:1.05rem">\U0001f50d <strong>{total} finding(s)</strong> detected. Review for exploitability.</div>'
    else:
        html += '<div class="no-findings">\u2705 No vulnerability patterns found.</div>'

    # Stats
    html += '<div class="stats">'
    html += f'<div class="stat-card"><div class="num" style="color:#f0f6fc">{total}</div><div class="label">Total</div></div>'
    html += f'<div class="stat-card"><div class="num" style="color:#238636">{bounty_count}</div><div class="label">Exploitable</div></div>'
    for sev in ['critical','high','medium','low']:
        c = sev_counts.get(sev, 0)
        html += f'<div class="stat-card"><div class="num" style="color:{SEVERITY_COLORS.get(sev,"#ccc")}">{c}</div><div class="label">{sev.upper()}</div></div>'
    html += '</div>'

    # Category breakdown
    if cat_counts:
        html += '<h2>\U0001f4ca Category Breakdown</h2><div class="cat-section"><div style="display:flex;flex-wrap:wrap;gap:.5rem">'
        for cat in sorted(cat_counts.keys(), key=lambda c: -cat_counts[c]):
            icon = CATEGORY_ICONS.get(cat, '\U0001f50d')
            html += f'<span class="cat-badge">{icon} {html_escape(cat)} ({cat_counts[cat]})</span>'
        html += '</div></div>'

    # Findings
    if all_findings:
        html += '<div class="toc"><h3>Table of Contents</h3><ul>'
        for idx, f in enumerate(all_findings, 1):
            icon = CATEGORY_ICONS.get(f['category'], '')
            b = ' \U0001f4b0' if f['bounty_worthy'] else ''
            html += f'<li><a href="#v-{idx}"><span class="sev-badge sev-{f["severity"]}">{f["severity"]}</span> #{idx} {icon} {html_escape(f["name"])}{b}</a></li>'
        html += '</ul></div>'

        html += '<h2>\U0001f6e1\ufe0f Findings</h2>'
        for idx, f in enumerate(all_findings, 1):
            sev = f['severity']
            icon = CATEGORY_ICONS.get(f['category'], '')
            bounty_h = '<span class="bounty-badge">\U0001f4b0 EXPLOITABLE</span>' if f['bounty_worthy'] else ''
            esc_match = html_escape(f['matched_text'][:100])
            esc_ctx = html_escape(f['context'])
            hl_ctx = esc_ctx.replace(esc_match, f'<span class="match">{esc_match}</span>', 1)

            html += f"""
<div class="finding {sev}" id="v-{idx}">
<div class="finding-hdr">
    <span class="sev-badge sev-{sev}">{sev}</span>
    <span class="finding-title">#{idx} {icon} {html_escape(f['name'])}</span>
    <span class="cat-badge">{html_escape(f['category'])}</span>
    {bounty_h}
</div>
<div class="finding-body">
<div class="finding-left">
    <h4>What Was Found</h4>
    <div class="finding-desc">{html_escape(f['description'])}</div>
    <div class="finding-meta">\U0001f4c4 <span class="file-name">{html_escape(os.path.basename(f['source_file']))}</span> : line ~{f['line_no']}</div>
    <h4 style="margin-top:1rem">Matched Code</h4>
    <pre class="code">{html_escape(f['matched_text'][:300])}</pre>
    <h4 style="margin-top:1rem">\u2705 Remediation</h4>
    <div class="fix">{html_escape(f['remediation'])}</div>
</div>
<div class="finding-right">
    <h4>\U0001f3af How to Test / Exploit</h4>
    <div class="howto">{html_escape(f['how_to_test'])}</div>
    <h4 style="margin-top:1rem">Source Context</h4>
    <pre class="code">{hl_ctx}</pre>
</div>
</div></div>
"""

    html += f'<p class="meta" style="margin-top:2rem;text-align:center">JS Vulnerability Scanner v1 | {len(COMPILED_VULNS)} patterns | {timestamp} | {dur}</p></div></body></html>'

    try:
        od = os.path.dirname(output_path)
        if od:
            os.makedirs(od, exist_ok=True)
        with open(output_path, 'w', encoding='utf-8') as fp:
            fp.write(html)
        return True
    except Exception as e:
        print(f"[!] Error saving report: {e}")
        return False


# ============================================================
# MAIN
# ============================================================

def main():
    banner = """
============================================================
   JS Vulnerability Scanner v1
   Sinks, Sources & Dangerous Patterns
   Based on: kpwn.de pentester guide + PortSwigger research
   DOM XSS | Prototype Pollution | Open Redirect | postMessage
   CORS | JSONP | Eval | Template Injection | Supply Chain
============================================================
    """
    print(banner)

    ap = argparse.ArgumentParser(
        description='JS vulnerability scanner for pentesters',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python js_vuln_scanner.py --js-dir js_files/
  python js_vuln_scanner.py --urls js_urls.txt
  python js_vuln_scanner.py --js-dir js_files/ --urls js.txt -o report.html -v
  python js_vuln_scanner.py --js-dir js_files/ -o reports/vuln_report.html
        """
    )
    ap.add_argument('--js-dir', help='Directory with local JS files')
    ap.add_argument('--urls', help='File with JS URLs to download and scan')
    ap.add_argument('-o', '--output', default='reports/js_vuln_report.html', help='Output HTML report')
    ap.add_argument('-v', '--verbose', action='store_true', help='Verbose')
    ap.add_argument('--max-file-size', type=float, default=50, help='Max file size MB')
    ap.add_argument('--download-dir', default='js_downloads', help='Dir for downloaded JS')
    ap.add_argument('--proxy', help='Proxy for downloads')
    ap.add_argument('--timeout', type=int, default=20, help='Download timeout')
    ap.add_argument('--txt', help='Save findings summary to text file')
    args = ap.parse_args()

    if not args.js_dir and not args.urls:
        if os.path.exists('js_files'):
            args.js_dir = 'js_files'
        else:
            print("[!] No input. Use --js-dir <dir> or --urls <file>")
            sys.exit(1)

    file_queue = []
    scan_start = time.time()

    # Download JS from URLs
    if args.urls:
        urls = []
        try:
            with open(args.urls, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and line.startswith('http'):
                        urls.append(line)
        except FileNotFoundError:
            print(f"[!] File not found: {args.urls}")
            sys.exit(1)

        if urls:
            print(f"[*] Downloading {len(urls)} JS files...")
            downloaded = download_js_files(urls, args.download_dir, args.timeout, args.proxy)
            for f in downloaded:
                file_queue.append(f)
            print(f"[+] Downloaded {len(downloaded)}/{len(urls)} files")

    # Local JS files
    if args.js_dir:
        if os.path.exists(args.js_dir):
            js_exts = {'.js', '.mjs', '.jsx', '.ts', '.tsx', '.json', '.txt'}
            for fn in sorted(os.listdir(args.js_dir)):
                ext = os.path.splitext(fn)[1].lower()
                if ext in js_exts or not ext:
                    file_queue.append(os.path.join(args.js_dir, fn))
            print(f"[*] Local JS files: {sum(1 for f in file_queue if f.startswith(args.js_dir))} in {args.js_dir}/")
        else:
            print(f"[!] Directory not found: {args.js_dir}")

    if not file_queue:
        print("[!] No files to scan.")
        sys.exit(1)

    print(f"[*] Total files: {len(file_queue)} | Patterns: {len(COMPILED_VULNS)}")
    print(f"[*] Output: {args.output}\n")

    all_findings = []
    scanned_files = []
    skipped_files = []

    for fi, fpath in enumerate(file_queue, 1):
        fname = os.path.basename(fpath)
        sz = get_file_size_mb(fpath)
        if sz > args.max_file_size:
            print(f"  [{fi}/{len(file_queue)}] SKIP {fname} ({sz:.1f}MB)")
            skipped_files.append(fpath)
            continue

        sz_str = f"{sz:.1f}MB" if sz >= 1 else f"{sz*1024:.0f}KB"
        print(f"  [{fi}/{len(file_queue)}] {fname} ({sz_str})", end='', flush=True)

        findings = scan_file(fpath, verbose=args.verbose)
        all_findings.extend(findings)
        scanned_files.append(fpath)

        if findings:
            sev_s = {}
            for f in findings:
                sev_s[f['severity']] = sev_s.get(f['severity'], 0) + 1
            parts = [f"{v} {k}" for k, v in sorted(sev_s.items(), key=lambda x: SEVERITY_ORDER.get(x[0], 99))]
            print(f" => {len(findings)} vuln(s): {', '.join(parts)}")
        else:
            print(f" => clean")

    scan_duration = time.time() - scan_start

    # Summary
    print(f"\n{'='*60}")
    print(f"SCAN COMPLETE ({scan_duration:.1f}s)")
    print(f"{'='*60}")
    print(f"Files scanned:    {len(scanned_files)}")
    print(f"Total findings:   {len(all_findings)}")
    bounty_count = sum(1 for f in all_findings if f['bounty_worthy'])
    print(f"Exploitable:      {bounty_count}")

    for sev in ['critical','high','medium','low','info']:
        c = sum(1 for f in all_findings if f['severity'] == sev)
        if c:
            print(f"  {sev.upper():<12} {c}")

    cat_counts = {}
    for f in all_findings:
        cat_counts[f['category']] = cat_counts.get(f['category'], 0) + 1
    if cat_counts:
        print(f"\nBy category:")
        for cat in sorted(cat_counts, key=lambda c: -cat_counts[c]):
            print(f"  {cat:<25} {cat_counts[cat]}")

    # Generate report
    print(f"\n[*] Generating HTML report...")
    if generate_report(all_findings, scanned_files, args.output, scan_duration):
        ap_str = os.path.abspath(args.output)
        print(f"[+] Report: {args.output}")
        print(f"    Full path: {ap_str}")
        print(f"\n[*] Open: file://{ap_str}")

    # Save text summary
    if args.txt and all_findings:
        try:
            od = os.path.dirname(args.txt)
            if od:
                os.makedirs(od, exist_ok=True)
            with open(args.txt, 'w', encoding='utf-8') as fp:
                for f in sorted(all_findings, key=lambda x: (SEVERITY_ORDER.get(x['severity'], 99), x['name'])):
                    fp.write(f"[{f['severity'].upper()}] {f['name']} | {os.path.basename(f['source_file'])}:L{f['line_no']}\n")
                    fp.write(f"  Category: {f['category']}\n")
                    fp.write(f"  Matched: {f['matched_text'][:120]}\n")
                    fp.write(f"  {f['description'][:200]}\n")
                    fp.write(f"  Bounty: {'Yes' if f['bounty_worthy'] else 'No'}\n\n")
            print(f"[+] Text summary: {args.txt}")
        except Exception as e:
            print(f"[!] Error saving txt: {e}")

    if bounty_count:
        print(f"\n[!!] {bounty_count} EXPLOITABLE pattern(s)! Check the report for exploitation guides.")
    print()


if __name__ == '__main__':
    main()
