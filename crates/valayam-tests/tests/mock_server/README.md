# Valayam Mock Vulnerability Server

This directory contains a standalone Mock Server built with Python (FastAPI). 
It serves as the foundation for end-to-end (E2E) integration testing of Valayam plugins.

## Architecture & Maintainability
Instead of testing plugins against random endpoints, all vulnerable endpoints are centralized here.
The application is structured modularly using FastAPI APIRouter to easily scale to 1000+ endpoints.
Each router represents a specific vulnerability category, making it easy to test our scanner logic deterministically.

> **Note on Coverage**: The endpoints in this mock server comprehensively cover all categories of the **OWASP Top 10 (2021)**, including Broken Access Control, Cryptographic Failures, Injection, Insecure Design, Security Misconfiguration, Vulnerable and Outdated Components, Identification and Authentication Failures, Software and Data Integrity Failures, Security Logging and Monitoring Failures, and Server-Side Request Forgery (SSRF).

### Implemented Modules:

#### 1. CORS (routers/misconfiguration/cors/endpoints.py)
- **Endpoint**: OPTIONS /api/cors/insecure (and GET)
- **Vulnerability**: Reflects the Origin header directly.

#### 2. GraphQL (routers/logic/graphql/endpoints.py)
- **Endpoint**: POST /graphql/introspection
- **Vulnerability**: Successfully responds to introspection queries (__schema).

#### 3. OAuth (routers/auth/endpoints.py)
- **Endpoint**: GET /oauth/callback
- **Vulnerability**: Missing state query parameter validation.

#### 4. SQL Injection (routers/injection/sqli/endpoints.py)
- **Endpoint**: GET /sqli/users?id=1
- **Vulnerability**: Vulnerable to classic SQL injection via the 'id' parameter.
- **Endpoint**: GET /sqli/users/blind?id=1
- **Vulnerability**: Vulnerable to blind (time-based) SQL injection.

#### 5. Cross-Site Scripting (routers/injection/xss/endpoints.py)
- **Endpoint**: GET /xss/search?q=query
- **Vulnerability**: Directly reflects the 'q' query parameter into the HTML response without sanitization.
- **Endpoint**: POST /xss/comment
- **Vulnerability**: Stored XSS simulation.

#### 6. Local File Inclusion (routers/file_ops/lfi/endpoints.py)
- **Endpoint**: GET /lfi/download?file=...
- **Vulnerability**: Allows reading arbitrary local files via path traversal.

#### 7. Server-Side Request Forgery (routers/request_forgery/ssrf/endpoints.py)
- **Endpoint**: GET /ssrf/fetch?url=...
- **Vulnerability**: Fetches arbitrary URLs without validation.

#### 8. OS Command Injection (routers/injection/osci/endpoints.py)
- **Endpoint**: GET /osci/ping?host=...
- **Vulnerability**: Executes shell commands appending user input directly.

#### 9. Insecure Direct Object Reference (routers/access_control/idor/endpoints.py)
- **Endpoint**: GET /idor/users/{user_id}/profile
- **Vulnerability**: Allows access to other users' profiles.

#### 10. Insecure JWT Validation (routers/auth/jwt/endpoints.py)
- **Endpoint**: GET /jwt/validate
- **Vulnerability**: Accepts 'none' algorithm.

#### 11. Open Redirect (routers/client_side/open_redirect/endpoints.py)
- **Endpoint**: GET /open_redirect/login?next=...
- **Vulnerability**: Redirects users to an arbitrary URL specified in the 'next' parameter.

#### 12. XML External Entity (routers/injection/xxe/endpoints.py)
- **Endpoint**: POST /xxe/parse
- **Vulnerability**: Insecurely parses XML containing external entities, simulating local file exposure.

#### 13. HTTP Parameter Pollution (routers/logic/hpp/endpoints.py)
- **Endpoint**: GET /hpp/transfer?amount=...&amount=...
- **Vulnerability**: Simulates parameter pollution by extracting and processing multiple identical parameters in unintended ways.

#### 14. Broken Access Control (routers/access_control/bac/endpoints.py)
- **Endpoint**: DELETE /bac/admin/delete_user?user_id=...
- **Vulnerability**: Allows unauthorized users to perform administrative actions by manipulating the 'role' header.

#### 15. Server-Side Template Injection (routers/injection/ssti/endpoints.py)
- **Endpoint**: GET /ssti/render?name=...
- **Vulnerability**: Evaluates user input as template code, simulating remote code execution via SSTI.

#### 16. Insecure Deserialization (routers/deserialization/endpoints.py)
- **Endpoint**: POST /deserialization/import_profile
- **Vulnerability**: Unsafely deserializes base64 encoded Python pickle data from the request body.

#### 17. Cross-Site Request Forgery (routers/request_forgery/csrf/endpoints.py)
- **Endpoint**: POST /csrf/transfer
- **Vulnerability**: Simulates a state-changing operation without anti-CSRF tokens.

#### 18. Mass Assignment (routers/access_control/mass_assignment/endpoints.py)
- **Endpoint**: POST /mass_assignment/update
- **Vulnerability**: Allows users to modify restricted fields, such as 'is_admin'.

#### 19. Broken Authentication / Brute Force (routers/auth/auth_bypass/endpoints.py)
- **Endpoint**: POST /auth_bypass/login
- **Vulnerability**: Simulates a login endpoint with no rate limiting or lockout mechanism.

#### 20. Security Misconfiguration (routers/data_exposure/debug/endpoints.py)
- **Endpoint**: GET /debug/env
- **Vulnerability**: Exposes sensitive environment variables directly to the client.

#### 21. Insecure Cryptographic Storage (routers/data_exposure/crypto/endpoints.py)
- **Endpoint**: POST /crypto/hash
- **Vulnerability**: Uses a weak, unsalted hashing algorithm (MD5) for passwords.

#### 22. Host Header Injection (routers/misconfiguration/host_header/endpoints.py)
- **Endpoint**: POST /host_header/reset_password
- **Vulnerability**: Generates password reset links using the untrusted 'Host' header.

#### 23. Unrestricted File Upload (routers/file_ops/file_upload/endpoints.py)
- **Endpoint**: POST /upload/file
- **Vulnerability**: Accepts file uploads without validating the file extension or content.

#### 24. Lack of Rate Limiting (routers/logic/rate_limiting/endpoints.py)
- **Endpoint**: GET /rate_limiting/sms
- **Vulnerability**: Allows sending an unlimited number of SMS messages without restriction.

#### 25. XPath Injection (routers/injection/xpath/endpoints.py)
- **Endpoint**: GET /xpath/user
- **Vulnerability**: Simulates an endpoint vulnerable to XPath injection via the 'username' parameter.

#### 26. LDAP Injection (routers/injection/ldap/endpoints.py)
- **Endpoint**: GET /ldap/search
- **Vulnerability**: Simulates an endpoint vulnerable to LDAP injection via the 'user' parameter.

#### 27. NoSQL Injection (routers/injection/nosqli/endpoints.py)
- **Endpoint**: POST /nosqli/login
- **Vulnerability**: Simulates an endpoint vulnerable to NoSQL injection by accepting JSON payload for authentication.

#### 28. CRLF Injection (routers/injection/crlf/endpoints.py)
- **Endpoint**: GET /crlf/set_cookie
- **Vulnerability**: Simulates HTTP Response Splitting / Header Injection via the 'lang' parameter.

#### 29. Insecure YAML Deserialization (routers/deserialization/yaml_deserialization/endpoints.py)
- **Endpoint**: POST /yaml/parse
- **Vulnerability**: Simulates unsafe parsing of YAML data.

#### 30. Zip Slip (routers/file_ops/zip_slip/endpoints.py)
- **Endpoint**: POST /zip_slip/extract
- **Vulnerability**: Simulates extracting an uploaded ZIP file without validating paths, leading to Directory Traversal.

#### 31. Weak JWT Secret (routers/auth/jwt_weak/endpoints.py)
- **Endpoint**: GET /jwt_weak/token
- **Vulnerability**: Signs JWT tokens with a weak, easily guessable secret ('123456').

#### 32. Broken Function Level Authorization (routers/access_control/bfla/endpoints.py)
- **Endpoint**: DELETE /bfla/users/{user_id}
- **Vulnerability**: Administrative endpoint exposed without any authorization checks.

#### 33. Clickjacking (routers/misconfiguration/clickjacking/endpoints.py)
- **Endpoint**: GET /clickjacking/page
- **Vulnerability**: Returns HTML without X-Frame-Options or CSP frame-ancestors headers.

#### 34. Blind SSRF (routers/request_forgery/ssrf_blind/endpoints.py)
- **Endpoint**: POST /ssrf_blind/webhook
- **Vulnerability**: Fetches a webhook URL in the background but returns no data.

#### 35. DOM XSS (routers/client_side/xss_dom/endpoints.py)
- **Endpoint**: GET /xss_dom/page
- **Vulnerability**: Returns HTML that insecurely assigns `window.location.hash` into `innerHTML`.

#### 37. CSV / Formula Injection (routers/injection/csv_injection/endpoints.py)
- **Endpoint**: GET /csv_injection/export
- **Vulnerability**: Injects untrusted input directly into a CSV response without escaping.

#### 38. GraphQL Query Depth / DoS (routers/logic/graphql_dos/endpoints.py)
- **Endpoint**: POST /graphql_dos/query
- **Vulnerability**: Accepts overly complex or deeply nested GraphQL queries, simulating a Denial of Service vulnerability.

#### 39. DOM-based Open Redirect (routers/client_side/open_redirect_dom/endpoints.py)
- **Endpoint**: GET /open_redirect_dom/redirect
- **Vulnerability**: Client-side JavaScript redirects the browser based on an untrusted URL parameter.

#### 40. JWT Key ID (kid) Injection (routers/auth/jwt_kid/endpoints.py)
- **Endpoint**: POST /jwt_kid/verify
- **Vulnerability**: Simulates trusting the 'kid' header in a JWT to specify a local file for the secret key.

#### 41. Session Fixation (routers/auth/session_fixation/endpoints.py)
- **Endpoint**: GET /session_fixation/login
- **Vulnerability**: Allows an attacker to fixate a user's session ID via a URL parameter.

#### 42. Race Condition / TOCTOU (routers/logic/race_condition/endpoints.py)
- **Endpoint**: POST /race_condition/transfer
- **Vulnerability**: Simulates a Time-of-Check to Time-of-Use (TOCTOU) race condition in a funds transfer operation.

#### 43. HTTP Request Smuggling (routers/http_smuggling/endpoints.py)
- **Endpoint**: POST /http_smuggling/process
- **Vulnerability**: Simulates an endpoint vulnerable to CL.TE or TE.CL request smuggling attacks.

#### 44. Cross-Site Tracing (XST) (routers/xst/endpoints.py)
- **Endpoint**: TRACE /xst/trace
- **Vulnerability**: The TRACE method reflects all headers, potentially exposing HttpOnly cookies to client-side scripts.

#### 45. XXE Billion Laughs / DoS (routers/injection/xxe_dos/endpoints.py)
- **Endpoint**: POST /xxe_dos/parse
- **Vulnerability**: Simulates parsing an XML payload susceptible to exponential entity expansion (Billion Laughs attack).

#### 46. Client-Side Template Injection (CSTI) (routers/injection/ssti_client/endpoints.py)
- **Endpoint**: GET /ssti_client/render
- **Vulnerability**: Reflects user input into a page containing a client-side template engine (AngularJS) without sanitization.

#### 47. Server-Side Includes (SSI) Injection (routers/injection/ssi/endpoints.py)
- **Endpoint**: GET /ssi/page
- **Vulnerability**: Returns HTML with unescaped user input that would be parsed by an SSI-enabled web server.

#### 48. Absolute Path Traversal (routers/file_ops/path_traversal_absolute/endpoints.py)
- **Endpoint**: GET /path_traversal_absolute/read
- **Vulnerability**: Reads absolute file paths directly (e.g., /etc/passwd or C:\) without restriction.

#### 49. Blind Command Injection (routers/injection/command_injection_blind/endpoints.py)
- **Endpoint**: POST /command_injection_blind/ping
- **Vulnerability**: Simulates time-based blind command injection by delaying response based on input.

#### 50. SQL Truncation Attack (routers/sql_truncation/endpoints.py)
- **Endpoint**: POST /sql_truncation/register
- **Vulnerability**: Simulates database truncation of input strings, potentially allowing account takeover.

#### 51. GraphQL Batching Attack (routers/logic/graphql_batching/endpoints.py)
- **Endpoint**: POST /graphql_batching/graphql
- **Vulnerability**: Accepts arrays of queries to bypass rate limits or perform brute-force attacks in a single request.

#### 52. JSONP Callback Injection (routers/client_side/jsonp/endpoints.py)
- **Endpoint**: GET /jsonp/data
- **Vulnerability**: Reflects the 'callback' parameter without validation, leading to XSS or data leakage.

#### 53. Insecure Randomness (routers/data_exposure/weak_random/endpoints.py)
- **Endpoint**: GET /weak_random/generate_token
- **Vulnerability**: Uses a predictable pseudo-random number generator for generating security tokens.

#### 54. Web Cache Poisoning (routers/misconfiguration/cache_poisoning/endpoints.py)
- **Endpoint**: GET /cache_poisoning/page
- **Vulnerability**: Reflects unkeyed HTTP headers (like X-Forwarded-Host) into the response without a Vary header.

#### 55. IP Spoofing via X-Forwarded-For (routers/misconfiguration/x_forwarded_for/endpoints.py)
- **Endpoint**: GET /x_forwarded_for/admin
- **Vulnerability**: Trusts the X-Forwarded-For header to determine the client IP for access control.

#### 56. OAuth Implicit Flow (routers/auth/oauth_implicit/endpoints.py)
- **Endpoint**: GET /oauth_implicit/authorize
- **Vulnerability**: Returns sensitive access tokens directly in the URL hash fragment.

#### 57. HTTP Method Tampering (routers/misconfiguration/method_tampering/endpoints.py)
- **Endpoint**: ANY /method_tampering/admin
- **Vulnerability**: Access controls only protect specific methods (GET/POST), allowing bypass via HEAD, OPTIONS, etc.

#### 58. Cross-Site WebSocket Hijacking (routers/request_forgery/cswsh/endpoints.py)
- **Endpoint**: WS /cswsh/ws
- **Vulnerability**: Accepts WebSocket connections from any origin, exposing sensitive data to attackers.

#### 59. Weak Password Policy (routers/auth/weak_password/endpoints.py)
- **Endpoint**: POST /weak_password/register
- **Vulnerability**: Fails to enforce password complexity, allowing trivially guessable passwords.

#### 60. Business Logic Flaw (routers/logic/business_logic/endpoints.py)
- **Endpoint**: POST /business_logic/checkout
- **Vulnerability**: Does not validate logical constraints (e.g., negative quantities), manipulating the total cost.

#### 61. Insecure Cookie Parameters (routers/auth/insecure_cookie/endpoints.py)
- **Endpoint**: GET /insecure_cookie/login
- **Vulnerability**: Sets session cookies without the Secure or HttpOnly flags, exposing them to XSS and network interception.

#### 62. SSRF Filter Bypass (routers/request_forgery/ssrf_bypass/endpoints.py)
- **Endpoint**: GET /ssrf_bypass/fetch
- **Vulnerability**: Uses incomplete blocklists (only '127.0.0.1' and 'localhost') that can be bypassed using alternatives (0.0.0.0, [::1], etc.).

#### 63. Log Injection / Forging (routers/injection/log_injection/endpoints.py)
- **Endpoint**: GET /log_injection/login
- **Vulnerability**: Unsafely writes untrusted input into server logs, allowing log forging via newline characters.

#### 64. Python Format String Injection (routers/injection/format_string/endpoints.py)
- **Endpoint**: GET /format_string/greet
- **Vulnerability**: Unsafely uses `str.format()` with user input, potentially exposing internal variables or secrets.

#### 65. Regular Expression DoS (ReDoS) (routers/logic/redos/endpoints.py)
- **Endpoint**: POST /redos/validate_email
- **Vulnerability**: Uses a catastrophic backtracking regex, allowing a crafted input to cause a Denial of Service.

#### 66. CORS Null Origin (routers/misconfiguration/cors_null/endpoints.py)
- **Endpoint**: GET /cors_null/data
- **Vulnerability**: Trusts the 'null' origin and returns Access-Control-Allow-Credentials: true, allowing sandbox bypasses.

#### 67. MIME Sniffing (routers/misconfiguration/mime_sniffing/endpoints.py)
- **Endpoint**: GET /mime_sniffing/file
- **Vulnerability**: Serves user-controllable content without the `X-Content-Type-Options: nosniff` header.

#### 68. JWT JKU Header Injection (routers/auth/jwt_jku/endpoints.py)
- **Endpoint**: POST /jwt_jku/verify
- **Vulnerability**: Trusts the 'jku' header in a JWT to fetch public keys from an untrusted URL.

#### 69. CSRF GET Request (routers/request_forgery/csrf_get/endpoints.py)
- **Endpoint**: GET /csrf_get/transfer
- **Vulnerability**: Allows state-changing operations via GET requests, making CSRF trivial.

#### 70. Sensitive Data Caching (routers/data_exposure/sensitive_cache/endpoints.py)
- **Endpoint**: GET /sensitive_cache/profile
- **Vulnerability**: Returns sensitive data without `Cache-Control: no-store`, allowing caching by intermediaries.

#### 71. GraphQL Introspection (routers/misconfiguration/graphql_introspection/endpoints.py)
- **Endpoint**: POST /graphql_introspection/query
- **Vulnerability**: Exposes the entire GraphQL schema to unauthenticated users via introspection queries.

#### 72. Technology Stack Leak (routers/misconfiguration/tech_stack_leak/endpoints.py)
- **Endpoint**: GET /tech_stack_leak/info
- **Vulnerability**: Exposes sensitive headers like `X-Powered-By` and `Server` to potential attackers.

#### 73. SSRF DNS Rebinding (routers/request_forgery/ssrf_dns_rebinding/endpoints.py)
- **Endpoint**: POST /ssrf_dns_rebinding/fetch
- **Vulnerability**: Validates an IP at resolution time but fetches later, allowing a TOCTOU DNS rebinding attack.

#### 74. BOLA in GraphQL (routers/access_control/bola_graphql/endpoints.py)
- **Endpoint**: POST /bola_graphql/query
- **Vulnerability**: Allows querying other users' private data by manipulating the ID parameter in a GraphQL query.

#### 75. Reflected XSS in SVG (routers/client_side/xss_svg/endpoints.py)
- **Endpoint**: GET /xss_svg/avatar
- **Vulnerability**: Reflects user input directly into an SVG file, which can execute JavaScript in the browser.

#### 76. Out-of-Band XXE (routers/injection/xxe_oob/endpoints.py)
- **Endpoint**: POST /xxe_oob/parse
- **Vulnerability**: Susceptible to OOB XXE where data is exfiltrated to an external attacker-controlled domain.

#### 77. Error-Based SQL Injection (routers/injection/sqli_error/endpoints.py)
- **Endpoints**: GET /sqli_error/user, POST /sqli_error/product
- **Vulnerability**: Simulates endpoints that return verbose database error messages when processing malicious SQL syntax.

#### 78. Advanced Stored XSS (routers/injection/xss_stored_advanced/endpoints.py)
- **Endpoints**: POST /xss_stored_advanced/profile_update, GET /xss_stored_advanced/profile_view, GET /xss_stored_advanced/profile_export
- **Vulnerability**: Simulates a workflow where unsanitized input is stored and reflected across multiple views/exports.

#### 79. Authentication Brute Force (routers/auth/auth_brute_force/endpoints.py)
- **Endpoints**: POST /auth_brute_force/login_no_lockout, POST /auth_brute_force/otp_bypass
- **Vulnerability**: Endpoints lacking rate limiting and account lockout, permitting continuous brute-force attempts on passwords and OTPs.

#### 80. IDOR Write Operations (routers/access_control/idor_write/endpoints.py)
- **Endpoints**: PUT /idor_write/update_settings/{user_id}, DELETE /idor_write/delete_post/{post_id}
- **Vulnerability**: Vulnerable endpoints allowing state-changing operations (updates, deletions) on arbitrary objects due to missing authorization checks.

#### 81. CRLF Advanced (routers/injection/crlf_advanced/endpoints.py)
- **Endpoints**: GET /crlf_advanced/log, GET /crlf_advanced/redirect
- **Vulnerability**: Advanced HTTP Response Splitting and log injection scenarios via unescaped newline characters in input.

#### 82. SSRF Targeting Internal APIs (routers/request_forgery/ssrf_internal/endpoints.py)
- **Endpoints**: POST /ssrf_internal/proxy, GET /ssrf_internal/status_check
- **Vulnerability**: Proxies requests or checks status of specific internal endpoints and IP ranges, disclosing internal structure.

#### 83. Advanced File Upload (routers/file_ops/file_upload_advanced/endpoints.py)
- **Endpoints**: POST /file_upload_advanced/avatar, POST /file_upload_advanced/document
- **Vulnerability**: Permits uploading potentially executable files (.php) or XSS vectors (.html, .svg) without validation.

#### 84. Advanced Mass Assignment (routers/access_control/api_ma_advanced/endpoints.py)
- **Endpoints**: POST /api_ma_advanced/create_user, PUT /api_ma_advanced/update_preferences
- **Vulnerability**: Accepts nested JSON structures and arrays allowing an attacker to inject unauthorized object properties.

#### 85. Advanced XXE (routers/injection/xxe_advanced/endpoints.py)
- **Endpoints**: POST /xxe_advanced/import_xml, POST /xxe_advanced/soap_endpoint
- **Vulnerability**: Simulates Local File Disclosure via XML import and Blind XXE in SOAP envelopes.

#### 86. Padding Oracle / Weak Crypto (routers/data_exposure/crypto_padding/endpoints.py)
- **Endpoints**: GET /crypto_padding/decrypt, POST /crypto_padding/encrypt
- **Vulnerability**: Exposes padding errors during decryption, simulating a padding oracle, and uses weak ECB encryption.

#### 87. SSRF Targeting Cloud Metadata (routers/request_forgery/ssrf_cloud/endpoints.py)
- **Endpoints**: GET /ssrf_cloud/aws, GET /ssrf_cloud/gcp
- **Vulnerability**: Simulates fetching cloud instance metadata (AWS 169.254.169.254 and GCP metadata.google.internal).

#### 88. Relative Path Traversal (routers/file_ops/path_traversal_relative/endpoints.py)
- **Endpoints**: GET /path_traversal_relative/fetch, GET /path_traversal_relative/download
- **Vulnerability**: Reads files relatively via URL encoding (`%2e%2e%2f`) and double URL encoding bypasses.

#### 89. Auth Timing Attack (routers/auth/auth_timing/endpoints.py)
- **Endpoints**: POST /auth_timing/login, POST /auth_timing/reset_password
- **Vulnerability**: Exposes user existence via observable timing discrepancies on valid versus invalid usernames.

#### 90. OOB Command Injection (routers/injection/cmd_oob/endpoints.py)
- **Endpoints**: POST /cmd_oob/network_test, POST /cmd_oob/dns_lookup
- **Vulnerability**: Blind command injection that triggers out-of-band network interactions (curl/wget or dns).

#### 91. Insecure CORS Regex (routers/misconfiguration/cors_regex/endpoints.py)
- **Endpoints**: GET /cors_regex/data, OPTIONS /cors_regex/data
- **Vulnerability**: Flawed regex or `startswith`/`endswith` checks allowing subdomains and arbitrary domain suffixes.

#### 92. Blind NoSQLi (routers/injection/nosqli_blind/endpoints.py)
- **Endpoints**: POST /nosqli_blind/auth, GET /nosqli_blind/user
- **Vulnerability**: Boolean-based blind NoSQL injection via regex and `$ne` operator manipulation.

#### 93. JWT Alg Confusion (routers/auth/jwt_alg_confusion/endpoints.py)
- **Endpoints**: POST /jwt_alg_confusion/verify, GET /jwt_alg_confusion/profile
- **Vulnerability**: Simulates a backend confusing symmetric verification (HS256) with a public key (RS256).

#### 94. Mutation XSS (mXSS) (routers/client_side/xss_mutation/endpoints.py)
- **Endpoints**: POST /xss_mutation/submit, GET /xss_mutation/view
- **Vulnerability**: Vulnerability caused by DOM changes during HTML parsing, bypassing simple filters.

#### 95. Advanced SSTI (routers/injection/ssti_advanced/endpoints.py)
- **Endpoints**: POST /ssti_advanced/render_jinja, POST /ssti_advanced/render_twig
- **Vulnerability**: Advanced Server-Side Template Injection bypassing basic filters in Jinja or Twig.

#### 96. OAuth State Bypass (routers/auth/oauth_state/endpoints.py)
- **Endpoints**: GET /oauth_state/authorize, GET /oauth_state/callback
- **Vulnerability**: Omission and failure to validate the `state` parameter, leading to OAuth CSRF.

## Usage

`bash
# Install dependencies
pip install -r requirements.txt

# Run the mock server (starts on port 8111)
python app.py
`

Swagger documentation is available at http://127.0.0.1:8111/docs.
