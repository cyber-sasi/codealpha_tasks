# SecureReview Demo — Security Review

## 1. Executive Summary

This review compared the intentionally insecure, loopback-only Flask application in `vulnerable_app/` with the remediated application in `secure_app/`. Manual inspection identified seven issues in the teaching implementation: unsafe debug mode, SQL injection, reflected cross-site scripting (XSS), plaintext password storage, a hardcoded Flask signing secret, missing CSRF defenses, and missing browser security headers.

No Critical issue was identified. Debug mode is High because the Werkzeug debugger can enable arbitrary code execution if the service becomes reachable by an untrusted party; the current entry point binds only to `127.0.0.1`, which constrains but does not make the setting safe. The remaining risks are Medium or Low as explained below, particularly because this demonstration is restricted to local use and synthetic data.

All seven findings have corresponding mitigations in `secure_app/`. Bandit 1.9.4 identified four relevant patterns in `vulnerable_app/` (one Low, two Medium, one High) and reported no issues in `secure_app/`. The test suite passed: 13 tests.

## 2. Scope

**In scope**

- Python and Flask source in `vulnerable_app/app.py` and `secure_app/app.py`.
- Both apps' templates, SQLite interactions, authentication/session handling, and form processing.
- pytest checks in `tests/`.
- Bandit recursive scans of each application package.

**Out of scope**

- Network or deployment testing, external websites/systems, operating-system configuration, dependency vulnerability databases, and production infrastructure.
- Testing with real credentials, personal information, or non-local data.
- Claims that this small review proves either implementation production-ready.

Both development servers are configured to bind to the loopback interface. The intentionally vulnerable application is a controlled code-review example and must not be exposed to a network.

## 3. Methodology

1. Manually inspected the vulnerable routes, SQL statements, templates, configuration, and form processing.
2. Compared relevant flows with the secure implementation to verify that each reported issue has a concrete remediation.
3. Ran Bandit against both application packages and verified each vulnerable-app warning against the affected source.
4. Ran pytest using Flask's in-process test clients and per-test temporary SQLite databases. Tests do not start a listener or contact external systems.

Bandit is a pattern-based static analyzer. Its warning is evidence to inspect, not by itself proof of exploitability. Conversely, manual review can identify issues that the scanner does not report.

## 4. Tools Used

| Tool | Version / environment | Use |
|---|---|---|
| Python | 3.12.10 | Runtime and test execution |
| Flask | 3.1.2 | Local application framework |
| pytest | 8.3.3 | Application behavior and remediation tests |
| Bandit | 1.9.4 | Python static analysis |
| SQLite | Python standard library `sqlite3` | Local application database |

Commands used in the configured Windows environment:

```powershell
C:/Users/Acer/AppData/Local/Programs/Python/Python312/python.exe -m pip install -r requirements.txt
C:/Users/Acer/AppData/Local/Programs/Python/Python312/python.exe -m pytest -q
C:/Users/Acer/AppData/Local/Programs/Python/Python312/python.exe -m bandit -r vulnerable_app
C:/Users/Acer/AppData/Local/Programs/Python/Python312/python.exe -m bandit -r secure_app
```

The dependency-install command completed successfully. The pytest command completed with `13 passed`. The vulnerable scan completed with four findings and exit status 1 (Bandit's normal non-zero status when findings meet its default reporting threshold). The secure scan completed with no findings and exit status 0.

## 5. Findings Summary

| ID | Vulnerability | Severity | Bandit |
|---|---|---|---|
| SCR-01 | SQL injection in user search | Medium | B608, Medium |
| SCR-02 | Reflected XSS in search output | Medium | B704, Medium |
| SCR-03 | Plaintext password storage | Medium | Not detected |
| SCR-04 | Hardcoded Flask signing secret | Medium | B106, Low |
| SCR-05 | Flask debug mode enabled | High | B201, High |
| SCR-06 | Missing CSRF protection on POST forms | Low | Not detected |
| SCR-07 | Missing security-related response headers | Low | Not detected |

Severity describes the potential application risk, considered in the local educational context. Bandit's category is shown separately where it differs.

## 6. Detailed Findings

### SCR-01 — SQL injection in user search

- **Severity:** Medium
- **Affected file:** `vulnerable_app/app.py`
- **Affected function/code area:** `search()`, SQL statement around line 118
- **Description:** The `q` request parameter is inserted directly into a SQL string using an f-string. This lets input change the meaning of the SQLite predicate instead of being handled solely as search data.
- **Security impact:** A crafted local request could alter the search condition and expose more demo usernames than intended, or make the query fail. The demonstrated database contains synthetic local data, so the impact is limited in this project; the same query-construction pattern would be unsafe with sensitive data.
- **Evidence:** `vulnerable_app/app.py` line 118 constructs `SELECT username FROM users WHERE username LIKE '%{term}%'` and executes it. Bandit reports B608 at that statement.
- **Recommended remediation:** Keep SQL structure constant and bind the search pattern as a parameter. Validate the expected search length.
- **Remediation status:** **Remediated** in `secure_app/app.py` around lines 163–174 using `LIKE ?`, a parameter tuple, and a 100-character limit.

### SCR-02 — Reflected cross-site scripting (XSS)

- **Severity:** Medium
- **Affected files:** `vulnerable_app/app.py`; `vulnerable_app/templates/search.html`
- **Affected function/code area:** `search()`, HTML response construction around lines 120–125; search template line 9
- **Description:** Search input is interpolated into HTML and passed to `markupsafe.Markup`, which marks the result as trusted and bypasses Jinja's normal escaping.
- **Security impact:** A browser rendering a crafted search URL can interpret attacker-controlled markup or script in the origin of this local app. This can affect that browser session and undermine user trust. The local-only context and default HttpOnly Flask session cookie reduce but do not eliminate XSS risk.
- **Evidence:** `vulnerable_app/app.py` lines 120–124 interpolate `term` into a `Markup` value; `vulnerable_app/templates/search.html` line 9 renders that value. Bandit reports B704 on the `Markup` call.
- **Recommended remediation:** Do not mark user input as safe HTML. Render values through autoescaped Jinja templates and avoid building HTML strings in route code.
- **Remediation status:** **Remediated** in `secure_app/app.py` around lines 163–180 and `secure_app/templates/search.html`, which render the term and results as ordinary template values. A test verifies markup is escaped.

### SCR-03 — Plaintext password storage

- **Severity:** Medium
- **Affected file:** `vulnerable_app/app.py`
- **Affected function/code area:** `register()` around lines 67–78; `login()` around lines 85–97; users table schema around lines 43–48
- **Description:** Registration stores the submitted password unchanged in the `password` column. Login compares the submitted password directly with that stored value.
- **Security impact:** Anyone who obtains a copy of the SQLite database can read every demo password. This is especially dangerous if users reuse passwords elsewhere. The app is intended for synthetic local accounts, but the pattern is not suitable for real accounts.
- **Evidence:** `vulnerable_app/app.py` line 75 inserts `password` directly; the schema declares a `password` column, and the login query compares against it.
- **Recommended remediation:** Store a salted, adaptive password hash produced by a maintained password-hashing utility; verify with its corresponding check function. Never log or store the raw password.
- **Remediation status:** **Remediated** in `secure_app/app.py` around lines 64, 125–126, and 143–145 with Werkzeug's `generate_password_hash` and `check_password_hash`. Tests verify stored content is not the submitted password and that valid login works.

### SCR-04 — Hardcoded Flask signing secret

- **Severity:** Medium
- **Affected file:** `vulnerable_app/app.py`
- **Affected function/code area:** `create_app()` configuration around line 22
- **Description:** The Flask `SECRET_KEY` is a fixed, source-controlled string. Flask uses this key to sign its client-side session cookies.
- **Security impact:** Anyone who knows the source can forge valid session cookies, including session values used for authentication. The demo key is deliberately fake, but the pattern would put real accounts at risk if copied into an actual deployment.
- **Evidence:** `vulnerable_app/app.py` line 22 assigns a literal string to `SECRET_KEY`.
- **Recommended remediation:** Load a unique, high-entropy secret from deployment configuration, do not commit it, and rotate it if exposed.
- **Remediation status:** **Remediated** in `secure_app/app.py` around line 33: use `SECURE_REVIEW_SECRET_KEY` when configured and generate a random development-only key otherwise. The generated fallback is not stable across restarts; set the environment variable for persistent sessions.

### SCR-05 — Flask debug mode enabled

- **Severity:** High
- **Affected file:** `vulnerable_app/app.py`
- **Affected function/code area:** module entry point around lines 149–151
- **Description:** The development server is explicitly started with `debug=True`. Flask's interactive Werkzeug debugger is not appropriate for an exposed service.
- **Security impact:** If an untrusted party can reach the debugger, it can potentially execute Python code with the server process's privileges. This is High when reachable. The current code binds to `127.0.0.1`, which limits remote reachability, but does not justify enabling the debugger or protect against accidental exposure or local threats.
- **Evidence:** `vulnerable_app/app.py` line 150 calls `app.run(..., debug=True)`. Bandit reports B201 (High).
- **Recommended remediation:** Disable debug mode for execution and use a production-appropriate server/configuration outside local development. Never expose Flask's development debugger.
- **Remediation status:** **Remediated** in `secure_app/app.py` line 206, which explicitly uses `debug=False`.

### SCR-06 — Missing CSRF protection on POST forms

- **Severity:** Low
- **Affected files:** `vulnerable_app/app.py`; `vulnerable_app/templates/register.html`, `login.html`, and `feedback.html`
- **Affected function/code area:** POST handlers `register()`, `login()`, and `feedback()`; corresponding forms
- **Description:** State-changing form handlers accept submissions without checking a per-session anti-CSRF token. The vulnerable templates do not include such a token, and logout changes session state through a GET route.
- **Security impact:** If a victim visits a malicious page while using a compatible browser/session context, that page may cause an unwanted form submission, such as a feedback entry or registration/login action. The demo's limited local functionality reduces impact; this is not presented as an external-system attack.
- **Evidence:** The registration, login, and feedback handlers process `request.method == "POST"` without a CSRF check, their forms contain no token field, and the logout route is a state-changing GET. There is no request-level CSRF validation in the vulnerable app.
- **Recommended remediation:** Use a well-maintained CSRF integration for production forms. For this small demonstration, generate a per-session token, include it in each POST form, and compare it safely on receipt.
- **Remediation status:** **Remediated** in `secure_app/app.py` around lines 75–84 and the POST forms, including logout, with per-session tokens and constant-time comparison. Tests verify missing tokens receive HTTP 400 and that logout requires a valid token.

### SCR-07 — Missing security-related response headers

- **Severity:** Low
- **Affected files:** `vulnerable_app/app.py`; `vulnerable_app/templates/base.html`
- **Affected function/code area:** Application response configuration and base document `<head>`
- **Description:** The vulnerable app does not configure security-related response headers such as a Content Security Policy, frame restrictions, or MIME-sniffing protection.
- **Security impact:** This removes browser defense-in-depth. For example, lack of a frame restriction may permit unwanted framing, and lack of CSP removes a useful mitigation if a markup injection issue is present. Headers alone would not fix the underlying XSS.
- **Evidence:** The vulnerable app has no response header hook, and the base template only declares character encoding and viewport metadata. Manual source inspection found no corresponding header configuration.
- **Recommended remediation:** Set restrictive headers appropriate to the app, including CSP and frame restrictions; keep output encoding and input handling correct as the primary XSS defenses.
- **Remediation status:** **Remediated** in `secure_app/app.py` around lines 87–98 with CSP, `X-Frame-Options`, `X-Content-Type-Options`, and `Referrer-Policy` headers. A test checks key headers.

## 7. Secure Coding Recommendations

- Use parameterized SQL for every value that originates from a request.
- Leave template autoescaping enabled; avoid raw HTML strings and `Markup` for untrusted content.
- Hash passwords using a maintained, salted, adaptive password-hashing implementation.
- Load signing secrets from protected environment/deployment configuration; do not commit secrets.
- Keep debug mode disabled and bind local demonstrations to loopback only.
- Protect browser form submissions against CSRF and set suitable session-cookie options.
- Validate input size and format on the server; browser-side attributes are usability aids, not security controls.
- Set browser security headers as defense-in-depth.
- Handle expected database constraint errors without exposing internal details.
- Use synthetic data and review all scanner findings manually.

## 8. Remediation Summary

`secure_app/` contains the corresponding fixes: bound SQL parameters and bounded search input; autoescaped rendering; password hashing and hash verification; environment-provided or ephemeral development secret; debug mode off; CSRF tokens for POST forms; explicit browser security headers; and username, password-length, search-length, and feedback-length validation.

The secure Bandit scan reported no issues. This means Bandit found no patterns in its configured checks; it is not proof that the application is free of security defects.

## 9. Limitations

- This is a small educational example, not a full production security review or a guarantee of safety.
- The vulnerable app intentionally contains unsafe code and must not be exposed to a network or used with real data.
- Bandit does not analyze all runtime behavior, templates, configuration, or business logic; manual review is necessary.
- pytest verifies selected application behavior using local in-process clients and temporary SQLite files. It does not model browsers, concurrent users, deployment, or every attack scenario.
- The secure app uses a lightweight demonstration CSRF implementation rather than a dedicated production CSRF package.
- `SESSION_COOKIE_SECURE` is false to permit the documented local HTTP demo. Production HTTPS deployments must enable secure cookies and configure a stable secret through deployment secrets.
- Rate limiting, account recovery, email verification, persistent operational monitoring, production server hardening, and a full threat model are outside scope.

## 10. Conclusion

The review found seven genuine, source-backed issues in the intentionally vulnerable application and mapped each to a remediation in the separate secure implementation. All 11 behavior/security checks passed, and Bandit reported four verified patterns in the vulnerable app and zero in the secure app. Use the project to learn review and remediation techniques only in the documented local, synthetic-data setting.
