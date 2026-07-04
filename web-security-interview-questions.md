# Web Security / Penetration Testing Interview Questions

**Interview questions for Web Application Penetration Tester / Web Security Engineer roles.** References: OWASP Top 10 (2021), OWASP Testing Guide, OWASP ASVS 5.0, and general browser-security mechanics (SOP, CORS, CSP, cookies).

## Scope note — how this fits with the other files in this repo
Web security overlaps heavily with application and API security, so to avoid re-explaining the same concept three different ways across files:
- **[Application Security](application-security-interview-questions.md)** owns the SDLC-centric, dev-facing side — secure code review, threat modeling, SAST/DAST/SCA, secure design. This file assumes that context and focuses on the **offensive/exploit mechanics** side: how a browser-facing vulnerability actually works and how a pentester finds and demonstrates it.
- **[API Security](api-security-interview-questions.md)** owns everything specific to API surfaces — BOLA, mass assignment, JWT/OAuth2 attacks, GraphQL-specific risks, API-flavored SSRF. This file covers the **general/foundational** mechanics of shared concepts (CORS, SSRF, session handling) that both files reference; where a concept has a distinctly API-shaped version, that version lives in the API file, not duplicated here.
- This file owns: browser security model fundamentals (SOP/CORS/CSP/cookies), the OWASP Top 10 (web) exploit mechanics, session/authentication attacks against browser-based apps, business-logic and access-control flaws in traditional web apps, and web application penetration-testing methodology and tooling.

## Table of Contents
1. [Browser Security Model Fundamentals](#browser-security-model-fundamentals)
2. [OWASP Top 10 (2021) — Exploit Mechanics](#owasp-top-10-2021--exploit-mechanics)
3. [Session & Authentication Attacks](#session--authentication-attacks)
4. [Web Application Penetration Testing Methodology](#web-application-penetration-testing-methodology)
5. [Scenario-Based Questions](#scenario-based-questions)
   1. [Scenario 1: Stored XSS in a comment field bypasses a client-side filter](#scenario-1-stored-xss-in-a-comment-field-bypasses-a-client-side-filter)
   2. [Scenario 2: CSRF token present but the state-changing action still succeeds](#scenario-2-csrf-token-present-but-the-state-changing-action-still-succeeds)
   3. [Scenario 3: IDOR in a web app's "download my invoice" link](#scenario-3-idor-in-a-web-apps-download-my-invoice-link)
   4. [Scenario 4: Open redirect chained into an OAuth token theft](#scenario-4-open-redirect-chained-into-an-oauth-token-theft)
   5. [Scenario 5: Clickjacking a "delete my account" button](#scenario-5-clickjacking-a-delete-my-account-button)
   6. [Scenario 6: Subdomain takeover via a dangling DNS CNAME](#scenario-6-subdomain-takeover-via-a-dangling-dns-cname)

---

## Browser Security Model Fundamentals

**1. Explain the Same-Origin Policy (SOP), and why almost every web vulnerability class exists because of an SOP bypass or a deliberate, misconfigured relaxation of it.**

SOP is the browser's default rule that a script running on `https://a.com` cannot read the DOM or make arbitrary readable requests to `https://b.com` — origin is defined by scheme + host + port, and any difference in any of the three is a different origin. Almost every classic web vulnerability is either an SOP *bypass* (XSS runs attacker script **inside** the victim origin, so SOP never even applies — the attacker is "inside the house," not trying to break in through the window) or a *deliberate relaxation* of SOP gone wrong (an overly permissive CORS policy, or `postMessage` handling that doesn't verify the sender's origin). Understanding this framing is what separates a candidate who can recite vulnerability names from one who understands *why* the vulnerability landscape looks the way it does.

**2. Explain CORS and the specific misconfiguration pattern that turns it into a vulnerability.**

CORS (Cross-Origin Resource Sharing) is the mechanism by which a server can deliberately tell the browser "it's fine for origin X to read responses from me," relaxing SOP in a controlled way via the `Access-Control-Allow-Origin` (ACAO) response header. The classic misconfiguration: a server that **reflects the request's `Origin` header back as the ACAO value for any origin**, combined with `Access-Control-Allow-Credentials: true` — this tells the browser "any website in the world may make credentialed requests to me and read the response," which defeats the entire purpose of CORS and is functionally equivalent to having no origin restriction at all while looking, at a glance, like a properly configured security control.
```http
# Vulnerable: reflects whatever Origin the browser sent, with credentials allowed
Access-Control-Allow-Origin: https://attacker-controlled-site.com
Access-Control-Allow-Credentials: true

# Hardened: explicit allow-list, never a wildcard or blind reflection when credentials are involved
Access-Control-Allow-Origin: https://app.yourcompany.com
Access-Control-Allow-Credentials: true
```

**3. What is CSP (Content Security Policy) and what's the most common way organizations weaken it into uselessness?**

CSP is a response header that tells the browser which sources of scripts, styles, images, and other resources are allowed to load/execute on the page, acting as a defense-in-depth backstop against XSS even if an injection point exists. The most common way it gets weakened: adding `'unsafe-inline'` and/or `'unsafe-eval'` to the `script-src` directive to avoid refactoring legacy inline `<script>` tags or `eval()`-based code — this single addition re-permits exactly the mechanism (inline script execution) that CSP exists to block, so a CSP header with `'unsafe-inline'` present provides close to zero protection against reflected/stored XSS, even though the header being present at all often shows up as a "pass" on an automated header-checking scan.

**4. What's the difference between `httpOnly`, `Secure`, and `SameSite` cookie attributes, and what specific attack does each mitigate?**

- **`httpOnly`**: The cookie is inaccessible to JavaScript (`document.cookie` can't read it) — mitigates session-cookie theft via XSS specifically (an XSS payload can still make the browser send authenticated requests using the cookie, but can't exfiltrate the cookie's value directly).
- **`Secure`**: The cookie is only ever sent over HTTPS — mitigates interception over an unencrypted/downgraded connection (a network attacker on the same Wi-Fi, or a protocol-downgrade attack).
- **`SameSite`** (`Strict`/`Lax`/`None`): Controls whether the cookie is sent on cross-site requests — `Strict`/`Lax` is the primary modern defense against CSRF (a cross-site form submission or link click won't carry the session cookie at all in most cases), while `None` (which requires `Secure`) explicitly opts back into cross-site sending for cases that genuinely need it (a legitimate third-party embed).

---

## OWASP Top 10 (2021) — Exploit Mechanics

**5. Walk through the mechanics of the three types of XSS and what makes each exploitable differently.**

- **Stored XSS**: Attacker's payload is saved server-side (a comment, a profile field, a support ticket) and served back to *every* subsequent visitor who views that content — highest severity because it requires zero interaction from the specific victim beyond viewing a normal page, and it can compromise many users from a single injection.
- **Reflected XSS**: The payload is part of the request itself (a URL query parameter, a search box submission) and is echoed back unescaped in the immediate response — requires the victim to click a crafted, attacker-supplied link, so it depends on a social-engineering delivery step.
- **DOM-based XSS**: The vulnerability lives entirely in client-side JavaScript that takes some attacker-influenceable source (`location.hash`, `document.referrer`, a `postMessage` payload) and writes it into the DOM via a dangerous sink (`innerHTML`, `document.write`) without server involvement in the vulnerable data flow at all — this is why a purely server-side code review can completely miss a DOM XSS bug; the vulnerable code path never touches the backend.

**6. Explain CSRF end to end: what makes it possible, and why does `SameSite=Lax` (the modern browser default) not fully eliminate it?**

CSRF works because browsers automatically attach cookies (including session cookies) to any request to a domain, regardless of which site/page initiated that request — so a malicious page at `evil.com` can submit a form or trigger a request to `bank.com`, and the victim's browser helpfully attaches their valid `bank.com` session cookie, making the forged request look completely legitimate server-side. `SameSite=Lax` (now the default in modern browsers when unset) blocks cookies on cross-site **POST/state-changing** requests but still allows them on **top-level GET navigation** (clicking a link) — so a CSRF vulnerability reachable via a GET request (a state-changing action incorrectly implemented behind a GET endpoint, which itself is a separate, also-fixable bug) or an application explicitly setting `SameSite=None` for legitimate cross-site needs can still be exploited even with the modern default in place. This is why CSRF tokens remain a recommended defense-in-depth layer rather than something `SameSite` alone fully retires — see Scenario 2 for how a CSRF token being *present* doesn't guarantee it's actually *validated*.

**7. What is SSRF, and how is the general web-application version of this different from the API-specific version already covered elsewhere in this repo?**

SSRF (Server-Side Request Forgery) is when an attacker gets an application's backend to make an HTTP request to a destination of the attacker's choosing, typically reaching internal-only resources the attacker couldn't reach directly. In a general web-app context, this classically shows up in features like PDF/image generation from a URL, webhook configuration, or "fetch a preview of this link" functionality embedded in a traditional server-rendered app. The mechanics and fix are identical to the API-flavored version — see the [full SSRF scenario with code in the API Security file](api-security-interview-questions.md#scenario-6-ssrf-via-a-fetch-this-url-webhookimport-feature) for the complete walkthrough (resolved-IP validation, redirect handling, cloud metadata endpoint protection) rather than duplicating it here.

**8. What's the difference between a broken-access-control finding in a traditional server-rendered web app versus BOLA in an API?**

Conceptually identical — both are "the system failed to verify the authenticated user actually has rights to the specific resource/action requested" — but the *shape* of the bug differs by surface. In a server-rendered web app, this often shows up as **IDOR via URL/form manipulation** (`GET /invoices/1042?user=jsmith` changed to `user=jdoe` in the browser address bar) or a hidden/disabled UI element (an admin-only button removed from the HTML for regular users, but the underlying form action still works if submitted directly) — the vulnerability class is the same as BOLA, but "manipulate a visible URL in the browser" versus "call an API endpoint directly with a modified ID" are different discovery paths worth being able to describe concretely; see Scenario 3 below and the [BOLA scenario in the API Security file](api-security-interview-questions.md#scenario-1-bola-in-a-my-orders-endpoint) for the API-shaped version.

**9. Explain insecure deserialization and why it's often a critical/RCE-level finding rather than "just" a logic bug.**

When an application deserializes data from an untrusted source (a cookie, a hidden form field, an uploaded file) using a language's native serialization format (Java's `ObjectInputStream`, Python's `pickle`, PHP's `unserialize()`), the deserialization process itself can be made to instantiate arbitrary objects and, via "gadget chains" (sequences of existing classes in the application's own dependencies whose constructors/destructors/magic methods can be chained together), execute arbitrary code — this is why insecure deserialization findings frequently escalate straight to remote code execution rather than staying at the level of a data-integrity bug, and why the standard fix is "don't deserialize untrusted data into native object formats at all" (use a safe, structured format like JSON with a fixed schema instead) rather than trying to sanitize the serialized payload.

---

## Session & Authentication Attacks

**10. What is session fixation, and how is it different from session hijacking?**

**Session hijacking** is stealing an already-valid session identifier belonging to a legitimate, already-authenticated user (via XSS, network sniffing, or a leaked log). **Session fixation** is different and often overlooked: the attacker sets a *known* session ID on the victim's browser *before* the victim logs in (e.g., via a URL parameter like `?sessionid=ATTACKER_KNOWN_VALUE` on an app that accepts session IDs from the URL, or a subdomain-shared cookie), and if the application doesn't **regenerate the session ID at the moment of successful authentication**, the victim's now-authenticated session continues using the attacker's pre-chosen ID — meaning the attacker already has a valid, authenticated session identifier the moment the victim logs in, with no theft required at all. The single fix that closes this: always issue a brand-new session identifier immediately upon successful login, discarding whatever pre-authentication session ID existed.

**11. What's a credential-stuffing attack, and why does it succeed even against applications with "strong" individual password policies?**

Credential stuffing uses username/password pairs leaked from **other, unrelated breaches** and replays them against your login endpoint at scale, betting on password reuse across services — it succeeds regardless of how strong your own password policy is, because the credentials being tested were valid, real passwords the user chose (possibly meeting a strong policy) on a *different* site. Defenses target the *behavior* (automated, high-volume login attempts across many usernames) rather than the *strength* of any individual password: rate limiting and progressive delays per account and per source IP, CAPTCHA after a threshold of failures, breached-password-database checking at registration/login (rejecting passwords known to appear in public breach corpora, e.g., via the k-anonymity model used by Have I Been Pwned's API), and — the control that actually neutralizes stolen-password-based attacks structurally — MFA, since a correct stolen password alone is no longer sufficient to authenticate.

**12. Explain a business-logic authentication flaw that automated scanners typically miss, and why manual testing is still essential for this class of bug.**

Automated scanners are pattern-matchers against known payload signatures (SQLi strings, XSS markers) — they have no model of your application's intended business rules, so they can't detect, for example: a multi-step checkout flow where skipping directly to the "confirm order" step (via a saved/replayed request) bypasses a payment-verification step that only the UI enforces; a password-reset flow that emails a reset link to the address on file but also accepts an email address passed as a parameter in the reset-confirmation request, letting an attacker complete the reset for an account of their choosing by simply changing that parameter; or a coupon/discount code endpoint with no check that a single-use code has actually been used before. This is why a real penetration test needs a human who reads and understands the application's intended workflow, not just a scanner run — see the methodology section below.

---

## Web Application Penetration Testing Methodology

**13. Walk through a standard web app penetration test methodology at a high level.**

1. **Scoping & reconnaissance** — define in-scope hosts/functionality, passive recon (subdomain enumeration, technology fingerprinting via response headers/error pages, identifying the framework/CMS in use), and reviewing any provided documentation/architecture diagrams.
2. **Mapping the application** — authenticated and unauthenticated crawl to build a complete map of endpoints, parameters, and roles/permission levels; this is where you build the mental model of "what should be reachable by whom" that later access-control testing depends on.
3. **Automated scanning as a baseline, not the deliverable** — run DAST tooling (Burp Suite, OWASP ZAP) to catch the well-known, pattern-matchable classes (missing security headers, obvious injection points, outdated library fingerprints) quickly, freeing manual effort for the higher-value work scanners can't do.
4. **Manual testing focused on business logic and access control** — the multi-step-workflow and IDOR/broken-access-control classes from Q8 and Q12 that require understanding intent, not just pattern-matching payloads; this is where a skilled human tester provides value a scanner fundamentally cannot.
5. **Exploitation and impact demonstration** — for confirmed findings, demonstrate real-world impact (not just "this parameter reflects unencoded input" but "here is a working payload that exfiltrates another user's session") to make the severity and business risk concrete for the report's audience.
6. **Reporting with actionable, reproducible findings** — each finding needs a clear reproduction path, evidence (request/response pairs, screenshots), severity (commonly CVSS-scored), and a specific remediation recommendation — a report a developer can act on without needing to re-derive what you did.
7. **Retest** — verify fixes actually close the finding rather than just changing its surface symptoms (e.g., confirming the fix addresses the root cause, not just the specific payload used to demonstrate it).

**14. What's the difference between DAST tooling (Burp Suite/OWASP ZAP) and a manual penetration test, and why do organizations need both?**

DAST tools excel at breadth and consistency — they can hit every endpoint with every known payload pattern for injection/XSS/known-CVE fingerprints far faster and more exhaustively than a human, and they're excellent for continuous, automated coverage in a CI/CD pipeline. They're fundamentally limited to what can be pattern-matched, though — they have no concept of your application's intended business logic (Q12), can't reliably chain multiple low-severity findings into a higher-severity exploit path the way a human attacker would, and produce a meaningful false-positive rate that needs human triage regardless. The practical answer: DAST as continuous, automated baseline coverage; periodic manual penetration testing (or ongoing bug bounty) for the business-logic, chained-exploit, and judgment-dependent findings that require a human attacker's mindset.

**15. How would you test for and demonstrate a CSRF vulnerability during a pentest, step by step?**

1. Identify a state-changing action (e.g., "update email address") and capture the legitimate request in an intercepting proxy.
2. Check whether the request includes any CSRF token/nonce; if present, check whether the *server actually validates* it (see Scenario 2 — many implementations generate a token but never check it server-side).
3. Craft a minimal auto-submitting HTML page reproducing the request without the legitimate token (or with a token stripped/reused from a different session) hosted on an attacker-controlled origin.
4. While authenticated to the target application in one browser tab, visit the crafted page in another tab (simulating the victim being lured to a malicious page while logged into the target app) and confirm the state-changing action executes.
5. Document the full reproduction (the HTML PoC page, the request/response, and the observable state change) as evidence, and assess real impact — a CSRF on "change display name" is lower severity than one on "add a new payment recipient" or "change account email/password," even though the underlying vulnerability mechanics are identical.

---

## Scenario-Based Questions

### Scenario 1: Stored XSS in a comment field bypasses a client-side filter

**Setup**: A comment section blocks obvious `<script>` tags via a client-side JavaScript filter before submission. A tester bypasses the browser UI entirely and submits a comment containing `<img src=x onerror=alert(document.cookie)>` directly via the underlying API request, and it renders and executes for every subsequent visitor to that page.

**Root cause**: **Stored XSS** — the actual vulnerability is that the **server** never validates or encodes the comment content on output; the client-side filter was pure security theater; since it runs in the browser and only blocks the specific `<script>` pattern via JavaScript, it does nothing to a request submitted directly (via the API, a proxy tool, or simply disabling JavaScript), and even if it did run, `onerror`-based payloads on non-script tags are a well-known bypass of naive tag-blocklist filtering.

**Fix:**
```javascript
// Vulnerable: server trusts the client-side filter and stores/renders raw input
app.post('/comments', (req, res) => {
  db.comments.insert({ text: req.body.text });   // no server-side validation or encoding at all
});
// template renders: <div>{{comment.text}}</div>   -- if the template engine doesn't auto-escape, this executes

// Hardened: contextual output encoding on render (defense that matters regardless of input filtering),
// plus a CSP as a second independent layer
const escapeHtml = require('escape-html');
app.post('/comments', (req, res) => {
  db.comments.insert({ text: req.body.text });   // store raw text; the encoding happens at output time
});
// template: <div>{{ escapeHtml(comment.text) }}</div>  -- or use a template engine with auto-escaping enabled by default
```
- **Fix output encoding server-side; never rely on client-side filtering as a security control** — anything enforced only in browser JavaScript is trivially bypassed by any client that isn't a browser running your exact JavaScript (a proxy tool, a script, a different browser extension environment), which is exactly how a tester found this in the first place.
- **Use contextual, output-context-aware encoding** (HTML-entity encoding for HTML body context, JavaScript-string encoding if reflected inside a `<script>` block, URL-encoding in a URL context) — the correct encoding differs by *where* in the page the data lands, and using the wrong context's encoding leaves the injection open.
- **Prefer a template engine with auto-escaping enabled by default**, so developers have to deliberately opt out (e.g., an explicit "raw/unescaped" helper) to introduce a vulnerability, rather than opting in to safety on every single output point.
- **Add CSP as an independent second layer** (Q3) — even if an encoding bug slips through in the future, a properly configured CSP without `unsafe-inline` prevents the injected payload from executing, providing defense-in-depth rather than relying on a single control.

---

### Scenario 2: CSRF token present but the state-changing action still succeeds

**Setup**: A tester notices the "change password" form includes a hidden `csrf_token` field. They build a CSRF proof-of-concept page, deliberately omit the token field entirely from the forged request, and the password change still succeeds.

**Root cause**: The application **generates** a CSRF token but never actually **validates** it server-side on the receiving endpoint — a startlingly common gap, because the presence of a token field in the HTML looks like the control is implemented when reviewed superficially (or scanned by a tool checking only for the token's presence in the form), while the server-side check that would make the token meaningful was simply never written or was accidentally removed during a refactor.

**Fix:**
```python
# Vulnerable: token is generated and rendered in the form, but the endpoint never checks it
@app.route('/change-password', methods=['POST'])
def change_password():
    update_password(current_user, request.form['new_password'])   # csrf_token field ignored entirely

# Hardened: the endpoint explicitly validates the token against the session before performing the action,
# and rejects (rather than silently proceeding) if it's missing, malformed, or mismatched
@app.route('/change-password', methods=['POST'])
def change_password():
    submitted_token = request.form.get('csrf_token')
    if not submitted_token or submitted_token != session.get('csrf_token'):
        abort(403, "invalid or missing CSRF token")
    update_password(current_user, request.form['new_password'])
```
- **Validate the token on every single state-changing endpoint, explicitly and consistently** — a CSRF-protection framework feature that has to be manually applied per-route is exactly the design that produces "we have CSRF protection... except on this one endpoint that predates the framework's adoption, or that a developer forgot to decorate."
- **Prefer a framework/middleware that enforces token validation globally by default** for all state-changing HTTP methods, requiring an explicit, auditable opt-out rather than an explicit opt-in per route — this flips the default failure mode from "forgot to protect" to "forgot to exempt," which is a much safer default.
- **Test this exact gap specifically during a review**: don't just check "is there a CSRF token in the form" — actually submit the request with the token stripped, malformed, or replaced with a token from a different session, and confirm the server rejects it; a token's mere presence in markup proves nothing about whether it's enforced.
- **Combine with `SameSite=Lax/Strict` cookies (Q6) as defense-in-depth**, but don't treat either control alone as sufficient — this exact scenario is precisely why relying on a single layer (just the token, or just SameSite) leaves a gap the other layer would have caught.

---

### Scenario 3: IDOR in a web app's "download my invoice" link

**Setup**: A logged-in user's account dashboard has a "Download Invoice" link: `https://app.example.com/invoices/download?invoice_id=8842`. A tester changes `invoice_id` to `8841` in the browser address bar and downloads a different customer's invoice PDF, including their billing address and partial payment details.

**Root cause**: **IDOR / broken access control** — functionally identical to the BOLA scenario in the API Security file, but discovered here through direct browser URL manipulation on a traditional server-rendered download link rather than a raw API call; the server accepts any authenticated session and any `invoice_id` with no check that the requesting user actually owns that specific invoice.

**Fix:**
```python
# Vulnerable: authenticates the session, never checks ownership of the specific requested invoice
@app.route('/invoices/download')
def download_invoice():
    invoice = db.invoices.find_one({"id": request.args.get("invoice_id")})
    return send_file(generate_pdf(invoice))

# Hardened: ownership check scoped into the query itself, identical principle to the API-side fix
@app.route('/invoices/download')
def download_invoice():
    invoice = db.invoices.find_one({
        "id": request.args.get("invoice_id"),
        "customer_id": current_user.id,   # scoped at the query level, not a bolt-on check after fetching
    })
    if invoice is None:
        abort(404)
    return send_file(generate_pdf(invoice))
```
- **Scope every resource-fetch by the authenticated user's identity at the query level** — see the [full BOLA fix walkthrough in the API Security file](api-security-interview-questions.md#scenario-1-bola-in-a-my-orders-endpoint) for the complete reasoning (uniform 404 vs. 403, non-sequential IDs as defense-in-depth, standing regression tests); the fix is identical regardless of whether the vulnerable surface is a REST API endpoint or a traditional web download link.
- **Don't assume a link "hidden" behind a login and only shown for the user's own invoices is sufficient protection** — the UI only showing the correct link doesn't stop a user from directly editing the URL; server-side authorization has to hold regardless of what the UI does or doesn't expose.
- **Test every ID-taking parameter across the entire application systematically**, not just the one a tester happened to notice — this class of bug is rarely isolated to a single endpoint once found, because it usually reflects a missing pattern/convention across the whole codebase rather than one team's individual mistake.

---

### Scenario 4: Open redirect chained into an OAuth token theft

**Setup**: The application has a "continue to partner site" feature: `https://app.example.com/redirect?url=https://partner.com/offer`. A tester notices the `url` parameter isn't validated against an allow-list and can point anywhere, including an attacker-controlled domain. Separately, the application's OAuth login flow uses this same redirect endpoint as part of its `redirect_uri` allow-list (because it's a first-party domain), and the tester chains the two together to steal a real user's OAuth access token.

**Root cause**: An **open redirect** is often dismissed as low severity in isolation ("it just sends you to a different website"), but its real danger is as a **chaining primitive** — here, because the OAuth authorization server was configured to trust `app.example.com` as a valid `redirect_uri` (reasonable on its face, since it's the legitimate first-party domain), and that domain hosts an unrestricted open redirect, the attacker can craft an OAuth authorization URL whose `redirect_uri` points to the trusted domain's open-redirect endpoint, which then forwards the OAuth callback (containing the access token or authorization code) onward to the attacker's own server — the token never leaves the "trusted" redirect_uri host from the authorization server's point of view, so its allow-list check is satisfied while the token still ends up in the attacker's hands.

**Fix:**
```python
# Vulnerable: redirects to any URL the request specifies, no validation at all
@app.route('/redirect')
def redirect_handler():
    return redirect(request.args.get('url'))

# Hardened: validate the destination against an explicit allow-list of known, intended destinations
ALLOWED_REDIRECT_HOSTS = {"partner.com", "trusted-vendor.com"}

@app.route('/redirect')
def redirect_handler():
    target = request.args.get('url')
    parsed = urlparse(target)
    if parsed.hostname not in ALLOWED_REDIRECT_HOSTS:
        abort(400, "redirect destination not permitted")
    return redirect(target)
```
- **Validate every redirect destination against an explicit allow-list of known-good hosts** — never accept and redirect to an arbitrary URL parameter with no validation, even for a feature that feels low-risk in isolation ("it's just sending users to our partner's site").
- **Treat `redirect_uri` allow-listing for OAuth as needing to specify a full, exact path, not just a trusted domain** — an OAuth authorization server's allow-list should match the complete, specific callback path expected, not just "any path on this trusted domain," since exactly this scenario shows that "trusted domain" isn't sufficient if any endpoint on that domain can be abused to relay the token elsewhere.
- **Never assume a finding is "low severity" purely because of its name/category without checking how it chains with the rest of the application** — an open redirect, a CORS misconfiguration, and a permissive `redirect_uri` allow-list are each individually modest findings that combine here into full OAuth token theft; a thorough pentest report should explicitly call out chaining potential, not just list each finding in isolation with its standalone severity.
- **Audit the full list of OAuth `redirect_uri` values registered for your application periodically** — this is exactly the kind of configuration that accumulates cruft over time (a redirect URI added for a one-off integration years ago that nobody remembers exists) and deserves the same "living inventory" treatment as the API-endpoint inventory discussed elsewhere in this repo.

---

### Scenario 5: Clickjacking a "delete my account" button

**Setup**: A tester creates a malicious page that loads the target application's account-settings page inside an invisible `<iframe>`, precisely overlays a fake "claim your free prize" button directly on top of the real, invisible "Delete My Account" button, and gets a test victim to click it — silently triggering the real account-deletion action on the underlying page.

**Root cause**: **Clickjacking (UI redress attack)** — the application doesn't prevent itself from being embedded in an iframe on an arbitrary third-party origin, so an attacker can render the real, fully-functional page invisibly (via CSS opacity/positioning) underneath their own decoy content, tricking a victim into interacting with the real page's controls while believing they're interacting with the decoy — the victim's actual, valid, authenticated click lands on the real button, so no CSRF token or session-validation control catches this at all, since it's a genuine, legitimately-authenticated action from the real user's own browser.

**Fix:**
```http
# Hardened: instruct the browser to refuse to render this page inside any frame at all
X-Frame-Options: DENY

# Modern equivalent (more flexible, supersedes X-Frame-Options where supported), via CSP
Content-Security-Policy: frame-ancestors 'none'
```
```javascript
// Defense-in-depth "framebusting" script for legacy browser support (not sufficient alone,
// since framebusting scripts can themselves sometimes be bypassed) — headers are the real control
if (top !== self) {
  top.location = self.location;
}
```
- **Set `X-Frame-Options: DENY` (or `SAMEORIGIN` if a legitimate same-origin framing use case exists) or the CSP `frame-ancestors` directive on every page**, especially any page hosting a sensitive, single-click, irreversible action — this is a cheap, high-leverage header-level fix for the entire vulnerability class.
- **Pay special attention to any single-click, high-impact action** (account deletion, fund transfer, permission grant) — these are the highest-value clickjacking targets precisely because they require no multi-step confirmation that would otherwise make an invisible-iframe attack harder to pull off in one click.
- **Consider requiring re-authentication or a confirmation step for genuinely irreversible actions** (re-enter password to delete account) as defense-in-depth — this doesn't fix the underlying framing issue but reduces the chance a single disguised click alone can complete the action.
- **Don't rely on JavaScript-based framebusting as your primary control** — historically, various framebusting-bypass techniques have existed (e.g., using the HTML5 `sandbox` attribute on the malicious iframe to suppress the busting script's ability to navigate the top window) — the HTTP header/CSP-based control is enforced by the browser itself before any page script runs, and is the control that should actually be relied on.

---

### Scenario 6: Subdomain takeover via a dangling DNS CNAME

**Setup**: A tester runs a subdomain enumeration tool against your domain and finds `promo.yourcompany.com` has a CNAME record pointing to `yourcompany.herokuapp.com` — but that Heroku application was decommissioned eight months ago and the app name is no longer registered to your organization. The tester registers that exact app name on Heroku for free, and `promo.yourcompany.com` — a real, trusted subdomain of your company — now serves whatever content the tester chooses, on your organization's own domain and TLS certificate trust.

**Root cause**: **Subdomain takeover via a dangling DNS record** — this isn't a bug in application code at all; it's an infrastructure/DNS-hygiene gap where a CNAME (or other DNS record) still points at a third-party service resource (a cloud provider's app-hosting subdomain, a CDN endpoint, an S3 bucket) that was deprovisioned without also removing the DNS record pointing to it, leaving the subdomain name available for anyone to claim on the third-party service. Impact is severe precisely because the takeover happens on your own legitimate, trusted domain — it can be used for convincing phishing (users trust the domain), cookie/session theft if the subdomain shares a parent-domain cookie scope, or bypassing domain-allow-list-based security controls elsewhere that trust `*.yourcompany.com`.

**Fix / prevention:**
```
# The structural gap: a DNS CNAME left pointing to a deprovisioned third-party resource
promo.yourcompany.com.   CNAME   yourcompany.herokuapp.com.   ; app no longer exists — dangling

# Prevention isn't a code fix — it's a decommissioning process fix:
# DNS record removal must be a mandatory, tracked step of resource teardown, not an afterthought
```
- **Make DNS record cleanup a mandatory, tracked step of any resource decommissioning runbook** — the root cause here is almost never malicious; it's a routine deprovisioning where deleting the DNS record was forgotten because the DNS zone is often managed by a different team than the one tearing down the actual cloud resource.
- **Run continuous, automated subdomain-takeover scanning** (open-source tools exist specifically for this — checking known "takeover fingerprints" per cloud provider/service against your full DNS zone) as a standing, scheduled security control, not a one-time pentest finding — DNS hygiene decays continuously as services get spun up and down, so this needs continuous monitoring, not a point-in-time check.
- **Maintain a genuinely current DNS zone inventory with an owner per record** — the same "living inventory" principle applied elsewhere in this repo to API endpoints and vendor access applies directly here: a DNS record with no identifiable owner or clear purpose is a standing risk that should be investigated and removed, not left alone because nobody's sure if it's still needed.
- **Treat any newly-discovered dangling CNAME as urgent regardless of the subdomain's apparent unimportance** — a "promo" or "staging" subdomain that seems low-value is exactly the kind of forgotten resource attackers specifically look for, and once claimed it inherits the full trust (and potentially cookie scope) of your actual production domain.
