# API Security Interview Questions

**Interview questions for API Security Engineer / AppSec-with-API-focus roles.** References: OWASP API Security Top 10 (2023), OWASP ASVS 5.0, and general API architecture practice (REST/GraphQL/gRPC, API gateways, OAuth2/OIDC).

## Scope note — how this fits with the other files in this repo
API security has become its own specialization, distinct from general web security and general application security, so it gets its own file. To avoid duplicating content:
- **[Application Security](application-security-interview-questions.md)** owns the SDLC-centric questions — secure code review, threat modeling, SAST/DAST/SCA, secure design patterns. This file assumes that context and focuses on what's *different* about securing an API surface specifically.
- **[Web Security](web-security-interview-questions.md)** owns general browser/network-facing exploit mechanics (XSS, CSRF, CORS/SOP fundamentals, session cookies). This file only covers those where they take an **API-specific** twist (e.g., CORS misconfiguration on a JSON API, JWT-in-place-of-a-session-cookie issues).
- This file owns: the OWASP API Security Top 10, REST/GraphQL/gRPC-specific vulnerability classes, API authentication/authorization architecture (OAuth2/OIDC/JWT/mTLS), API gateway design, rate limiting, and shadow/undocumented API discovery.

## Table of Contents
1. [Fundamentals](#fundamentals)
2. [OWASP API Security Top 10 (2023)](#owasp-api-security-top-10-2023)
3. [Authentication & Authorization Deep Dive](#authentication--authorization-deep-dive)
4. [GraphQL-Specific Security](#graphql-specific-security)
5. [API Gateway & Platform Architecture](#api-gateway--platform-architecture)
6. [Scenario-Based Questions](#scenario-based-questions)
   1. [Scenario 1: BOLA in a "my orders" endpoint](#scenario-1-bola-in-a-my-orders-endpoint)
   2. [Scenario 2: Mass assignment on a profile-update endpoint](#scenario-2-mass-assignment-on-a-profile-update-endpoint)
   3. [Scenario 3: JWT "alg: none" and key-confusion attack](#scenario-3-jwt-alg-none-and-key-confusion-attack)
   4. [Scenario 4: GraphQL nested-query resource exhaustion](#scenario-4-graphql-nested-query-resource-exhaustion)
   5. [Scenario 5: Shadow API discovered via mobile app teardown](#scenario-5-shadow-api-discovered-via-mobile-app-teardown)
   6. [Scenario 6: SSRF via a "fetch this URL" webhook/import feature](#scenario-6-ssrf-via-a-fetch-this-url-webhookimport-feature)
   7. [Scenario 7: GraphQL field-level authorization bypass through query aliasing](#scenario-7-graphql-field-level-authorization-bypass-through-query-aliasing)
   8. [Scenario 8: gRPC service mesh authenticates every call but authorizes none of them](#scenario-8-grpc-service-mesh-authenticates-every-call-but-authorizes-none-of-them)

---

## Fundamentals

**1. Why does API security get treated as a distinct discipline from "web security" now?**

A traditional web app is mostly consumed by a browser that renders HTML and enforces same-origin policy, cookies, and CSP — a lot of the browser itself acts as a safety net. An API is consumed by arbitrary clients (mobile apps, other backend services, third parties) with **no browser sandbox in the loop at all** — there's no same-origin policy protecting a mobile app's HTTP client, no CSP, often no session cookie (bearer tokens instead). That means authorization has to be enforced entirely server-side, on every single request, with no assist from client-side security mechanisms — which is exactly why **broken object-level authorization (BOLA)** is the #1 API vulnerability year after year: it's a purely server-side check that's easy to forget precisely because nothing on the client side would have caught it either.

**2. What's the practical security difference between REST, GraphQL, and gRPC APIs?**

- **REST**: Resource-oriented, one endpoint per resource/action, authorization is naturally scoped per-endpoint but has to be re-implemented consistently across every endpoint — the risk is inconsistency (endpoint #47 forgot the ownership check that the other 46 have).
- **GraphQL**: A single endpoint exposes a full query language over your data graph — authorization has to happen at the **field/resolver level**, not the endpoint level, and the flexible query structure creates unique resource-exhaustion risks (deeply nested queries, query batching) that don't exist in REST. See the GraphQL section below.
- **gRPC**: Binary protocol (Protobuf), typically internal service-to-service — the risk profile shifts toward service identity/mTLS and schema/contract security rather than the classic REST injection surface, but object-level authorization (does this calling service have rights to this object) still applies identically.

**3. What's the difference between authentication and authorization in an API context, and why do interviewers ask candidates to distinguish them?**

Authentication answers "who is making this call" (a valid API key, JWT, or mTLS client cert); authorization answers "is this authenticated caller allowed to do *this specific thing to this specific resource*." The reason this distinction gets tested constantly in API security interviews: the single most common real-world API vulnerability class (BOLA, OWASP API1) is a system that authenticates perfectly (the token is 100% valid) but never re-checks authorization against the specific object being requested — an interviewer asking this is checking whether you understand that "the request had a valid token" and "this request should be allowed" are two completely separate checks.

**4. What is BOLA (Broken Object-Level Authorization), and why is it still the #1 API vulnerability years after being named?**

BOLA (formerly commonly called IDOR — Insecure Direct Object Reference) happens when an API endpoint takes an object identifier from the request (`GET /api/orders/12345`) and returns/modifies that object **without verifying the authenticated caller actually owns or has rights to it**. It stays #1 because it's a missing check, not a present-but-wrong one — nothing crashes, no error is thrown, the endpoint works perfectly for every legitimate call, and it's invisible in code review unless the reviewer specifically asks "wait, where's the ownership check for this ID?" for every single object-returning endpoint.

**5. What's mass assignment, and why do modern web frameworks make it easy to introduce by accident?**

Mass assignment happens when an API endpoint binds the entire incoming JSON body directly to an internal data model/ORM object, so any field the client includes — even ones the UI never exposes, like `"role": "admin"` or `"account_balance": 999999` — gets written if the underlying field exists on the model and there's no explicit allow-list. Frameworks that offer convenient auto-binding (`Model.update(req.body)`) are optimizing for developer speed, and that convenience is exactly the vulnerability: the fix (explicit field allow-listing on every write endpoint) is one extra line that's easy to skip when the "just bind the whole object" version already works in testing.

**6. How should rate limiting be designed differently for an API than for a web login form?**

A login-form rate limit is usually IP- or account-based and exists mainly to slow brute force. An API's resource-consumption risk is broader (OWASP API4: Unrestricted Resource Consumption) — a single authenticated, legitimate-looking client can still cause damage via expensive queries, large result-set pagination, bulk export endpoints, or file-upload size, none of which look like "attack traffic" in a simple IP-rate-limit sense. API rate limiting needs to be **per-identity (API key/token, not just IP), tiered by endpoint cost** (an expensive search/export endpoint gets a much tighter budget than a cheap health-check), and paired with hard caps on response size/pagination/computation, not just requests-per-minute.

---

## OWASP API Security Top 10 (2023)

**7. Walk through the current OWASP API Security Top 10 and the core idea behind each.**

| # | Risk | Core idea |
|---|---|---|
| API1 | Broken Object Level Authorization (BOLA) | Endpoint returns/modifies an object by ID with no ownership check |
| API2 | Broken Authentication | Weak token issuance/validation, missing token expiry, credential stuffing on API endpoints not covered by the same protections as the web login |
| API3 | Broken Object Property Level Authorization | Even with correct object-level access, individual *fields* aren't scoped (mass assignment on write, over-exposure of sensitive fields on read) |
| API4 | Unrestricted Resource Consumption | No limits on request rate, payload size, response size, or computational cost per request |
| API5 | Broken Function Level Authorization | A regular user can call an admin-only endpoint because the endpoint doesn't check role, only that *some* valid token was presented |
| API6 | Unrestricted Access to Sensitive Business Flows | No abuse-protection on business logic (e.g., unlimited automated purchases of a limited-stock item, unlimited coupon-code generation) even though each individual API call is "valid" |
| API7 | Server-Side Request Forgery (SSRF) | An API feature that fetches a user-supplied URL (webhooks, imports, link previews) gets used to reach internal-only endpoints |
| API8 | Security Misconfiguration | Verbose error messages/stack traces, default credentials, unnecessary HTTP methods enabled, missing security headers, permissive CORS |
| API9 | Improper Inventory Management | Old/deprecated/undocumented ("shadow") API versions still live and unprotected, differing security postures between versions |
| API10 | Unsafe Consumption of APIs | Your backend blindly trusts data/responses coming *from* third-party APIs you integrate with, without the same validation you'd apply to user input |

**8. API3 (Broken Object Property Level Authorization) is new-ish naming — how is it different from API1 (BOLA)?**

API1 is about the **object** as a whole ("can this user access order #12345 at all?"). API3 is about **individual fields within an object the user is otherwise allowed to access** — e.g., a user can legitimately view their own profile (API1 check passes), but the response also includes an internal `risk_score` field never meant to be exposed, or the update endpoint lets them write to a `role` field they should never be able to set (this overlaps with mass assignment, Q5). The distinction matters because the fix is different: API1 is fixed with an ownership check before returning the object at all; API3 is fixed with an explicit allow-list of *which fields* are readable/writable, applied even after the object-level check has already passed.

**9. Explain API6 (Unrestricted Access to Sensitive Business Flows) with a concrete example — how is this different from just "add rate limiting"?**

Take a flash-sale endpoint for limited-stock inventory: standard rate limiting (X requests per minute per token) might be satisfied by an attacker running many accounts/tokens in parallel, each individually under the rate limit, to buy up the entire stock via bots before real customers can act — each individual API call is completely valid and within any per-token rate limit, so simple rate limiting doesn't catch it. This needs **business-flow-aware protection**: CAPTCHA or proof-of-work at the specific high-value flow, device/behavioral fingerprinting to detect coordinated multi-account abuse, purchase-velocity limits tied to account age/history rather than just request count, and monitoring specifically for the business outcome ("stock depleted in 4 seconds by 200 different new accounts" is the signal, not "any single account exceeded a rate limit").

**10. API10 (Unsafe Consumption of APIs) — why is this in a Top 10 that's mostly about *your* API being attacked?**

Because your backend is also a *client* of other APIs (payment processors, data enrichment services, partner integrations), and teams frequently apply rigorous input validation to data coming from end users while implicitly trusting data coming back from a third-party API response — following redirects blindly, deserializing responses without validation, or trusting a webhook payload's content without verifying its signature. The mental model: **any data source you don't fully control is untrusted input**, whether it arrived via a user's browser or via another company's API response, and needs the same validation discipline either way.

---

## Authentication & Authorization Deep Dive

**11. Compare API keys, OAuth2 bearer tokens, and mutual TLS (mTLS) as API authentication mechanisms — when would you use each?**

- **API keys**: Simple, good for service-to-service or partner integrations with coarse-grained trust; weak on their own because a leaked key is a static, long-lived credential with no built-in expiry or scope — pair with IP allow-listing and short rotation cycles if used at all for anything sensitive.
- **OAuth2 bearer tokens (often JWTs)**: The standard for user-delegated access (a mobile app acting on behalf of a logged-in user) — supports scopes, expiry, and refresh flows, but a bearer token is exactly what its name says: whoever *bears* it can use it, so token theft (via XSS, insecure storage, or a leaked log) is equivalent to full account compromise for that token's scope and lifetime.
- **mTLS**: Strong service identity for service-to-service communication (each service has a certificate, both sides authenticate each other) — excellent for internal microservice-to-microservice trust (ties directly into the service-mesh pattern from zero-trust architecture), but heavier operationally (certificate issuance/rotation infrastructure) and not practical for public, arbitrary third-party API consumers.

**12. What should a security review specifically check about JWT usage in an API?**

- **Algorithm confirmation, not just signature presence**: verify the server-side validation code hard-codes the expected algorithm (e.g., RS256) rather than trusting an `alg` field from the token itself — this is exactly the `alg: none` / algorithm-confusion vulnerability class (see Scenario 3).
- **Expiry (`exp`) enforcement and reasonable token lifetime** — a JWT with no expiry, or a 1-year expiry, turns any single leaked token into a near-permanent credential.
- **Revocation strategy** — JWTs are stateless by design, which means there's no built-in way to invalidate one before its natural expiry; check whether the system has a real answer for "user's account is compromised right now, how do we kill their existing valid tokens" (a short-lived-access-token + revocable-refresh-token pattern, or a server-side deny-list for the (rare) case of needing immediate revocation).
- **What's actually inside the token** — sensitive data (PII, internal roles/permissions beyond what's needed) shouldn't be stuffed into a JWT payload just because it's convenient, since a JWT's payload is base64-encoded, not encrypted, and readable by anyone who intercepts or is handed the token.
- **Where it's stored client-side** — a JWT stored in `localStorage` is readable by any XSS on that origin (this is where the API-specific version of a web-security concept lives — see the [Web Security file](web-security-interview-questions.md) for the general XSS mechanics); an httpOnly cookie is safer against XSS but reopens CSRF considerations for browser-based clients.

**13. What is Broken Function Level Authorization (API5) and how does it differ from BOLA (API1) in practice?**

BOLA (API1) is about **which object** a user can act on (their own order vs. someone else's). Broken Function Level Authorization (API5) is about **which functionality/endpoint** a user can call at all, regardless of object — e.g., a regular user's valid token can successfully call `POST /api/admin/users/{id}/promote` because the endpoint only checks "is this a valid authenticated token" and never checks "does this token's role include admin." The practical review technique: enumerate every endpoint by intended role (public / authenticated-user / admin / service-only) and explicitly test whether a lower-privileged token can call a higher-privileged endpoint — this is the single most effective, cheap manual test for API5 and is frequently missed because admin endpoints are "not supposed to be found" rather than actually being access-controlled.

---

## GraphQL-Specific Security

**14. Why does GraphQL need a fundamentally different authorization approach than REST?**

In REST, one endpoint typically returns one shape of data, so an authorization check at the endpoint/controller level covers that endpoint's data. In GraphQL, a single query can traverse arbitrary, client-composed paths through your entire data graph in one request (`user { orders { items { supplier { internalCostPrice } } } }`) — authorization has to be enforced **at the resolver/field level** for every field in the schema, because the client controls which combination of fields and nested relationships get requested, and endpoint-level authorization simply has no equivalent granularity to hook into.

**15. What's a GraphQL-specific denial-of-service risk that doesn't have a direct REST equivalent, and how do you defend against it?**

**Deeply nested/recursive queries and query batching** — because GraphQL lets a client request arbitrarily nested relationships in a single call, a query like repeatedly nesting `friends { friends { friends { friends { ... } } } }` can force the server to perform exponentially expanding work from what looks like one small request. Defenses: enforce a maximum query depth and complexity score (assign a "cost" to each field/resolver and reject queries exceeding a total budget) at the GraphQL layer specifically, disable/limit query batching and introspection in production, and apply per-query timeout and result-size caps in addition to standard per-client rate limiting — see Scenario 4 for a concrete walkthrough.

---

## API Gateway & Platform Architecture

**16. What security responsibilities belong at the API gateway, versus inside each individual service?**

The gateway is the right place for **coarse-grained, cross-cutting** controls: TLS termination, coarse authentication (is there a valid token at all), schema/contract validation (reject malformed requests before they reach application code), global rate limiting, and centralized logging. It is the **wrong** place to stop — **fine-grained, resource-level authorization** (does *this* caller have rights to *this specific* object — the BOLA check) has to happen inside the service itself, because the gateway generally doesn't have the business-logic context (ownership relationships, current object state) needed to make that call correctly. Treating gateway-level auth as sufficient and skipping the in-service object-level check is the single most common real-world path to a BOLA vulnerability at organizations that have "already solved" auth at the gateway.

**17. How do you prevent "shadow APIs" — undocumented or forgotten endpoints — from becoming your biggest blind spot?**

Shadow APIs (OWASP API9: Improper Inventory Management) accumulate from old app versions still calling deprecated backend versions, internal debug/admin endpoints that were never meant to ship but did, and endpoints created for one-off integrations that outlived their original purpose and got forgotten. Defenses: route **all** traffic through the API gateway so there's a single point where every live endpoint is observable (services that expose endpoints directly, bypassing the gateway, are exactly how shadow APIs form); run continuous API discovery/traffic analysis to compare what's actually being called against what's in your documented API inventory and investigate every gap; and enforce an explicit deprecation and sunset policy with a hard technical cutoff date (see the API versioning discussion in the [Security Architect scenarios](Security_Architect_Scenario_Questions.md#scenario-8-designing-a-secure-api-architecture-for-a-public-facing-platform)) rather than "old versions" quietly staying reachable forever because nobody wants to be the one to turn them off.

---

## Scenario-Based Questions

### Scenario 1: BOLA in a "my orders" endpoint

**Setup**: `GET /api/v1/orders/{order_id}` returns order details for a logged-in user's mobile app. A security researcher changes the `order_id` in an otherwise normal, authenticated request from their own order (`54321`) to a sequential neighbor (`54322`) and gets back a full stranger's order — items, shipping address, and the last 4 digits of their payment card.

**Root cause**: Classic **BOLA (OWASP API1)** — the endpoint correctly authenticates the caller (valid token) but never checks whether the authenticated user actually owns `order_id`. Sequential, guessable numeric IDs make this trivially easy to exploit at scale (script through a range of IDs), but the vulnerability exists even with random IDs — it's just harder to enumerate.

**Fix:**
```python
# Vulnerable: authenticates the caller, never verifies ownership of the requested object
@app.get("/api/v1/orders/{order_id}")
def get_order(order_id: str, current_user: User = Depends(get_current_user)):
    order = db.orders.find_one({"id": order_id})   # any valid token can fetch any order by ID
    return order

# Hardened: ownership check is part of the query itself, not a separate afterthought check
@app.get("/api/v1/orders/{order_id}")
def get_order(order_id: str, current_user: User = Depends(get_current_user)):
    order = db.orders.find_one({"id": order_id, "customer_id": current_user.id})  # scoped at the query level
    if order is None:
        raise HTTPException(404)   # same 404 whether the order doesn't exist or isn't theirs — don't leak which
    return order
```
- **Scope every object-fetch query by the authenticated caller's identity at the database-query level**, not via a separate `if` check after fetching — building the ownership constraint into the query itself means there's no code path where the object can be fetched without it.
- **Return an identical response (404, not 403) for "doesn't exist" and "not yours"** — a 403 confirms the object exists and belongs to someone else, which itself leaks information (useful for enumeration) that a uniform 404 doesn't.
- **Use non-sequential, non-guessable IDs (UUIDs) as defense-in-depth** — this doesn't fix the underlying missing authorization check, but it does eliminate trivial mass-enumeration as an amplification factor while the real fix is being verified.
- **Make this a standing automated test, not a one-off finding**: for every object-returning endpoint, an automated test suite entry that authenticates as user A and attempts to fetch user B's known object ID, asserting a 404 — run on every PR touching that endpoint, since this exact class of bug reintroduces itself easily during refactors.

---

### Scenario 2: Mass assignment on a profile-update endpoint

**Setup**: `PATCH /api/v1/users/me` lets a logged-in user update their own profile (name, email, notification preferences). A user notices the API accepts a JSON body, and out of curiosity includes `"account_tier": "enterprise"` in the request body alongside their name change — and their account is instantly upgraded to enterprise tier for free, with no purchase.

**Root cause**: **Mass assignment (rolls into OWASP API3, Broken Object Property Level Authorization)** — the endpoint binds the entire request body directly onto the user's database model with no allow-list of which fields a user is permitted to modify about their own record. The object-level check (they can only modify *their own* user record) is actually fine here — the bug is at the field level: some fields on that same object (`account_tier`, potentially `role`, `email_verified`) should never be client-writable at all, regardless of whose object it is.

**Fix:**
```javascript
// Vulnerable: entire request body bound directly to the user model
app.patch('/api/v1/users/me', authenticate, (req, res) => {
  User.findByIdAndUpdate(req.user.id, req.body);   // whatever fields the client sends, all get written
});

// Hardened: explicit allow-list of client-writable fields, everything else is ignored regardless of what's sent
const USER_EDITABLE_FIELDS = ['name', 'email', 'notification_preferences'];

app.patch('/api/v1/users/me', authenticate, (req, res) => {
  const updates = pick(req.body, USER_EDITABLE_FIELDS);   // only these fields ever reach the model, by construction
  User.findByIdAndUpdate(req.user.id, updates);
});
```
- **Default to an explicit allow-list of writable fields per endpoint, never a blanket bind of the request body** — this needs to be a standard/lint-enforced pattern across the codebase, not something each developer remembers to do case by case, since the convenient "just bind the whole object" approach will keep reappearing under deadline pressure otherwise.
- **Sensitive/privileged fields (role, tier, verification status, balance) should have their own dedicated, separately-authorized endpoint** (e.g., `account_tier` changes only through a payment-confirmation-triggered internal service call, never through the general profile-update endpoint at all) rather than being merely excluded from one allow-list and potentially reachable through another endpoint that forgot the same exclusion.
- **Test explicitly for this class of bug**: for any write endpoint, a standing test that sends every field name that exists on the underlying model (not just the documented ones) and asserts that undocumented/privileged fields are silently ignored, not silently accepted.

---

### Scenario 3: JWT "alg: none" and key-confusion attack

**Setup**: A penetration test against your API's authentication reports that they were able to forge a valid-looking JWT for any user ID of their choosing, with no knowledge of your signing key, and the API accepted it.

**Root cause**: This is almost always one of two well-known JWT implementation bugs: (1) the server's JWT validation library trusts the `alg` field embedded in the (attacker-controlled) token header rather than enforcing a fixed expected algorithm — setting `"alg": "none"` on some libraries causes signature verification to be skipped entirely; or (2) an **RS256-to-HS256 key-confusion attack** — the server is configured to accept both RS256 (asymmetric, public/private key) and HS256 (symmetric, single shared secret) tokens, and the attacker signs a forged token with HS256 using the server's **public key** (which is, by definition, public) as the HS256 shared secret — a library that doesn't strictly separate which algorithm is expected per key type will incorrectly validate this forged token as legitimate.

**Fix:**
```python
# Vulnerable: trusts whatever algorithm the token header claims, or accepts multiple algorithm families
payload = jwt.decode(token, key, algorithms=["RS256", "HS256", "none"])   # never do this

# Hardened: hard-code the single expected algorithm server-side; never take it from the token itself
payload = jwt.decode(token, PUBLIC_KEY, algorithms=["RS256"])   # exactly one algorithm, explicitly pinned
```
- **Hard-code the expected algorithm in your verification call, and reject anything else outright** — never derive the verification algorithm from the incoming token's own header, since that header is fully attacker-controlled before signature verification even happens.
- **Never configure a single verification endpoint to accept both symmetric (HS256) and asymmetric (RS256) algorithms** — if you need both for different purposes, use separate keys and separate, explicitly-scoped verification paths so a public asymmetric key can never be reinterpreted as a symmetric secret.
- **Use a well-maintained, current JWT library and keep it updated** — the `alg: none` and key-confusion bugs are old, well-known, and patched in current versions of major libraries; this class of finding in a modern pentest usually points to either a very old library version or custom hand-rolled JWT handling, both of which are worth flagging as findings in their own right.
- **Keep token lifetime short and pair with a genuinely revocable refresh-token pattern** (Q12) as defense-in-depth — even with perfect signature validation, a short-lived access token limits the damage window of any future, currently-unknown JWT implementation bug.

---

### Scenario 4: GraphQL nested-query resource exhaustion

**Setup**: Your social-networking API exposes a GraphQL endpoint. A single request from one client — well within any per-minute rate limit — takes your database cluster from a comfortable baseline to fully saturated CPU for several minutes, degrading the service for everyone else.

**Root cause**: A **GraphQL nested-query resource-exhaustion attack** (the API-flavor of OWASP API4, Unrestricted Resource Consumption) — the query nested a relationship field many levels deep (`user { friends { friends { friends { posts { comments { author { friends { ... } } } } } } } }`), and because each level fans out to potentially hundreds of results from the previous level, the total resolved work grows combinatorially even though it's syntactically one request that easily clears a simple per-minute rate limit.

**Fix:**
```javascript
// Vulnerable: no limit on query depth or computed cost — the schema allows arbitrary nesting
const server = new ApolloServer({ typeDefs, resolvers });

// Hardened: enforce maximum depth and a computed complexity budget before executing any query
const depthLimit = require('graphql-depth-limit');
const costAnalysis = require('graphql-cost-analysis');

const server = new ApolloServer({
  typeDefs,
  resolvers,
  validationRules: [
    depthLimit(6),                                  // hard ceiling on nesting depth
    costAnalysis({ maximumCost: 1000, defaultCost: 1, variables: {} }),  // per-field cost budget, rejects before execution
  ],
});
```
- **Enforce a maximum query depth and a computed complexity/cost limit at the schema-validation layer**, rejecting oversized queries before any resolver executes — depth alone isn't sufficient (a shallow but wide query can be equally expensive), so cost analysis assigning weight per field/connection is the more robust control.
- **Disable introspection and query batching in production** unless specifically required for a trusted internal client — introspection makes it trivially easy for an attacker to map your entire schema and find the most expensive possible query path, and batching lets many expensive queries be smuggled into what looks like one request.
- **Apply per-query execution timeouts and result-size caps independent of the cost-analysis estimate** — cost analysis is an estimate; a hard runtime timeout is the backstop for when the estimate is wrong.
- **Use persisted queries (an allow-list of pre-approved, pre-analyzed query shapes) for public-facing GraphQL APIs where the client set is known** (your own mobile app, not arbitrary third parties) — this eliminates the open-ended "client can compose any query" attack surface entirely for that use case, trading GraphQL's query flexibility for a much smaller, auditable attack surface.

---

### Scenario 5: Shadow API discovered via mobile app teardown

**Setup**: A security researcher decompiles your public mobile app's binary and finds it calling `https://api.internal.yourcompany.com/v2/debug/dump-user-session?user_id=X` — an endpoint that was built for internal debugging during development, was never intended to ship, has no authentication at all, and returns full session data for any user ID.

**Root cause**: **Improper Inventory Management (OWASP API9)** — an endpoint that was never part of the intended, documented, reviewed API surface made it into a production build and stayed reachable with no security review ever having been applied to it, because it wasn't in anyone's inventory of "endpoints that need a security review." This is a distinct failure mode from BOLA (Scenario 1): there the endpoint was known and reviewed but had a logic gap; here the endpoint was **never on anyone's radar at all**.

**Fix / prevention going forward:**
```yaml
# The structural fix: route every endpoint through the gateway, and fail closed
# for anything not explicitly registered in the API inventory/contract
gateway_policy:
  default_action: deny            # nothing reachable unless explicitly registered
  registered_routes:
    - path: /v2/orders/{id}
      auth_required: true
      reviewed: true
    - path: /v2/debug/dump-user-session
      status: BLOCKED              # discovered via inventory audit — never should have shipped
```
- **Route all traffic through a single API gateway with a default-deny policy** — an endpoint that isn't explicitly registered and reviewed simply isn't reachable, which structurally prevents "debug endpoint accidentally shipped" from becoming exploitable even if it accidentally makes it into a production build.
- **Strip or gate debug/development-only endpoints at build time, not by convention** — a build pipeline check that fails the production build if any route tagged `debug`/`internal-only` is present, rather than relying on developers remembering to remove them before shipping.
- **Run continuous API discovery against your own production traffic and mobile app binaries**, comparing what's actually being called against your documented, reviewed API inventory, and treat any gap as an incident to investigate immediately, not a routine cleanup item.
- **Assume mobile app binaries will be decompiled — because they will be** — never rely on "the endpoint URL isn't publicly documented" as a security control; any endpoint your own app calls is discoverable by anyone willing to decompile the binary, so the only real protection is proper authentication/authorization on the endpoint itself.

---

### Scenario 6: SSRF via a "fetch this URL" webhook/import feature

**Setup**: Your API offers a "import data from a URL" feature — users provide a URL, and your backend fetches and processes the content. A security researcher submits `http://169.254.169.254/latest/meta-data/iam/security-credentials/` (the cloud instance metadata service address) as the "import URL" and your API dutifully fetches it and includes the response — your production server's actual IAM credentials — in the error message returned to the user.

**Root cause**: **Server-Side Request Forgery (OWASP API7)** — any feature where the backend makes an outbound HTTP request to a user-supplied URL is a potential SSRF vector, because the backend server sits inside your trusted network perimeter and can reach internal-only resources (cloud metadata services, internal admin panels, other internal services with no external-facing authentication) that the external user could never reach directly. This is one of the highest-severity findings in modern cloud environments specifically because cloud instance metadata endpoints often hand out live, usable credentials to anything on the instance's network that asks.

**Fix:**
```python
import ipaddress
import socket
from urllib.parse import urlparse

BLOCKED_NETWORKS = [
    ipaddress.ip_network("169.254.0.0/16"),   # link-local, includes cloud metadata services
    ipaddress.ip_network("127.0.0.0/8"),      # loopback
    ipaddress.ip_network("10.0.0.0/8"),       # private ranges
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]

def is_safe_url(url: str) -> bool:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return False
    resolved_ip = ipaddress.ip_address(socket.gethostbyname(parsed.hostname))  # resolve BEFORE fetching, check the real IP
    return not any(resolved_ip in net for net in BLOCKED_NETWORKS)

def import_from_url(user_supplied_url):
    if not is_safe_url(user_supplied_url):
        raise ValueError("URL resolves to a disallowed internal address")
    # Also: disable redirect-following, or re-validate the destination on every redirect hop
    return requests.get(user_supplied_url, allow_redirects=False, timeout=5)
```
- **Validate the resolved IP address, not just the URL string** — checking the hostname/URL for "looks internal" is insufficient because DNS rebinding lets an attacker register a public domain that resolves to `127.0.0.1` or `169.254.169.254` at fetch time; resolve DNS yourself and check the actual IP against a blocked-ranges list before making the request.
- **Disable automatic redirect-following, or re-validate the destination IP on every single redirect hop** — a URL that passes validation (points to an allowed external host) can still redirect to an internal address, and most HTTP client libraries follow redirects by default without re-running your validation logic.
- **Use a dedicated network egress path for outbound fetches from this kind of feature** (a proxy or dedicated subnet with no route to internal/metadata addresses) as defense-in-depth, so even a validation-logic bug doesn't grant a path to internal resources.
- **Disable or v2-only cloud instance metadata service access where your cloud provider supports it** (e.g., AWS IMDSv2, which requires a session token via a PUT request that most naive SSRF payloads can't perform) — this is an infrastructure-level control that meaningfully raises the bar even if an application-level SSRF bug exists.
- **Never reflect a fetched response's raw content back to the requesting user**, especially in error messages/debug output — even with the URL-validation fix in place, treat "don't echo internal fetch results back to the external caller" as an independent defense-in-depth layer.

---

### Scenario 7: GraphQL field-level authorization bypass through query aliasing

**Setup**: Your GraphQL API correctly enforces object-level authorization on the `salary` field of an `Employee` type — a resolver-level check confirms the requesting user is either the employee themselves or their direct manager before returning that field. A penetration test reports they extracted every employee's salary in the company anyway, using a single query that aliases the same field query many times over with different employee IDs, discovering that the authorization check was actually implemented once at the **query root**, not inside the field resolver itself — so it only validated the *first* employee referenced in the request, and every subsequent aliased sub-query slipped through unchecked.

**Root cause**: This is **Broken Object Level Authorization (OWASP API1) manifesting through a GraphQL-specific mechanism** — query aliasing lets a single request ask for the same field multiple times against different arguments in one round trip (`emp1: employee(id: "A") { salary } emp2: employee(id: "B") { salary }`), and if the authorization check is bolted on at a single, top-level middleware/gateway layer rather than genuinely re-executed **inside the resolver for every single field/object instance resolved**, aliasing turns "we checked authorization once" into "we checked authorization for the first of N objects and silently trusted the rest." This is exactly the GraphQL-shaped version of the general principle from Q14: authorization has to live at the resolver level because the client controls arbitrarily-shaped, arbitrarily-repeated traversals of the graph in a single request.

**Fix:**
```javascript
// Vulnerable: authorization checked once, at the query-root level, assuming one employee per request
const resolvers = {
  Query: {
    employee: async (_, { id }, context) => {
      await authorizeOnce(context.user, id);   // runs once per resolved root field call... but see below
      return db.employees.findById(id);
    },
  },
  Employee: {
    salary: (employee) => employee.salary,   // no independent check here — trusts that Query.employee already did it
  },
};
// Aliasing (emp1: employee(id:"A"){salary} emp2: employee(id:"B"){salary}) calls Query.employee
// twice, once per alias — so this actually *does* re-run per alias in most engines. The real-world
// version of this bug is subtler: a DataLoader/batching layer that fetches multiple employees in
// one batched DB call and applies the authorization check against only the *first* ID in the batch,
// or a resolver that memoizes/caches the authorization result per request instead of per object.

// Hardened: authorization check runs inside the field resolver itself, per object instance,
// with no caching/memoization across different object IDs within the same request
const resolvers = {
  Employee: {
    salary: async (employee, _, context) => {
      const authorized = await authorize(context.user, "read:salary", employee.id);  // per-instance, every time
      if (!authorized) return null;   // or throw, per your API's error-handling convention
      return employee.salary;
    },
  },
};
```
- **Enforce authorization inside the field resolver for every sensitive field, keyed to the specific object instance being resolved** — never assume a check performed on the query's root field, or on the first item in a batch, covers every object the query ultimately touches; GraphQL's aliasing and nested-selection capabilities mean a "one check per request" mental model is the wrong mental model entirely.
- **Audit any DataLoader/batching layer specifically for this exact bug**: batching (fetching many objects' data in one underlying DB call for efficiency) is a common, legitimate GraphQL performance pattern, but if the authorization check was written against the batch as a whole (or against the first/primary ID) rather than per resolved item, batching silently reintroduces this vulnerability even when the naive single-object resolver code looks correct.
- **Test explicitly with aliased and batched queries, not just single-object queries**, during both development and pentest — a manual test that only ever requests one object per query will never trigger this class of bug, since it's specifically the multi-object, single-request shape that exposes the gap.
- **Prefer a schema-directive-based or centralized authorization framework** (e.g., a `@requiresRole` / `@authz` directive applied declaratively on sensitive fields in the schema definition, enforced by the GraphQL engine itself before resolution) over hand-rolled per-resolver checks — a declarative, engine-enforced approach is far less likely to have a batching/aliasing-shaped gap than authorization logic scattered across individually-written resolver functions.
- **Log field-level access to sensitive data (who read which employee's salary, when) independent of whether the request "looked normal"** — this is what makes a bulk-exfiltration-via-aliasing attack detectable after the fact even if it's missed at request time, since the access pattern (one account reading hundreds of salary fields in a short window) is a strong anomaly signal regardless of how the underlying query was shaped.

---

### Scenario 8: gRPC service mesh authenticates every call but authorizes none of them

**Setup**: Your internal microservices communicate over gRPC through a service mesh (mTLS enforced everywhere, every service has a verified certificate identity). During an incident investigation, you discover the `billing-service` accepted and processed a `VoidInvoice` RPC call originating from the `recommendation-service` — a service that has no legitimate business reason to ever call that method — and nothing in the architecture would have prevented it, because "the mesh handles security" had been the team's mental model from day one.

**Root cause**: This is **Broken Function Level Authorization (OWASP API5)** at the service-to-service layer — mTLS via the service mesh is a strong **authentication** control (every service can cryptographically prove its identity to every other service), but authentication alone answers "who is calling," not "should this specific caller be allowed to call this specific method." Teams frequently conflate the two once mTLS is in place ("it's authenticated internal traffic, so it's trusted") and skip building any actual per-method, per-caller authorization policy — meaning any compromised internal service (via a dependency vulnerability, a supply-chain issue, or a misconfiguration) can call *any* RPC method on *any* other service in the mesh, turning a single-service compromise into a mesh-wide blast radius.

**Fix:**
```protobuf
// The gap: a gRPC service definition with no notion of which callers are
// permitted to invoke which methods — mTLS only tells you the caller's identity
service BillingService {
  rpc GetInvoice(GetInvoiceRequest) returns (Invoice);
  rpc VoidInvoice(VoidInvoiceRequest) returns (VoidInvoiceResponse);   // anyone with a valid mesh identity can call this
}
```
```python
# Hardened: an interceptor enforces an explicit allow-list of which authenticated
# service identities may call which methods, independent of mTLS having already succeeded
SERVICE_METHOD_POLICY = {
    "VoidInvoice": {"payments-orchestrator", "billing-admin-console"},   # explicit allow-list, least privilege
    "GetInvoice": {"payments-orchestrator", "customer-portal-service", "billing-admin-console"},
}

class AuthorizationInterceptor(grpc.ServerInterceptor):
    def intercept_service(self, continuation, handler_call_details):
        caller_identity = get_verified_identity_from_mtls_cert(handler_call_details)  # from the mTLS cert, not headers
        method_name = handler_call_details.method.split('/')[-1]
        allowed_callers = SERVICE_METHOD_POLICY.get(method_name, set())
        if caller_identity not in allowed_callers:
            raise PermissionError(f"{caller_identity} is not authorized to call {method_name}")
        return continuation(handler_call_details)
```
- **Never treat mesh-enforced mTLS as sufficient authorization** — mTLS is authentication (proving identity), and needs to be paired with an explicit, maintained per-method authorization policy (an allow-list or a policy-as-code rule set) that answers "given this verified caller identity, is *this specific method* permitted" — the same authentication-vs-authorization distinction from Q3, applied to service-to-service calls instead of end-user API calls.
- **Derive the caller identity from the verified mTLS certificate itself, never from a self-reported header or metadata field** — a gRPC call can include arbitrary metadata that a compromised caller controls; only the mesh-verified certificate identity is a trustworthy signal to authorize against (this is the same lesson as the multi-agent impersonation risk of trusting a self-asserted identity field instead of a cryptographically verified one).
- **Apply least privilege per service-to-service relationship, scoped to the minimum method set each caller actually needs** — `recommendation-service` should structurally be unable to reach `billing-service.VoidInvoice` at all, not merely "unlikely to call it because it has no reason to," since the entire point of this control is to contain what a *compromised* version of a legitimate service can do, not to trust that legitimate services will only make legitimate calls.
- **Enforce authorization policy centrally and declaratively where the mesh supports it** (e.g., a service mesh's own authorization-policy resources, or an interceptor pattern applied consistently across every service) rather than expecting each service team to hand-write and remember to include their own per-method checks — a policy that depends on every team independently getting this right will have gaps exactly like the one this incident found.
- **Treat this as a mandatory finding in any zero-trust or service-mesh migration review** (tying back to the [Security Architect zero-trust and microservices-migration scenarios](Security_Architect_Scenario_Questions.md#scenario-4-implementing-zero-trust-architecture)) — "we deployed mTLS everywhere" is a common, dangerously incomplete milestone that teams mistake for "we implemented zero trust," when zero trust specifically requires per-request authorization decisions, not just strong identity verification.
- **Log and alert on cross-service calls that don't match the expected service-dependency graph**, independent of whether the authorization policy blocked them — an unexpected caller successfully reaching a sensitive method (or even being denied but still attempting it) is a strong signal of either a misconfiguration or an active compromise, and is exactly the kind of anomaly that's invisible if your only observability is "was the mTLS handshake successful."
