<div align="center">

# 🤖 AGI-idor

### **Autonomous IDOR & Broken Access Control Hunting Agent**

> *Your AI-powered access control auditor. Reads real HackerOne techniques and hunts bugs while you sleep.*

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Security](https://img.shields.io/badge/security-bug%20bounty-red.svg)](https://hackerone.com)
[![Version](https://img.shields.io/badge/version-2.0-green.svg)]()

<p align="center">
  <img src="https://img.shields.io/badge/Burp%20Suite-Integrated-orange?logo=burpsuite" />
  <img src="https://img.shields.io/badge/GraphQL-Supported-pink?logo=graphql" />
  <img src="https://img.shields.io/badge/JWT-Bypass%20Lab-purple" />
  <img src="https://img.shields.io/badge/IDOR-Automated-critical" />
</p>

</div>

---

## 🎯 What is AGI-idor?

**AGI-idor** is a production-grade, autonomous penetration testing framework that hunts **IDOR (Insecure Direct Object Reference)** and **Broken Access Control** vulnerabilities. 

Unlike static scanners, AGI-idor:
- 📖 **Reads** a skill file (`skills/hunt-idor.md`) synthesized from **Top 100 real HackerOne reports**
- 🔍 **Discovers** endpoints by mining JavaScript bundles and API documentation
- 🧠 **Tests** with multiple accounts simultaneously (horizontal, vertical, cross-tenant)
- ⚡ **Bypasses** JWT validation, API gateways, input filters, and business logic
- 📊 **Reports** findings with copy-paste ready `curl` commands and mass-impact scores

> **Built for bug bounty hunters, by bug bounty hunters.**

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🧠 **Skill-Driven Engine** | Parses `hunt-idor.md` dynamically — add new techniques without touching code |
| 👥 **Multi-Account Matrix** | Tests with 2+ accounts (attacker, victim, admin) to map exact access boundaries |
| 🔍 **JS Bundle Mining** | Extracts hidden API endpoints, GraphQL operations, and ID parameters from minified JS |
| 📡 **GraphQL Hunter** | Introspects schemas, tests batch queries, alias enumeration, and mutation ID swaps |
| 🔐 **JWT Bypass Lab** | Tests `none` algorithm, RS256→HS256 confusion, `kid`/`jwk` injection, signature stripping |
| 🔄 **Method Switching** | GET→POST→PUT→PATCH→DELETE — finds auth checks that only protect one method |
| 🎭 **Parameter Pollution** | Duplicate params, array injection, nested JSON manipulation |
| 🏎️ **Race Condition Tester** | Fires concurrent requests to exploit TOCTOU vulnerabilities |
| 📊 **Mass Impact Scoring** | Calculates how many user IDs are accessible — proves scale to triagers |
| 🕸️ **Burp Suite Proxy** | Route all traffic through Burp for manual verification |
| 🛡️ **Safety Guardrails** | Destructive actions (DELETE, password reset, financial) blocked unless `--dangerous` is set |

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         AGI-idor v2.0                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   📄 skills/hunt-idor.md  ←── Brain (Top 100 HackerOne Reports)│
│                                                                 │
│   ┌──────────────┐    ┌──────────────┐    ┌──────────────┐     │
│   │   Config     │    │    Recon     │    │ Auth Matrix  │     │
│   │  (3 JSONs)   │───→│ (JS Mining)  │───→│(Multi-Account│     │
│   │              │    │(API Docs)    │    │   Baseline)  │     │
│   └──────────────┘    └──────────────┘    └──────────────┘     │
│          │                   │                   │              │
│          ▼                   ▼                   ▼              │
│   ┌──────────────────────────────────────────────────────┐     │
│   │              🎯 IDOR Engine (Core)                   │     │
│   │  Horizontal │ Vertical │ Cross-Tenant │ Mass Assign  │     │
│   └──────────────────────────────────────────────────────┘     │
│          │                   │                   │              │
│          ▼                   ▼                   ▼              │
│   ┌──────────────┐    ┌──────────────┐    ┌──────────────┐     │
│   │   GraphQL    │    │  Bypass Lab  │    │   Reporter   │     │
│   │  Analyzer    │    │(JWT/Gateway/ │    │(Markdown +  │     │
│   │(Batch/Alias) │    │ Race/Input)  │    │  JSON + curl│     │
│   └──────────────┘    └──────────────┘    └──────────────┘     │
│                              │                                  │
│                              ▼                                  │
│                    ┌──────────────────┐                         │
│                    │  output/report.md │                         │
│                    │  + findings/      │                         │
│                    │  + evidence/      │                         │
│                    └──────────────────┘                         │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## 🚀 Quick Start (5 Minutes)

### Step 1: Clone & Install

```bash
git clone https://github.com/YOUR_USERNAME/AGI-idor.git
cd AGI-idor

python3 -m venv .venv
source .venv/bin/activate  # Linux/Mac
# OR
.venv\Scripts\activate   # Windows

pip install -r requirements.txt
```

### Step 2: Configure Your Target

Edit `config/target.json`:

```json
{
  "program_name": "ExampleCorp Bug Bounty",
  "base_url": "https://api.example.com",
  "in_scope_domains": ["api.example.com", "app.example.com"],
  "out_of_scope": ["blog.example.com"],
  "js_files": [
    "https://app.example.com/static/main.js",
    "https://app.example.com/static/app.bundle.js"
  ],
  "api_docs": [
    "https://api.example.com/swagger.json",
    "https://api.example.com/graphql"
  ],
  "rate_limit": 10,
  "proxy": "http://127.0.0.1:8080",
  "auth_mechanism": "bearer"
}
```

### Step 3: Configure Test Accounts

You need **at least 2 accounts** at the same privilege level + optionally 1 admin account.

Edit `config/accounts.json`:

```json
{
  "accounts": [
    {
      "account_id": "attacker",
      "role": "user",
      "email": "attacker@example.com",
      "jwt_token": "eyJhbGciOiJSUzI1NiIs...",
      "headers": {
        "Authorization": "Bearer eyJhbGciOiJSUzI1NiIs..."
      },
      "is_baseline": true
    },
    {
      "account_id": "victim",
      "role": "user",
      "email": "victim@example.com",
      "jwt_token": "eyJhbGciOiJSUzI1NiIs...",
      "headers": {
        "Authorization": "Bearer eyJhbGciOiJSUzI1NiIs..."
      }
    },
    {
      "account_id": "admin",
      "role": "admin",
      "email": "admin@example.com",
      "jwt_token": "eyJhbGciOiJSUzI1NiIs...",
      "headers": {
        "Authorization": "Bearer eyJhbGciOiJSUzI1NiIs..."
      }
    }
  ]
}
```

> 💡 **Pro Tip:** Create accounts via the target's registration flow. Do NOT use production accounts.

### Step 4: Configure Safety Scope

Edit `config/scope.json`:

```json
{
  "max_requests_per_endpoint": 1000,
  "max_ids_to_test": 10000,
  "enable_mass_testing": true,
  "enable_graphql": true,
  "enable_jwt_bypass": true,
  "enable_param_pollution": true,
  "enable_method_switching": true,
  "forbidden_actions": ["delete", "account_deletion", "password_reset", "financial_transfer"],
  "require_dangerous_flag_for": ["delete", "account_deletion", "password_reset"],
  "concurrent_workers": 10,
  "timeout_seconds": 30
}
```

### Step 5: Run the Agent

```bash
# Full autonomous scan
python main.py

# Route through Burp Suite for manual inspection
python main.py --burp

# Only reconnaissance (discover endpoints, no attacks)
python main.py --recon-only

# Only test GraphQL endpoints
python main.py --graphql-only

# Only run the bypass laboratory
python main.py --bypass-only

# Test a single endpoint
python main.py --test-endpoint /api/v1/users/{id}/profile

# Enable destructive tests (USE WITH EXTREME CAUTION)
python main.py --dangerous
```

---

## 📁 Project Structure

```
AGI-idor/
├── 📄 main.py                    # CLI entry point
├── 📄 requirements.txt           # Python dependencies
├── 📄 README.md                  # You are here
│
├── 📁 config/                    # Configuration files
│   ├── accounts.json             # Test accounts & auth tokens
│   ├── target.json               # Target scope & endpoints
│   └── scope.json                # Safety guardrails & limits
│
├── 📁 skills/                    # The Brain
│   └── hunt-idor.md              # IDOR techniques from HackerOne
│
├── 📁 core/                      # Core Engine
│   ├── agent.py                  # Main orchestrator
│   ├── recon.py                  # JS mining & endpoint discovery
│   ├── auth_matrix.py            # Multi-account access mapping
│   ├── idor_engine.py            # Core IDOR attack engine
│   ├── graphql_analyzer.py       # GraphQL-specific testing
│   ├── bypass_lab.py             # JWT, gateway, race condition bypasses
│   └── reporter.py               # Report generation
│
├── 📁 utils/                     # Utilities
│   ├── http_client.py            # Rate-limited HTTP client
│   ├── jwt_utils.py              # JWT manipulation toolkit
│   ├── id_harvester.py           # ID extraction & classification
│   └── diff_engine.py            # Response comparison engine
│
├── 📁 payloads/                  # Payload databases
│   ├── id_patterns.json
│   └── wordlists/
│       ├── sequential_ids.txt
│       └── graphql_mutations.txt
│
├── 📁 docs/                      # Your target documentation
│   └── project_docs.md           # Optional: API docs, business logic notes
│
└── 📁 output/                    # Generated results
    ├── report.md                 # Consolidated findings report
    ├── all_findings.json         # Machine-readable findings
    ├── discovered_endpoints.json # Discovered API endpoints
    ├── auth_matrix.json          # Access control matrix
    ├── graphql_schema.json       # GraphQL schema (if found)
    ├── findings/                 # Individual finding reports
    ├── evidence/                 # Request/response dumps
    └── logs/                     # Full execution trace
```

---

## 🎓 Newbie Guide: Understanding the Output

After running AGI-idor, check `output/report.md`. Here is what each section means:

### 🔴 Critical Finding Example

```markdown
# Finding: Horizontal IDOR on /api/v1/users/{id}/profile

**Severity:** 🔴 Critical
**Endpoint:** `GET /api/v1/users/12345/profile`
**Vulnerability Class:** IDOR Horizontal

## Description
The endpoint `/api/v1/users/{id}/profile` returns the full profile of any user
when the `{id}` parameter is changed, with no ownership verification.

## Steps to Reproduce
1. Authenticate as `attacker` (Account A)
2. Send: `GET /api/v1/users/67890/profile` (victim's ID)
3. Observe: 200 OK with victim's PII

## Evidence
```bash
curl -X GET "https://api.example.com/api/v1/users/67890/profile" \
  -H "Authorization: Bearer ATTACKER_TOKEN"
```

## Mass Impact Assessment
- IDs Tested: 100
- IDs Accessible: 97
- Percentage: 97%
- Assessment: 🔴 Mass Vulnerability

## Remediation
Add an ownership check: `if current_user.id != requested_id: return 403`
```

### Understanding Severity

| Severity | Meaning | Example |
|----------|---------|---------|
| 🔴 **Critical** | Mass impact, ATO, financial, admin access | 1000+ users accessible, credit card data |
| 🟠 **High** | Single user ATO, privilege escalation, sensitive PII | One account takeover, SSN exposure |
| 🟡 **Medium** | Limited data, non-sensitive IDOR | Email list enumeration |
| 🟢 **Low** | Info disclosure, missing auth on non-sensitive | Public profile fields |

---

## 🔧 Advanced Configuration

### Using Burp Suite Proxy

Set proxy in `config/target.json`:
```json
"proxy": "http://127.0.0.1:8080"
```

All traffic routes through Burp. You can manually inspect requests in the **HTTP History** tab.

### Adding Custom Headers

```json
"custom_headers": {
  "X-Bug-Bounty": "AGI-idor",
  "X-Forwarded-For": "127.0.0.1"
}
```

### Cookie-Based Authentication

```json
{
  "account_id": "attacker",
  "role": "user",
  "cookies": {
    "session": "sess_abc123",
    "auth": "auth_xyz789"
  },
  "headers": {
    "X-CSRF-Token": "csrf_token_here"
  }
}
```

### API Key Authentication

```json
{
  "account_id": "attacker",
  "role": "user",
  "api_key": "key_live_xxxxxxxx",
  "headers": {
    "X-API-Key": "key_live_xxxxxxxx"
  }
}
```

---

## 🛡️ Safety & Responsible Disclosure

AGI-idor is designed with **safety first**:

- ✅ **Destructive actions blocked by default** — DELETE, password reset, financial transfers require `--dangerous`
- ✅ **Rate limiting** — Configurable requests/sec to avoid DoS
- ✅ **Scope enforcement** — Out-of-scope domains are never touched
- ✅ **Evidence preservation** — Every request/response is logged
- ✅ **Burp integration** — Route through Burp for manual oversight

> ⚠️ **Only test systems you have explicit written permission to test.**
> Unauthorized access to computer systems is illegal.

---

## 🧪 Example Workflow

```bash
# 1. Recon only — see what exists
python main.py --recon-only

# 2. Check discovered endpoints
 cat output/discovered_endpoints.json

# 3. Run full scan with Burp
python main.py --burp

# 4. Review findings
 cat output/report.md

# 5. Pick a finding and verify manually
# Copy the curl command from output/findings/FINDING_ID.md

# 6. Report to the program
# Include the finding markdown + evidence in your HackerOne report
```

---

## 📊 Performance Tips

| Scenario | Recommended Config |
|----------|-------------------|
| Large target (10K+ endpoints) | `concurrent_workers: 20`, `max_ids_to_test: 1000` |
| Rate-limited target | `rate_limit: 5`, `concurrent_workers: 3` |
| GraphQL-heavy target | `enable_graphql: true`, `enable_mass_testing: false` |
| Quick triage | `--recon-only` first, then `--test-endpoint` on high-value endpoints |

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Commit your changes: `git commit -m 'Add amazing feature'`
4. Push to the branch: `git push origin feature/amazing-feature`
5. Open a Pull Request

---

## 📜 License

Distributed under the MIT License. See `LICENSE` for more information.

---

## 🙏 Acknowledgments

- Techniques synthesized from **Top 100 HackerOne Disclosed Reports**
- Inspired by real-world IDOR findings from PayPal, Shopify, Uber, Reddit, TikTok, and more
- Built for the bug bounty community

---

<div align="center">

**⭐ Star this repo if it helped you find bugs!**

**🐛 Found a bug in AGI-idor? Open an issue!**

**💬 Questions? Discussions welcome!**

</div>
