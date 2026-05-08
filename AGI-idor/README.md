# AGI-idor 🔓

> Autonomous IDOR & Broken Access Control Hunter  
> Brain: `skills/hunt-idor.md` — synthesized from Top 100 HackerOne Reports

## Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Configure your target
#    Edit config/target.json  → set base_url, JS files, API docs
#    Edit config/accounts.json → set auth tokens for 2+ accounts
#    Edit config/scope.json   → set safety guardrails

# 3. Run full scan
python main.py

# 4. Run with Burp proxy
python main.py  # (proxy configured in target.json)

# 5. Recon only
python main.py --recon-only

# 6. GraphQL only
python main.py --graphql-only

# 7. Include destructive tests (DELETE, etc.)
python main.py --dangerous
```

## Architecture

```
main.py → AGIIDORAgent (core/agent.py)
              ├── Phase 1: Parse skills/hunt-idor.md
              ├── Phase 2: IDORRecon → JS mining, API docs, GraphQL introspection
              ├── Phase 3: AuthMatrix → Multi-account baseline
              ├── Phase 4: IDOREngine → Horizontal, Vertical, Cross-Tenant, Mass Assignment
              ├── Phase 5: GraphQLAnalyzer → Mutations, Batching, Aliases, Fragments
              ├── Phase 6: BypassLab → JWT, Gateway, Input Validation, Race Conditions
              └── Phase 7: IDORReporter → Markdown findings + consolidated report
```

## Modules

| Module | Purpose |
|---|---|
| `core/agent.py` | Main orchestrator — reads skill file, drives pipeline |
| `core/recon.py` | JS bundle mining, endpoint extraction, GraphQL introspection |
| `core/auth_matrix.py` | Multi-account session management & role mapping |
| `core/idor_engine.py` | Core attack engine — generates & fires IDOR payloads |
| `core/graphql_analyzer.py` | GraphQL-specific IDOR testing |
| `core/bypass_lab.py` | JWT manipulation, param pollution, method switching |
| `core/reporter.py` | Markdown findings + consolidated report |
| `utils/http_client.py` | Rate-limited HTTP client with Burp proxy & retry |
| `utils/jwt_utils.py` | JWT decode, forge, algorithm confusion |
| `utils/id_harvester.py` | Extract & classify IDs from responses/JS/URLs |
| `utils/diff_engine.py` | Response comparison & IDOR confirmation |

## Safety

- **Forbidden actions** configured in `config/scope.json`
- DELETE/password reset/financial endpoints blocked unless `--dangerous` flag
- All requests logged to `output/logs/`
- Rate limiting enforced (configurable)
- Proxy support for Burp Suite traffic inspection

## Output

```
output/
├── report.md                    # Consolidated findings report
├── all_findings.json            # Machine-readable findings
├── discovered_endpoints.json    # All discovered endpoints
├── auth_matrix.json             # Access control matrix
├── idor_candidates.json         # Potential IDOR targets
├── harvested_ids.json           # All extracted identifiers
├── graphql_schema.json          # GraphQL schema (if available)
├── findings/                    # Individual finding markdown files
├── evidence/                    # Response dumps
└── logs/                        # Full request/response logs
```

## The Brain: hunt-idor.md

The skill file at `skills/hunt-idor.md` contains:
- **Crown Jewel Targets** — highest-impact IDOR surfaces from real reports
- **Attack Surface Signals** — what to look for before testing
- **Step-by-Step Methodology** — 12-step workflow from recon to confirmation
- **Object Reference Patterns** — identifier types and test strategies
- **Bypass Techniques** — JWT, gateway, RBAC, input validation, business logic, GraphQL
- **Advanced Chains** — IDOR → ATO, Priv Esc, Mass Exfil, Financial Fraud, RCE
- **Tooling & Automation** — Burp extensions, CLI tools, custom scripts

All techniques are extracted from real disclosed HackerOne reports.

## Disclaimer

This tool is for **authorized security testing only**. Always obtain written permission
before testing. The authors are not responsible for misuse.
