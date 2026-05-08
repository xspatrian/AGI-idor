"""
AGI-idor Agent — Main orchestrator that reads the skill file,
coordinates all modules, and drives the full IDOR hunting pipeline.
"""
from __future__ import annotations
import json, logging, sys, time
from pathlib import Path
from colorama import Fore, Style, init as colorama_init
from utils.http_client import RotatingHTTPClient
from utils.id_harvester import IDHarvester
from core.recon import IDORRecon
from core.auth_matrix import AuthMatrix
from core.idor_engine import IDOREngine
from core.graphql_analyzer import GraphQLAnalyzer
from core.bypass_lab import BypassLab
from core.reporter import IDORReporter

colorama_init(autoreset=True)
logger = logging.getLogger("agi-idor")

BANNER = f"""
{Fore.RED}
     █████╗  ██████╗ ██╗      ██╗██████╗  ██████╗ ██████╗
    ██╔══██╗██╔════╝ ██║      ██║██╔══██╗██╔═══██╗██╔══██╗
    ███████║██║  ███╗██║█████╗██║██║  ██║██║   ██║██████╔╝
    ██╔══██║██║   ██║██║╚════╝██║██║  ██║██║   ██║██╔══██╗
    ██║  ██║╚██████╔╝██║      ██║██████╔╝╚██████╔╝██║  ██║
    ╚═╝  ╚═╝ ╚═════╝ ╚═╝      ╚═╝╚═════╝  ╚═════╝ ╚═╝  ╚═╝
{Fore.CYAN}    Autonomous IDOR & Access Control Hunter v1.0
{Fore.WHITE}    Brain: skills/hunt-idor.md | Source: Top 100 HackerOne Reports
{Style.RESET_ALL}
"""

class AGIIDORAgent:
    def __init__(self, config_dir: str = "config", skills_file: str = "skills/hunt-idor.md",
                 output_dir: str = "output", dangerous: bool = False):
        self.config_dir = Path(config_dir)
        self.skills_file = Path(skills_file)
        self.output_dir = Path(output_dir)
        self.dangerous = dangerous

        # Load configs
        self.target_config = self._load_json("target.json")
        self.accounts_config = self._load_json("accounts.json").get("accounts", [])
        self.scope_config = self._load_json("scope.json")

        # Initialize HTTP client
        self.http = RotatingHTTPClient(
            proxy=self.target_config.get("proxy"),
            rate_limit=self.target_config.get("rate_limit", 10),
            timeout=self.scope_config.get("timeout_seconds", 30),
            log_dir=str(self.output_dir / "logs"),
            user_agent=self.target_config.get("user_agent", "AGI-idor/1.0"),
            custom_headers=self.target_config.get("custom_headers", {}),
        )

        # Initialize modules
        self.recon = IDORRecon(self.target_config, self.http)
        self.auth = AuthMatrix(self.accounts_config, self.http)
        self.engine = IDOREngine(
            auth_matrix=self.auth, http_client=self.http,
            scope=self.scope_config, base_url=self.target_config.get("base_url", ""),
        )
        self.engine.dangerous_mode = dangerous
        self.graphql = GraphQLAnalyzer(self.target_config, self.http, self.auth)
        self.bypass = BypassLab(self.target_config, self.http, self.auth)
        self.reporter = IDORReporter(str(self.output_dir))

    def _load_json(self, filename: str) -> dict:
        filepath = self.config_dir / filename
        if not filepath.exists():
            logger.warning(f"Config file not found: {filepath}")
            return {}
        with open(filepath, "r") as f:
            return json.load(f)

    def run(self):
        """Execute the full IDOR hunting pipeline."""
        print(BANNER)
        start_time = time.time()

        # Phase 1: Load Skills
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f" PHASE 1: LOADING BRAIN (hunt-idor.md)")
        print(f"{'='*60}{Style.RESET_ALL}\n")
        skills = self.engine.parse_skills_file(str(self.skills_file))
        if not skills:
            print(f"{Fore.YELLOW}[WARN] Skills file not found or empty — running without brain{Style.RESET_ALL}")

        # Phase 2: Reconnaissance
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f" PHASE 2: RECONNAISSANCE")
        print(f"{'='*60}{Style.RESET_ALL}\n")
        js_endpoints = self.recon.discover_js_endpoints()
        print(f"  Found {len(js_endpoints)} endpoints from JS files")
        api_endpoints = self.recon.discover_api_docs()
        print(f"  Found {len(api_endpoints)} endpoints from API docs")
        all_endpoints = self.recon.get_sorted_endpoints()
        self.recon.save_results(str(self.output_dir))
        print(f"\n  {Fore.GREEN}Total unique endpoints: {len(all_endpoints)}{Style.RESET_ALL}")

        if not all_endpoints:
            print(f"{Fore.YELLOW}[WARN] No endpoints discovered. Check target.json configuration.{Style.RESET_ALL}")
            return

        # Phase 3: Auth Matrix
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f" PHASE 3: BUILDING AUTH MATRIX")
        print(f"{'='*60}{Style.RESET_ALL}\n")
        sample = all_endpoints[:min(50, len(all_endpoints))]
        self.auth.build_baseline(sample, self.target_config.get("base_url", ""))
        candidates = self.auth.find_idor_candidates()
        self.auth.save_matrix(str(self.output_dir))
        print(f"\n  {Fore.GREEN}IDOR candidates: {len(candidates)}{Style.RESET_ALL}")

        # Phase 4: IDOR Engine
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f" PHASE 4: IDOR ENGINE — ATTACK PHASE")
        print(f"{'='*60}{Style.RESET_ALL}\n")
        victim_ids = self.recon.harvester.get_unique_ids("sequential_int")[:100]
        if not victim_ids:
            victim_ids = [str(i) for i in range(1, 21)]
        tenant_ids = self.recon.harvester.get_unique_ids("uuid")[:20]
        priority_eps = [ep for ep in all_endpoints if ep.get("priority", 0) >= 7][:30]
        if not priority_eps:
            priority_eps = all_endpoints[:20]
        idor_findings = self.engine.run_all_tests(priority_eps, victim_ids, tenant_ids)
        self.reporter.add_findings(idor_findings)

        # Phase 5: GraphQL Analysis
        if self.scope_config.get("enable_graphql", True):
            print(f"\n{Fore.CYAN}{'='*60}")
            print(f" PHASE 5: GRAPHQL ANALYSIS")
            print(f"{'='*60}{Style.RESET_ALL}\n")
            gql_findings = self.graphql.run_all_tests(victim_ids[:20])
            self.reporter.add_findings(gql_findings)

        # Phase 6: Bypass Lab
        if self.scope_config.get("enable_jwt_bypass", True):
            print(f"\n{Fore.CYAN}{'='*60}")
            print(f" PHASE 6: BYPASS LAB")
            print(f"{'='*60}{Style.RESET_ALL}\n")
            bypass_findings = self.bypass.run_all_tests(priority_eps[:15])
            self.reporter.add_findings(bypass_findings)

        # Phase 7: Report Generation
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f" PHASE 7: REPORT GENERATION")
        print(f"{'='*60}{Style.RESET_ALL}\n")
        self.engine.save_findings(str(self.output_dir))
        report_path = self.reporter.save_report()

        # Summary
        elapsed = time.time() - start_time
        total_findings = len(self.reporter.findings)
        print(f"\n{Fore.GREEN}{'='*60}")
        print(f" SCAN COMPLETE")
        print(f"{'='*60}")
        print(f"  Duration:         {elapsed:.1f}s")
        print(f"  Requests sent:    {self.http.total_requests}")
        print(f"  Endpoints tested: {len(all_endpoints)}")
        print(f"  Total findings:   {total_findings}")
        print(f"  Report:           {report_path}")
        print(f"{'='*60}{Style.RESET_ALL}\n")

        if total_findings == 0:
            print(f"{Fore.YELLOW}No IDOR/BAC vulnerabilities confirmed. This is normal — "
                  f"review output/auth_matrix.json for potential candidates.{Style.RESET_ALL}")
