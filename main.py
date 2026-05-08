#!/usr/bin/env python3
"""
AGI-idor — Autonomous IDOR & Broken Access Control Hunter
Single command entry point.

Usage:
    python main.py                          # Full scan
    python main.py --dangerous              # Include destructive tests (DELETE, etc.)
    python main.py --recon-only             # Only run reconnaissance
    python main.py --graphql-only           # Only run GraphQL analysis
    python main.py --config-dir ./config    # Custom config directory
"""
from __future__ import annotations
import argparse, logging, sys, warnings
from pathlib import Path

# Suppress InsecureRequestWarning for Burp proxy
warnings.filterwarnings("ignore", message="Unverified HTTPS request")

# Setup logging — defer file handler until output dir exists
Path("output/logs").mkdir(parents=True, exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    handlers=[
        logging.FileHandler("output/logs/agi-idor.log", mode="a"),
        logging.StreamHandler(sys.stdout),
    ],
)
logger = logging.getLogger("agi-idor")


def main():
    parser = argparse.ArgumentParser(
        description="AGI-idor: Autonomous IDOR & Broken Access Control Hunter",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--config-dir", default="config", help="Path to config directory")
    parser.add_argument("--skills", default="skills/hunt-idor.md", help="Path to skills file")
    parser.add_argument("--output", default="output", help="Output directory")
    parser.add_argument("--dangerous", action="store_true", help="Enable destructive tests (DELETE, password reset, etc.)")
    parser.add_argument("--recon-only", action="store_true", help="Only run reconnaissance phase")
    parser.add_argument("--graphql-only", action="store_true", help="Only run GraphQL analysis")
    parser.add_argument("--bypass-only", action="store_true", help="Only run bypass lab")
    parser.add_argument("--no-proxy", action="store_true", help="Disable proxy even if configured")
    parser.add_argument("--rate-limit", type=int, default=None, help="Override rate limit (requests/sec)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Ensure output directories exist
    Path(args.output).mkdir(parents=True, exist_ok=True)
    (Path(args.output) / "logs").mkdir(exist_ok=True)
    (Path(args.output) / "findings").mkdir(exist_ok=True)
    (Path(args.output) / "evidence").mkdir(exist_ok=True)

    # Import here to avoid circular imports at module level
    from core.agent import AGIIDORAgent

    agent = AGIIDORAgent(
        config_dir=args.config_dir,
        skills_file=args.skills,
        output_dir=args.output,
        dangerous=args.dangerous,
    )

    if args.no_proxy:
        agent.http.session.proxies = {}

    if args.rate_limit:
        from utils.http_client import TokenBucketRateLimiter
        agent.http.rate_limiter = TokenBucketRateLimiter(args.rate_limit)

    if args.recon_only:
        from colorama import Fore, Style
        print(f"\n{Fore.CYAN}Running reconnaissance only...{Style.RESET_ALL}\n")
        agent.engine.parse_skills_file(str(agent.skills_file))
        agent.recon.discover_js_endpoints()
        agent.recon.discover_api_docs()
        agent.recon.save_results(args.output)
        eps = agent.recon.get_sorted_endpoints()
        print(f"\n{Fore.GREEN}Discovered {len(eps)} endpoints. Saved to {args.output}/discovered_endpoints.json{Style.RESET_ALL}")
        return

    if args.graphql_only:
        from colorama import Fore, Style
        print(f"\n{Fore.CYAN}Running GraphQL analysis only...{Style.RESET_ALL}\n")
        findings = agent.graphql.run_all_tests()
        agent.reporter.add_findings(findings)
        agent.reporter.save_report()
        return

    if args.bypass_only:
        from colorama import Fore, Style
        print(f"\n{Fore.CYAN}Running bypass lab only...{Style.RESET_ALL}\n")
        agent.recon.discover_js_endpoints()
        agent.recon.discover_api_docs()
        eps = agent.recon.get_sorted_endpoints()
        findings = agent.bypass.run_all_tests(eps[:20])
        agent.reporter.add_findings(findings)
        agent.reporter.save_report()
        return

    # Full scan
    agent.run()


if __name__ == "__main__":
    main()
