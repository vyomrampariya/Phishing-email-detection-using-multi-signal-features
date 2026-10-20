"""CLI: python -m sender_header message.eml"""
import argparse, json, sys
from pathlib import Path
from .analyzer import analyze_sender_header

def main() -> int:
    parser = argparse.ArgumentParser(description="Analyze sender/header risk from a raw .eml file")
    parser.add_argument("email_file", nargs="?", help="raw email file; reads stdin if omitted")
    parser.add_argument("--trusted-domain", action="append", default=[], help="trusted domain; repeatable")
    args = parser.parse_args()
    raw = Path(args.email_file).read_text(encoding="utf-8", errors="replace") if args.email_file else sys.stdin.read()
    print(json.dumps(analyze_sender_header(raw, trusted_domains=args.trusted_domain or None), indent=2, ensure_ascii=False))
    return 0

if __name__ == "__main__": raise SystemExit(main())
