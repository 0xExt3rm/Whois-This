#!/usr/bin/env python3

# --------------------------------------------------------------------------------
# whois_this.py - WHOIS (domain + IP), reverse IP, and ASN information collector |
# (Project 2, step ? who is step?)                                                            |
#                                                                                |
# Usage:                                                                         |
#    python3 whois_this.py domain <domain_name> [--raw] [--json]                 |
#    python3 whois_this.py ip <ip_address> [--raw] [--json]                      |
#    python3 whois_this.py reverse <ip_address> [--candidates FILE] [--skip-api] |
#    python3 whois_this.py asn <ip_or_asn>                                       |
# --------------------------------------------------------------------------------

import argparse
import json
import re
import socket
import sys
import time
import urllib.error
import urllib.request
from typing import Optional


class Color:
    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    RESET = "\033[0m"


BANNER = f"""{Color.CYAN}{Color.BOLD}
WHOIS / ASN COLLECTOR  v0.4
======================================
  domain  |  ip  |  reverse  |  asn
======================================{Color.RESET}"""

IANA_WHOIS = "whois.iana.org"
CYMRU_WHOIS = "whois.cymru.com"
WHOIS_PORT = 43
TIMEOUT_SECONDS = 10.0
HACKERTARGET_REVERSE_IP_URL = "https://api.hackertarget.com/reverseiplookup/?q={ip}"


def looks_like_ipv4(value: str) -> bool:
    try:
        socket.inet_pton(socket.AF_INET, value)
        return True
    except OSError:
        return False


# ------------------------
# Shared WHOIS transport |
# ------------------------

def raw_whois_query(server: str, query: str) -> str:
    with socket.create_connection((server, WHOIS_PORT), timeout=TIMEOUT_SECONDS) as sock:
        sock.sendall((query + "\r\n").encode("utf-8"))
        chunks = []
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
    return b"".join(chunks).decode("utf-8", errors="ignore")


def find_iana_referral(query: str) -> Optional[str]:
    """
    Ask IANA who's responsible for a TLD or an IP address block. IANA
    sits at the top of both hierarchies and answers either kind of
    question from the same server, pointing onward via a "whois:" or
    "refer:" field depending on which kind of record it is.
    """
    response = raw_whois_query(IANA_WHOIS, query)
    for line in response.splitlines():
        lower = line.strip().lower()
        if lower.startswith("whois:") or lower.startswith("refer:"):
            return line.split(":", 1)[1].strip()
    return None


# -------------------------------------------------------------------
# Generic WHOIS text parsing - shared engine, per-mode field tables |
# -------------------------------------------------------------------

def parse_whois_response(raw_text: str, field_patterns: dict, multi_value_fields: set) -> dict:
    """
    Best-effort extraction of fields from raw WHOIS text. WHOIS has no
    single machine-readable schema shared across every registry, so this
    matches whichever field-pattern table the caller supplies. Domain and
    IP lookups both call this - only the field names differ.
    """
    parsed = {}
    for line in raw_text.splitlines():
        line = line.strip()
        if not line:
            continue
        for field, patterns in field_patterns.items():
            for pattern in patterns:
                match = re.match(pattern, line, re.IGNORECASE)
                if not match:
                    continue
                value = match.group(1).strip()
                if not value:
                    continue
                if field in multi_value_fields:
                    parsed.setdefault(field, [])
                    if value not in parsed[field]:
                        parsed[field].append(value)
                elif field not in parsed:
                    parsed[field] = value
                break
    return parsed


def print_parsed(parsed: dict, field_labels: dict, label_width: int = 15) -> bool:
    if not parsed:
        return False
    for field, label in field_labels.items():
        if field not in parsed:
            continue
        value = parsed[field]
        if isinstance(value, list):
            print(f"{Color.CYAN}{label:<{label_width}}{Color.RESET}: {value[0]}")
            for extra in value[1:]:
                print(f"{'':<{label_width}}  {extra}")
        else:
            print(f"{Color.CYAN}{label:<{label_width}}{Color.RESET}: {value}")
    return True


# --------------
# Domain WHOIS |
# --------------

def whois_domain(domain: str) -> str:
    if "." not in domain:
        raise ValueError(f"'{domain}' doesn't look like a domain name")

    tld = domain.rsplit(".", 1)[-1]
    registry_server = find_iana_referral(tld)
    if not registry_server:
        raise LookupError(f"No known WHOIS server for the .{tld} TLD")

    response = raw_whois_query(registry_server, domain)

    for line in response.splitlines():
        lower = line.lower()
        if "whois server:" in lower or lower.startswith("refer:"):
            referred_server = line.split(":", 1)[1].strip()
            if referred_server and referred_server != registry_server:
                referred_response = raw_whois_query(referred_server, domain)
                if referred_response.strip():
                    return referred_response

    return response


DOMAIN_FIELD_PATTERNS = {
    "domain_name": [r"^Domain Name:\s*(.+)$"],
    "registrar": [r"^Registrar:\s*(.+)$"],
    "creation_date": [r"^Creation Date:\s*(.+)$"],
    "expiration_date": [
        r"^Registry Expiry Date:\s*(.+)$",
        r"^Expiration Date:\s*(.+)$",
        r"^Expiry Date:\s*(.+)$",
    ],
    "updated_date": [r"^Updated Date:\s*(.+)$"],
    "status": [r"^Domain Status:\s*(.+)$"],
    "name_servers": [r"^Name Server:\s*(.+)$"],
}

DOMAIN_MULTI_VALUE_FIELDS = {"status", "name_servers"}

DOMAIN_FIELD_LABELS = {
    "domain_name": "Domain Name",
    "registrar": "Registrar",
    "creation_date": "Created",
    "expiration_date": "Expires",
    "updated_date": "Updated",
    "status": "Status",
    "name_servers": "Name Servers",
}


def run_domain_mode(args):
    if "." not in args.domain:
        print(f"{Color.RED}[-] '{args.domain}' doesn't look like a domain name{Color.RESET}", file=sys.stderr)
        sys.exit(1)

    tld = args.domain.rsplit(".", 1)[-1]
    print(f"{Color.CYAN}[i] Finding registry for .{tld}...{Color.RESET}", file=sys.stderr)

    start = time.time()
    try:
        raw_text = whois_domain(args.domain)
    except LookupError as e:
        print(f"{Color.RED}[-] {e}{Color.RESET}", file=sys.stderr)
        sys.exit(1)
    except socket.timeout:
        print(f"{Color.RED}[-] Connection timed out after {TIMEOUT_SECONDS}s{Color.RESET}", file=sys.stderr)
        sys.exit(1)
    except socket.gaierror:
        print(f"{Color.RED}[-] Couldn't resolve a WHOIS server hostname - check your connection{Color.RESET}", file=sys.stderr)
        sys.exit(1)
    except OSError as e:
        print(f"{Color.RED}[-] Connection failed: {e}{Color.RESET}", file=sys.stderr)
        sys.exit(1)
    elapsed = time.time() - start

    parsed = parse_whois_response(raw_text, DOMAIN_FIELD_PATTERNS, DOMAIN_MULTI_VALUE_FIELDS)
    print(f"{Color.GREEN}[+] Got a response in {elapsed:.2f}s{Color.RESET}", file=sys.stderr)

    if args.json:
        print(json.dumps({
            "domain": args.domain,
            "elapsed_seconds": round(elapsed, 2),
            "parsed": parsed,
            "raw": raw_text,
        }, indent=2))
        return

    if args.raw:
        print(raw_text)
        return

    if not print_parsed(parsed, DOMAIN_FIELD_LABELS):
        print(f"{Color.YELLOW}[!] Couldn't identify known fields - showing raw text{Color.RESET}", file=sys.stderr)
        print(raw_text)


# --------------------------------------------------------------------
# IP WHOIS (new) - who owns this address block, not who's routing it |
# --------------------------------------------------------------------

def whois_ip(ip: str) -> str:
    """
    Full IP WHOIS lookup: ask IANA which Regional Internet Registry (RIR)
    owns this address block, query that RIR directly, then follow one
    further referral if given (some older allocations point from one RIR
    to another). Same two-hop shape as whois_domain(), different
    registries underneath.
    """
    rir_server = find_iana_referral(ip)
    if not rir_server:
        raise LookupError(f"Could not determine the responsible registry for {ip}")

    response = raw_whois_query(rir_server, ip)

    for line in response.splitlines():
        lower = line.strip().lower()
        if lower.startswith("referralserver:") or lower.startswith("refer:"):
            referred = line.split(":", 1)[1].strip()
            referred = referred.split("//")[-1].split(":")[0].split("/")[0]
            if referred and referred != rir_server:
                try:
                    referred_response = raw_whois_query(referred, ip)
                except OSError:
                    referred_response = ""
                if referred_response.strip():
                    return referred_response

    return response


IP_FIELD_PATTERNS = {
    "range": [
        r"^NetRange:\s*(.+)$",
        r"^inetnum:\s*(.+)$",
    ],
    "cidr": [r"^CIDR:\s*(.+)$"],
    "name": [
        r"^NetName:\s*(.+)$",
        r"^netname:\s*(.+)$",
    ],
    "organization": [
        r"^Organization:\s*(.+)$",
        r"^OrgName:\s*(.+)$",
        r"^owner:\s*(.+)$",
        r"^descr:\s*(.+)$",
    ],
    "country": [
        r"^Country:\s*(.+)$",
        r"^country:\s*(.+)$",
    ],
    "created": [
        r"^RegDate:\s*(.+)$",
        r"^created:\s*(.+)$",
    ],
    "updated": [
        r"^Updated:\s*(.+)$",
        r"^last-modified:\s*(.+)$",
        r"^changed:\s*(.+)$",
    ],
}

IP_MULTI_VALUE_FIELDS = set()

IP_FIELD_LABELS = {
    "range": "IP Range",
    "cidr": "CIDR",
    "name": "Network Name",
    "organization": "Organization",
    "country": "Country",
    "created": "Registered",
    "updated": "Updated",
}


def run_ip_mode(args):
    if not looks_like_ipv4(args.ip):
        print(f"{Color.RED}[-] '{args.ip}' doesn't look like a valid IPv4 address{Color.RESET}", file=sys.stderr)
        sys.exit(1)

    print(f"{Color.CYAN}[i] Finding responsible registry for {args.ip}...{Color.RESET}", file=sys.stderr)

    start = time.time()
    try:
        raw_text = whois_ip(args.ip)
    except LookupError as e:
        print(f"{Color.RED}[-] {e}{Color.RESET}", file=sys.stderr)
        sys.exit(1)
    except socket.timeout:
        print(f"{Color.RED}[-] Connection timed out after {TIMEOUT_SECONDS}s{Color.RESET}", file=sys.stderr)
        sys.exit(1)
    except socket.gaierror:
        print(f"{Color.RED}[-] Couldn't resolve a WHOIS server hostname - check your connection{Color.RESET}", file=sys.stderr)
        sys.exit(1)
    except OSError as e:
        print(f"{Color.RED}[-] Connection failed: {e}{Color.RESET}", file=sys.stderr)
        sys.exit(1)
    elapsed = time.time() - start

    parsed = parse_whois_response(raw_text, IP_FIELD_PATTERNS, IP_MULTI_VALUE_FIELDS)
    print(f"{Color.GREEN}[+] Got a response in {elapsed:.2f}s{Color.RESET}", file=sys.stderr)

    if args.json:
        print(json.dumps({
            "ip": args.ip,
            "elapsed_seconds": round(elapsed, 2),
            "parsed": parsed,
            "raw": raw_text,
        }, indent=2))
        return

    if args.raw:
        print(raw_text)
        return

    if not print_parsed(parsed, IP_FIELD_LABELS):
        print(f"{Color.YELLOW}[!] Couldn't identify known fields - showing raw text{Color.RESET}", file=sys.stderr)
        print(raw_text)


# ------------
# Reverse IP |
# ------------

def reverse_dns_lookup(ip: str) -> Optional[str]:
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except (socket.herror, OSError):
        return None


def reverse_ip_via_api(ip: str) -> str:
    url = HACKERTARGET_REVERSE_IP_URL.format(ip=ip)
    request = urllib.request.Request(url, headers={"User-Agent": "whois_this.py"})
    with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
        return response.read().decode("utf-8", errors="ignore").strip()


def check_candidate_domains(ip: str, candidates_path: str):
    matches = []
    checked = 0
    with open(candidates_path, "r", encoding="utf-8", errors="ignore") as f:
        for raw_line in f:
            domain = raw_line.strip()
            if not domain or domain.startswith("#"):
                continue
            checked += 1
            try:
                resolved_ip = socket.gethostbyname(domain)
            except socket.gaierror:
                continue
            if resolved_ip == ip:
                matches.append(domain)
    return matches, checked


def run_reverse_mode(args):
    if not looks_like_ipv4(args.ip):
        print(f"{Color.RED}[-] '{args.ip}' doesn't look like a valid IPv4 address{Color.RESET}", file=sys.stderr)
        sys.exit(1)

    print(f"{Color.CYAN}[i] Reverse DNS (PTR) lookup for {args.ip}...{Color.RESET}", file=sys.stderr)
    hostname = reverse_dns_lookup(args.ip)
    if hostname:
        print(f"PTR: {hostname}")
        print(f"{Color.GREEN}[+] PTR record found{Color.RESET}", file=sys.stderr)
    else:
        print(f"{Color.YELLOW}[!] No PTR record set for this IP{Color.RESET}", file=sys.stderr)

    if not args.skip_api:
        print(f"{Color.CYAN}[i] Checking HackerTarget's reverse-IP index...{Color.RESET}", file=sys.stderr)
        try:
            api_result = reverse_ip_via_api(args.ip)
        except (urllib.error.URLError, OSError) as e:
            print(f"{Color.RED}[-] Reverse-IP API request failed: {e}{Color.RESET}", file=sys.stderr)
        else:
            lowered = api_result.lower()
            if "error" in lowered or "api count exceeded" in lowered:
                print(f"{Color.YELLOW}[!] {api_result}{Color.RESET}", file=sys.stderr)
            elif api_result:
                for line in api_result.splitlines():
                    print(line)
                print(f"{Color.GREEN}[+] {len(api_result.splitlines())} domain(s) from HackerTarget{Color.RESET}", file=sys.stderr)
            else:
                print(f"{Color.YELLOW}[!] No records from HackerTarget for this IP{Color.RESET}", file=sys.stderr)

    if not args.candidates:
        return

    print(f"{Color.CYAN}[i] Testing candidate domains from {args.candidates}...{Color.RESET}", file=sys.stderr)
    try:
        matches, checked = check_candidate_domains(args.ip, args.candidates)
    except FileNotFoundError:
        print(f"{Color.RED}[-] Candidate file not found: {args.candidates}{Color.RESET}", file=sys.stderr)
        sys.exit(1)

    print(f"{Color.CYAN}[i] Checked {checked} candidate domain(s){Color.RESET}", file=sys.stderr)
    for domain in matches:
        print(domain)
    if not matches:
        print(f"{Color.YELLOW}[!] None of the candidates resolve to {args.ip}{Color.RESET}", file=sys.stderr)


# -----
# ASN |
# -----

def cymru_query(query_line: str):
    raw = raw_whois_query(CYMRU_WHOIS, query_line)
    lines = [line.strip() for line in raw.splitlines() if line.strip()]
    if not lines:
        return [], raw

    def split_fields(line):
        return [field.strip() for field in line.split("|")]

    header = split_fields(lines[0])
    if not header or header[0] != "AS":
        return None, raw

    rows = [dict(zip(header, split_fields(line))) for line in lines[1:]]
    return rows, raw


def normalize_asn_query(target: str) -> str:
    stripped = target.strip()
    if looks_like_ipv4(stripped):
        return f" -v {stripped}"

    as_number = stripped.upper()
    if as_number.startswith("AS"):
        as_number = as_number[2:]
    if not as_number.isdigit():
        raise ValueError(f"'{target}' isn't a valid IPv4 address or AS number")
    return f" -v AS{as_number}"


def run_asn_mode(args):
    try:
        query_line = normalize_asn_query(args.target)
    except ValueError as e:
        print(f"{Color.RED}[-] {e}{Color.RESET}", file=sys.stderr)
        sys.exit(1)

    print(f"{Color.CYAN}[i] Querying Team Cymru for {args.target}...{Color.RESET}", file=sys.stderr)
    try:
        rows, raw = cymru_query(query_line)
    except socket.timeout:
        print(f"{Color.RED}[-] Connection timed out after {TIMEOUT_SECONDS}s{Color.RESET}", file=sys.stderr)
        sys.exit(1)
    except OSError as e:
        print(f"{Color.RED}[-] Connection failed: {e}{Color.RESET}", file=sys.stderr)
        sys.exit(1)

    if rows is None:
        print(f"{Color.YELLOW}[!] Unrecognized response format - showing raw text{Color.RESET}", file=sys.stderr)
        print(raw)
        return

    if not rows:
        print(f"{Color.YELLOW}[!] No data returned for {args.target}{Color.RESET}", file=sys.stderr)
        sys.exit(1)

    for row in rows:
        for label, value in row.items():
            print(f"{Color.CYAN}{label:<12}{Color.RESET}: {value}")
        print()


# -------------
# Entry point |
# -------------

def main():
    parser = argparse.ArgumentParser(
        description="WHOIS (domain + IP), reverse IP, and ASN information collector",
        epilog=(
            "examples:\n"
            "  python3 whois_this.py domain example.com\n"
            "  python3 whois_this.py domain example.com --json\n"
            "  python3 whois_this.py ip 8.8.8.8\n"
            "  python3 whois_this.py ip 8.8.8.8 --raw\n"
            "  python3 whois_this.py reverse 8.8.8.8\n"
            "  python3 whois_this.py reverse 8.8.8.8 --candidates domains.txt\n"
            "  python3 whois_this.py asn 8.8.8.8\n"
            "  python3 whois_this.py asn AS15169\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="mode", required=True, help="What to look up")

    domain_parser = subparsers.add_parser("domain", help="WHOIS lookup for a domain name")
    domain_parser.add_argument("domain", help="Domain to look up, e.g. example.com")
    domain_parser.add_argument("--raw", action="store_true", help="Show the full raw WHOIS text instead of parsed fields")
    domain_parser.add_argument("--json", action="store_true", help="Output as JSON instead of human-readable text")

    ip_parser = subparsers.add_parser("ip", help="WHOIS lookup for an IP address (who owns it, not who's routing it)")
    ip_parser.add_argument("ip", help="IPv4 address to look up, e.g. 8.8.8.8")
    ip_parser.add_argument("--raw", action="store_true", help="Show the full raw WHOIS text instead of parsed fields")
    ip_parser.add_argument("--json", action="store_true", help="Output as JSON instead of human-readable text")

    reverse_parser = subparsers.add_parser("reverse", help="PTR lookup + reverse-IP domain discovery for an address")
    reverse_parser.add_argument("ip", help="IPv4 address to look up")
    reverse_parser.add_argument("--candidates", metavar="FILE", help="File of candidate domains to test against this IP, one per line")
    reverse_parser.add_argument("--skip-api", action="store_true", help="Skip the HackerTarget reverse-IP API call (PTR + candidates only)")

    asn_parser = subparsers.add_parser("asn", help="ASN lookup by IP address or AS number")
    asn_parser.add_argument("target", help="IPv4 address (e.g. 8.8.8.8) or AS number (e.g. AS15169 or 15169)")

    args = parser.parse_args()
    print(BANNER, file=sys.stderr)

    if args.mode == "domain":
        run_domain_mode(args)
    elif args.mode == "ip":
        run_ip_mode(args)
    elif args.mode == "reverse":
        run_reverse_mode(args)
    elif args.mode == "asn":
        run_asn_mode(args)


if __name__ == "__main__":
    main()
