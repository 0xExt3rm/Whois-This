# Whois-This
> **Project 2** — *domain, IP, reverse-IP, and ASN recon in one CLI*

`WHOIS (domain + IP) + reverse-IP + ASN lookup` — pure Python, zero dependencies

## Usage:
    python3 whois_this.py domain <domain_name> [--raw] [--json]
    python3 whois_this.py ip <ip_address> [--raw] [--json]
    python3 whois_this.py reverse <ip_address> [--candidates FILE] [--skip-api]
    python3 whois_this.py asn <ip_or_asn>

# Examples

## 1. Domain WHOIS :

    python3 whois_this.py domain example.com

Add `--raw` for the full, untouched registry response, or `--json` to feed the result into another script.

## 2. IP WHOIS :

Who legally owns an address block — ARIN, RIPE, APNIC, LACNIC, or AFRINIC, depending on region. Not who's currently routing it; that's ASN, below.

    python3 whois_this.py ip 8.8.8.8

## 3. Reverse IP :

PTR (reverse DNS) for the address, plus a crawled reverse-IP index from HackerTarget's free API:

    python3 whois_this.py reverse 76.223.54.146

To verify specific domains against that IP instead of trusting the API dump as-is:

    python3 whois_this.py reverse 76.223.54.146 --candidates domains.txt

`Note: shared hosting, CDN, and cloud IPs (AWS, Cloudflare, etc.) return long, noisy lists — many entries can be stale, past tenants rather than what's live now. --candidates is how you confirm which ones still are.`

## 4. ASN Lookup :

Which network is currently routing this address, via BGP — accepts either an IP or an AS number directly:

    python3 whois_this.py asn 8.8.8.8
    python3 whois_this.py asn AS15169

`Note: IP WHOIS and ASN can legitimately disagree for the same address — one says who registered it, the other says who's routing it right now. That's not a bug in either lookup.`

## Disclaimer

This tool is created strictly for educational purposes and authorized security testing. Do not use it against systems or infrastructure without explicit permission.
