#!/usr/bin/env python3
"""
site_intel.py
"""

import socket
import ssl
import requests
import whois
import json
import subprocess
import sys
from urllib.parse import urlparse
from datetime import datetime

# Optional: pip install python-whois requests
try:
    import whois
except ImportError:
    print("Install: pip install python-whois requests")
    sys.exit(1)

def banner():
    print(r"""
  WEBSITE INFORMATION GATHERING.
    """)
    print("="*50)

def dns_lookup(domain):
    print(f"[+] DNS Lookup")
    try:
        ip = socket.gethostbyname(domain)
        print(f"    IP: {ip}")
    except:
        print("    Failed to resolve")

    # MX records
    try:
        import dns.resolver
        answers = dns.resolver.resolve(domain, 'MX')
        print("    Mail Servers:")
        for rdata in answers:
            print(f"      {rdata.exchange}")
    except:
        print("    MX lookup failed (dnspython not installed)")

def whois_lookup(domain):
    print(f"\n[+] WHOIS")
    try:
        w = whois.whois(domain)
        print(f"    Registrar: {w.registrar}")
        print(f"    Created: {w.creation_date}")
        print(f"    Expires: {w.expiration_date}")
        print(f"    Name Servers: {', '.join(w.name_servers) if w.name_servers else 'N/A'}")
    except Exception as e:
        print(f"    WHOIS failed: {e}")

def ssl_info(domain):
    print(f"\n[+] SSL Certificate")
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                print(f"    Issuer: {cert.get('issuer', 'N/A')}")
                print(f"    Expires: {cert.get('notAfter', 'N/A')}")
                print(f"    Subject: {cert.get('subject', 'N/A')}")
    except:
        print("    No SSL or connection failed")

def http_headers(url):
    print(f"\n[+] HTTP Headers")
    try:
        r = requests.get(url, timeout=10, allow_redirects=True)
        print(f"    Status: {r.status_code}")
        print(f"    Server: {r.headers.get('Server', 'Hidden')}")
        print(f"    X-Powered-By: {r.headers.get('X-Powered-By', 'None')}")
        print(f"    Final URL: {r.url}")
    except Exception as e:
        print(f"    HTTP failed: {e}")

def tech_detect(url):
    print(f"\n[+] Technology Detection (Wappalyzer-style)")
    try:
        r = requests.get(url, timeout=10)
        tech = []
        if 'wordpress' in r.text.lower():
            tech.append("WordPress")
        if 'jquery' in r.text.lower():
            tech.append("jQuery")
        if 'cloudflare' in r.headers.get('Server', '').lower():
            tech.append("Cloudflare")
        if 'x-shopify' in r.headers:
            tech.append("Shopify")
        print("    Detected: " + ", ".join(tech) if tech else "    Basic HTML")
    except:
        print("    Failed")

def wayback_check(domain):
    print(f"\n[+] Wayback Machine")
    try:
        url = f"http://archive.org/wayback/available?url={domain}"
        r = requests.get(url, timeout=10).json()
        if r.get("archived_snapshots"):
            snap = r["archived_snapshots"]["closest"]["url"]
            print(f"    Snapshot: {snap}")
        else:
            print("    No snapshots")
    except:
        print("    Failed")

def subdomain_brute(domain, wordlist="common.txt"):
    print(f"\n[+] Subdomain Brute-Force (Passive)")
    if not wordlist:
        print("    Skip (no wordlist)")
        return
    try:
        with open(wordlist) as f:
            words = [line.strip() for line in f if line.strip()]
        found = []
        for word in words[:50]:  # limit
            sub = f"{word}.{domain}"
            try:
                socket.gethostbyname(sub)
                found.append(sub)
            except:
                pass
        print(f"    Found: {', '.join(found) if found else 'None'}")
    except:
        print("    Wordlist not found")

def port_scan(ip):
    print(f"\n[+] Port Scan (Common)")
    common = [21, 22, 25, 80, 443, 3389, 8080]
    open_ports = []
    for port in common:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        if result == 0:
            open_ports.append(port)
        sock.close()
    print(f"    Open: {', '.join(map(str, open_ports)) if open_ports else 'None'}")

def main():
    banner()
    if len(sys.argv) != 2:
        print("Usage: python3 site_intel.py example.com")
        sys.exit(1)

    domain = sys.argv[1].lower().strip()
    if not domain.startswith("http"):
        url = f"https://{domain}"
    else:
        url = domain
        domain = urlparse(domain).netloc

    print(f"Target: {domain}\n")

    try:
        ip = socket.gethostbyname(domain)
    except:
        print("Cannot resolve domain.")
        sys.exit(1)

    dns_lookup(domain)
    whois_lookup(domain)
    ssl_info(domain)
    http_headers(url)
    tech_detect(url)
    wayback_check(domain)
    subdomain_brute(domain)  # download common.txt from SecLists
    port_scan(ip)

    print("\n" + "="*50)
    print("Recon complete. All data is public.")

if __name__ == "__main__":
    main()
