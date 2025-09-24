#!/usr/bin/env python3
"""
extract-iocs.py
Pulls domains, IPs and URLs from a URLscan.io result and outputs CSV.
Usage: python3 extract-iocs.py <urlscan_uuid>
"""

import sys
import json
import urllib.request

# TODO: add pagination for results > 1000 entries
def fetch_urlscan(uuid):
    url = f"https://urlscan.io/api/v1/result/{uuid}/"
    req = urllib.request.Request(url, headers={"User-Agent": "ioc-extractor/1.0"})
    with urllib.request.urlopen(req) as r:
        return json.loads(r.read())

# might be missing some ioc types - check if file hashes are ever in the data
def extract_iocs(data):
    iocs = {"domains": set(), "ips": set(), "urls": set()}

    for req in data.get("data", {}).get("requests", []):
        url = req.get("request", {}).get("url", "")
        if url:
            iocs["urls"].add(url)

    for domain in data.get("lists", {}).get("domains", []):
        iocs["domains"].add(domain)

    for ip in data.get("lists", {}).get("ips", []):
        iocs["ips"].add(ip)

    return iocs

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 extract-iocs.py <urlscan_uuid>")
        sys.exit(1)

    uuid = sys.argv[1]
    print(f"[*] Fetching URLscan result for {uuid}")

    data = fetch_urlscan(uuid)
    iocs = extract_iocs(data)

    print(f"\n[+] Extracted IOCs:")
    print(f"    Domains : {len(iocs['domains'])}")
    print(f"    IPs     : {len(iocs['ips'])}")
    print(f"    URLs    : {len(iocs['urls'])}")

    print("\ntype,indicator")
    for d in sorted(iocs["domains"]):
        print(f"domain,{d}")
    for ip in sorted(iocs["ips"]):
        print(f"ip,{ip}")
    for u in sorted(iocs["urls"]):
        print(f"url,{u}")

if __name__ == "__main__":
    main()
