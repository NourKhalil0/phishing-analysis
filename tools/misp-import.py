#!/usr/bin/env python3
"""
misp-import.py
Imports IOCs from indicators.csv into a MISP instance.
Usage: python3 misp-import.py --url https://your-misp --key YOUR_API_KEY --csv ../iocs/indicators.csv
"""

import csv
import sys
import argparse

def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--url", required=True, help="MISP instance URL")
    p.add_argument("--key", required=True, help="MISP API key")
    p.add_argument("--csv", required=True, help="Path to indicators.csv")
    return p.parse_args()

TYPE_MAP = {
    "domain": "domain",
    "ip": "ip-dst",
    "url": "url",
    "email": "email-src",
    "hash": "sha256",
}

def main():
    args = parse_args()

    try:
        from pymisp import PyMISP, MISPEvent, MISPAttribute
    except ImportError:
        print("[-] pymisp not installed. Run: pip install pymisp")
        sys.exit(1)

    misp = PyMISP(args.url, args.key, False)
    event = MISPEvent()
    event.info = "FakeMicrosoft-O365-Harvest - TIR-2025-009"
    event.distribution = 0
    event.threat_level_id = 2
    event.analysis = 2

    added = 0
    with open(args.csv) as f:
        reader = csv.DictReader(f)
        for row in reader:
            ioc_type = TYPE_MAP.get(row["type"])
            if not ioc_type:
                continue
            attr = MISPAttribute()
            attr.type = ioc_type
            attr.value = row["indicator"].replace("[.]", ".")
            attr.comment = row.get("context", "")
            attr.to_ids = True
            event.add_attribute(**attr)
            added += 1

    result = misp.add_event(event)
    print(f"[+] Created MISP event {result['Event']['id']} with {added} attributes")

if __name__ == "__main__":
    main()
