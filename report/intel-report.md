# Threat Intelligence Report - FakeMicrosoft-O365-Harvest

Report ID: TIR-2025-009
Analyst: NourKhalil0
Date: 2025-09-24
TLP: TLP:WHITE
Confidence: High

---

## Executive Summary

A credential harvesting campaign targeting Microsoft 365 users across SMB and enterprise environments. The actor registered typosquatted domains mimicking Microsoft login infrastructure and distributed phishing links via email. Victims were presented with a pixel-perfect clone of the Microsoft 365 login page. Credentials and session tokens were captured in real time via an evilginx2 reverse proxy, bypassing MFA.

Discovered via URLscan.io submissions showing identical page fingerprints across newly registered domains resolving to the same hosting ASN.

---

## 1. Initial Discovery

Identified via URLscan.io by querying for pages matching the Microsoft 365 login DOM fingerprint. Results returned 14 unique URLs across 6 domains submitted within a 72-hour window. All domains were registered within 30 days and shared identical JARM TLS fingerprints. Cross-referencing IPs against AbuseIPDB returned abuse reports on 3 of the 5 IPs.

---

## 2. Infrastructure Analysis

Domains:

| Domain | Registered | Registrar | Purpose |
|--------|-----------|-----------|---------|
| microsofft-login[.]com | 2025-09-01 | Namecheap | Primary phishing page |
| login-microsoftonline[.]net | 2025-09-03 | Namecheap | Redirect hop |
| office365-verify[.]com | 2025-09-04 | NameSilo | Credential exfil receiver |
| ms-secure-login[.]org | 2025-09-05 | Namecheap | Backup phishing page |
| msonline-auth[.]com | 2025-09-08 | NameSilo | Credential exfil receiver |

IP Addresses:

| IP | ASN | Provider | Country | AbuseIPDB |
|----|-----|----------|---------|-----------|
| 185.220.101.47 | AS205100 | F3 Netze | DE | 87% |
| 185.220.101.52 | AS205100 | F3 Netze | DE | 91% |
| 194.165.16.78 | AS47890 | UNMANAGED | NL | 74% |
| 194.165.16.81 | AS47890 | UNMANAGED | NL | 69% |
| 45.142.212.100 | AS208091 | Proton66 | RU | 95% |

Shodan: All servers nginx 1.18. JARM fingerprint matches known evilginx2 deployments. Port 8443 open on two IPs (evilginx2 admin default).

crt.sh revealed additional domains: microsofft-sso[.]com, ms365-auth[.]net, login-ms-secure[.]com

---

## 3. Phishing Page Analysis

Pixel-perfect Microsoft 365 login clone. Loads real CSS and fonts from cdn.office.net. Pre-fills victim email from URL parameter. Shows fake wrong-password error after first submission to harvest a second attempt. Redirects to real Microsoft login after second entry. evilginx2 captures session cookies alongside credentials, bypassing MFA.

Exfil endpoint identified in page JavaScript:
POST https://office365-verify[.]com/collect
Parameters: email, pass, token

---

## 4. Email Lure

Subject: Action Required - Unusual sign-in activity on your Microsoft account
From: no-reply@microsofft-login[.]com
Display name: Microsoft Account Team
Lure: Suspicious foreign login warning, link to verify account
Link format: https://microsofft-login[.]com/signin?email=victim@target.com&ref=alert

Sending infrastructure on separate IPs from phishing page hosting, suggesting deliberate separation.

---

## 5. MITRE ATT&CK Mapping

| ATT&CK ID | Technique | Observed Behavior |
|-----------|-----------|-------------------|
| T1566.002 | Phishing: Spearphishing Link | Email with link to phishing page |
| T1583.001 | Acquire Infrastructure: Domains | Typosquatted domains registered in bulk |
| T1583.003 | Acquire Infrastructure: VPS | Bulletproof hosting AS205100, AS208091 |
| T1071.001 | Application Layer Protocol: Web | HTTPS for C2 and exfil |
| T1557 | Adversary-in-the-Middle | evilginx2 reverse proxy |
| T1078 | Valid Accounts | Harvested credentials used for access |
| T1539 | Steal Web Session Cookie | Session tokens captured to bypass MFA |

---

## 6. Threat Actor Assessment

No solid attribution. The infra choices (bulletproof ASNs, Namecheap/NameSilo for domains, evilginx2 which is free and open source) are consistent with a mid-level financially motivated actor - probably an IAB or someone doing their own harvesting. The scale of it (multiple backup domains, separate sending infra) rules out a one-person opportunistic operation but it's not APT-tier either.

---

## 7. SOC Blocking Recommendations

Immediate: Block all IOC domains and IPs at proxy and firewall. Domains first as IPs rotate.

Email gateway: Block sender domain microsofft-login[.]com. Alert on emails linking to any IOC domain.

SIEM rules:
- DNS queries resolving to IOC IPs
- HTTP/HTTPS traffic to IOC domains
- Outbound POST to paths matching /collect

Users: Send awareness notification with lure screenshots. Remind that Microsoft does not ask for account verification via emailed links.

If clicked: Force password reset and revoke all active sessions immediately.

Long-term: URLscan.io alerts for your domain. Certstream monitoring for typosquats.

---

## 8. IOC Summary

| Type | Count |
|------|-------|
| Domains | 9 |
| IP addresses | 5 |
| URLs | 14 |
| Sender domains | 2 |
| File hashes | 3 |

Full list: iocs/indicators.csv
