# Email Threat Investigation Lab

A personal cybersecurity project demonstrating hands-on email threat investigation — covering phishing detection, sender authentication analysis (SPF, DKIM, DMARC), IOC lookup, and structured incident documentation.

---

## Project Overview

This lab applies the email investigation workflow used in Security Operations Centres (SOC) to real-world email samples. Three representative samples were analyzed:
1. **Email-01 (Phishing):** A brand impersonation lure mimicking Microsoft Security Alerts with attacker collection channels and tracking beacons.
2. **Email-02 (Authentication Issue / Phishing):** A financial loyalty phishing lure originating from a cloud VPS with an unconfigured bare hostname envelope sender causing SPF/DMARC resolution failures.
3. **Email-03 (Legitimate Baseline):** A standard, authenticated email exchanged over Google infrastructure to establish an analytical baseline.

For each sample, the investigation covers:
- Extraction and interpretation of email header fields (sender identity, routing hops, message metadata)
- In-depth verification of SPF, DKIM, and DMARC alignment and delivery authentication results
- Threat intelligence lookups on external IPs, domains, and URLs using Cisco Talos and passive DNS records
- Structured incident response documentation with technical findings, MITRE-aligned indicators, and remediation steps

---

## Repository Structure

```
Email-Security-Project/
├── README.md
├── samples/
│   ├── email-01-phishing.eml              ← Microsoft impersonation phishing sample
│   ├── email-02-authentication-issue.eml  ← Bradesco points phishing / bare VPS sender
│   └── email-03-legitimate-baseline.eml   ← Authenticated Gmail baseline
├── analysis/
│   ├── header-analysis.md                 ← Header fields, Received hops & identity mapping
│   ├── spf-dkim-dmarc-analysis.md         ← RFC protocol mechanics & alignment outcomes
│   └── ioc-analysis.md                    ← Extracted indicators, Talos IP reputation & status
├── reports/
│   ├── IR-001-phishing.md                 ← Incident Report: Microsoft account alert phishing
│   ├── IR-002-spoofing.md                 ← Incident Report: Bradesco financial loyalty phishing
│   └── IR-003-baseline.md                 ← Incident Report: Google infrastructure baseline
└── screenshots/
    ├── email-01-ip-talos.png              ← Cisco Talos reputation for 89.144.44.2
    └── email-02-ip-talos.png              ← Cisco Talos reputation for 137.184.34.4
```

---

## Samples Investigated

| Sample | Description | Classification | SPF | DKIM | DMARC |
|---|---|---|---|---|---|
| [email-01](./samples/email-01-phishing.eml) | Microsoft "Unusual Signin Activity" lure | Phishing | `none` | `none` | `permerror` |
| [email-02](./samples/email-02-authentication-issue.eml) | Bradesco Prime points expiration lure | Phishing | `temperror` | `none` | `temperror` (`compauth=fail`) |
| [email-03](./samples/email-03-legitimate-baseline.eml) | Personal Gmail communication | Legitimate Baseline | `pass` | `pass` | `pass` |

All phishing samples were sourced from the [`rf-peixoto/phishing_pot`](https://github.com/rf-peixoto/phishing_pot) research repository.

---

## Key Findings

- **Email-01 (Microsoft Impersonation Phishing):** The email attempted to impersonate Microsoft security notifications. The visible sender domain (`access-accsecurity.com`) and envelope sender domain (`thcultarfdes.co.uk`) were completely dissociated. Neither domain published SPF or DMARC records, and no DKIM signature was present. The message body hijacked victim responses via `mailto:` links pointing to a private Gmail account (`sotrecognizd@gmail.com`) and embedded a hidden 1x1 tracking beacon (`thebandalisty.com`). Both domains have since expired (NXDOMAIN).
- **Email-02 (Bradesco Financial Impersonation Phishing):** The email was dispatched from a DigitalOcean VPS (`137.184.34.4`) with the envelope sender set to the default non-FQDN hostname `root@ubuntu-s-1vcpu-1gb-35gb-intel-sfo3-06`. This bare hostname caused SPF and DMARC queries to time out (`temperror`), but Microsoft Exchange Online Protection correctly flagged the message via composite authentication (`compauth=fail reason=001`). The body linked to a fraudulent points-redemption landing page (`blog1seguimentmydomain2bra.me`).
- **Email-03 (Legitimate Baseline):** Delivered directly across Google mail infrastructure (`209.85.220.41`). SPF, DKIM (selector `20251104`), and DMARC all passed with strict domain alignment, confirming message origin and transmission integrity.

---

## Methodology & Key Technical Insights

1. **Envelope Sender vs Visible Sender:** SPF validates the sending IP against the domain found in the SMTP `MAIL FROM` command (reflected as `Return-Path:`), **not** the visible `From:` header. A difference between `From:` and `Return-Path:` is common in third-party services, but in phishing, it often reveals unauthenticated throwaway domains.
2. **Understanding `none` and `temperror`:** Neither result represents an authentication pass. SPF `none` indicates missing records, while `temperror` signifies DNS resolution timeouts (frequently triggered when attackers fail to configure an FQDN on VPS mail servers).
3. **DMARC Result vs DMARC Policy:** `dmarc=permerror` or `dmarc=fail` is the observed evaluation result at the receiving mail server. The domain's published policy (`p=none`, `p=quarantine`, `p=reject`) determines enforcement. When a domain publishes no policy or `p=none`, receiving servers will not reject failing mail unless local composite heuristics override delivery.
4. **Disposable Phishing Infrastructure:** Threat actors frequently register lookalike domains or spin up cheap cloud servers for short-lived campaigns. During investigation, four of the extracted indicator domains (`access-accsecurity.com`, `thcultarfdes.co.uk`, `thebandalisty.com`, `blog1seguimentmydomain2bra.me`) had already become defunct (NXDOMAIN). Historical headers preserve the evidentiary trail.

---

## Analysis Documents & Reports

| Document | Scope |
|---|---|
| [Header Analysis](./analysis/header-analysis.md) | Granular breakdown of identity fields, routing hops, and body markers across all samples |
| [SPF / DKIM / DMARC Analysis](./analysis/spf-dkim-dmarc-analysis.md) | Technical protocol specifications, DNS queries, and alignment outcomes |
| [IOC Analysis](./analysis/ioc-analysis.md) | Indicators of compromise, defanged URLs, Cisco Talos IP lookups, and limitations |
| [IR-001 — Phishing Report](./reports/IR-001-phishing.md) | Full incident report on Microsoft security alert lure |
| [IR-002 — Authentication Issue Report](./reports/IR-002-spoofing.md) | Full incident report on Bradesco points redemption lure |
| [IR-003 — Legitimate Baseline](./reports/IR-003-baseline.md) | Full incident report on Google infrastructure baseline comparison |

---

## Tools Used

- **Header Parsing & Hop Visualization:** Google Admin Toolbox (Messageheader), MXToolbox
- **DNS Record Queries:** PowerShell `nslookup` (TXT queries for SPF, DKIM selectors, and DMARC)
- **Threat Intelligence & IP Reputation:** Cisco Talos Intelligence Center, VirusTotal
- **Analysis Environment:** Visual Studio Code / Antigravity IDE, PowerShell

---

## Disclaimer

This repository is for educational and portfolio demonstration purposes. All investigated samples were obtained from public research repositories or benign communications. All suspicious URLs and email indicators are defanged using `hxxp` and `[.]` conventions.

---

*Analyst: Mustak · October 2026*
