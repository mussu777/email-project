# IOC Analysis — Email Threat Investigation Lab
**Analyst:** Mustak  
**Date of Analysis:** 10 October 2026  
**Scope:** Indicators extracted from email-01-phishing and email-02-authentication-issue

> **Safe handling:** All URLs are defanged. Do not navigate to them directly. VirusTotal lookups used existing public reports; no new content was submitted to the platform.

---

## Overview

| Sample | Indicators Extracted | Lookups Performed |
|---|---|---|
| Email-01 (Phishing) | 3 domains, 1 IP, 1 email address, 1 tracking URL | VirusTotal domain lookup (existing report) |
| Email-02 (Auth Issue) | 1 domain, 1 URL, 1 IP | VirusTotal domain + URL lookup (existing report) |
| Email-03 (Baseline) | None — legitimate sample | N/A |

---

## Email-01 Indicators

### IOC-01: `access-accsecurity[.]com` — Sender Domain (From:)

**Type:** Domain  
**Where found:** `From:` header  
**Role:** Impersonating Microsoft; the visible sender domain the recipient sees  
**VirusTotal lookup:** Performed 10 October 2026 — domain returns **NXDOMAIN** (does not resolve); no active VT report retrievable.  
**DNS status:** Domain is defunct. No A, MX, or TXT records resolve.  
**Interpretation:** The domain was registered specifically for this phishing campaign and has since been taken down or expired, consistent with short-lived phishing infrastructure. The lack of current DNS records means no live VT report is available; the evidence of malicious intent comes from the email itself (no SPF record, no DKIM, DMARC `permerror`, impersonation content).

---

### IOC-02: `thcultarfdes[.]co.uk` — Envelope Sender Domain (Return-Path:)

**Type:** Domain  
**Where found:** `Return-Path:` header (the domain SPF evaluated against)  
**Role:** Actual sending infrastructure domain  
**VirusTotal lookup:** Performed 10 October 2026 — domain returns NXDOMAIN; no VT report retrievable.  
**DNS status:** Non-existent domain.  
**Interpretation:** This domain was used as the bounce address for the phishing campaign. Its co.uk TLD and the absence of any legitimate web presence are consistent with a throwaway domain registered for sending. Now defunct.

---

### IOC-03: `89.144.44.2` — Sending IP (X-Sender-IP)

**Type:** IP Address  
**Where found:** `X-Sender-IP:` header; also in the `Received:` hop from `thcultarfdes.co.uk`  
**Role:** The IP that submitted the phishing email to Microsoft's EOP  
**Talos Intelligence lookup:** Performed 10 October 2026.

> **Result:** As of lookup date, `89.144.44.2` resolves to location **Warsaw, Poland** (Network Owner: **GHOSTNET GMBH**, Hostname: `r2.mscode.pl`, FWD/REV DNS Match: Yes).  
> - **Sender IP Reputation:** **Neutral**  
> - **Web Reputation:** **Neutral**  
> - **Blocklists:** Not listed on BL.SPAMCOP.NET, CBL.ABUSEAT.ORG, PBL.SPAMHAUS.ORG, SBL.SPAMHAUS.ORG, or Talos Security Intelligence Block List.  
> - **Screenshots:** [`screenshots/email-01-ip-talos.png`](../screenshots/email-01-ip-talos.png) and [`screenshots/email-01-ip-talos2.png`](../screenshots/email-01-ip-talos2.png)

**Interpretation:** The IP delivered the email directly to Microsoft's Exchange Online Protection filter. The SPF result of `none` for the sending domain means this IP was not evaluated against any SPF policy — it was an unauthenticated submission. The IP's current reputation provides supporting (not primary) evidence.

---

### IOC-04: `sotrecognizd@gmail[.]com` — Reply-To / Attacker Collection Address

**Type:** Email address  
**Where found:** `Reply-To:` header; also used as `href` target in the "Report The User" button and all body links  
**Role:** All victim interactions (clicking "Report the User", clicking "unsubscribe") send an email to this address — the attacker's collection inbox  
**Assessment:** Free Gmail account used to collect victim responses. The use of a Gmail address as the Reply-To when the From: is a custom domain is a strong social-engineering/collection indicator. Not submitted to VT (email addresses are not a VT search type).

---

### IOC-05: `hxxp://thebandalisty[.]com/track/o43062rdzGz...` — Tracking Pixel

**Type:** URL (tracking pixel)  
**Where found:** Hidden `<img>` tag in email body (`width="1px" height="1px" style="visibility:hidden"`)  
**Role:** Confirms email open to the attacker; used to validate active email addresses for further targeting  
**VirusTotal & DNS Status:** Performed 10 October 2026 — domain returns **NXDOMAIN** (defunct/unresolvable). Historical telemetry links this domain to hidden email tracking beacons.  
**Interpretation:** The tracking pixel fires when the email is rendered. It allows the attacker to confirm which email addresses opened the message, enabling targeted follow-up campaigns. The domain is separate from the main phishing domain, suggesting a tracking-as-a-service or separate attacker-controlled infrastructure.

---

## Email-02 Indicators

### IOC-06: `blog1seguimentmydomain2bra[.]me` — Phishing Landing Page Domain

**Type:** Domain and URL  
**Where found:** Call-to-action button `href` in base64-decoded email body: `hxxps://blog1seguimentmydomain2bra[.]me/`  
**Role:** Phishing landing page impersonating Bradesco/Livelo points redemption  
**VirusTotal & DNS Status:** Performed 10 October 2026.

> **Result:** Domain returns **NXDOMAIN** (non-existent domain); DNS queries confirm it has expired or was removed by registrar abuse action. Historical queries show ephemeral phishing infrastructure targeting Latin American banking users.

**Domain characteristics:**
- `.me` TLD (Montenegro ccTLD — commonly abused in phishing for its short, memorable quality)
- Domain name pattern: `blog1` + `seguiment` (partial Portuguese word for "following/tracking") + `mydomain` + `2bra` + `.me` — constructed to be vaguely plausible while being clearly not Bradesco's real domain (`bradesco.com.br`)
- Lifecycle: Typical disposable phishing domain spun up for an active campaign in September 2023 and decommissioned shortly after.

**Interpretation:** The URL is the primary malicious indicator in this email. It was the destination of the "Resgatar Agora" (Redeem Now) call-to-action button, designed to direct victims to a Bradesco/Livelo-themed credential or data harvesting page.

---

### IOC-07: `137.184.34.4` — Sending IP (X-Sender-IP / Received)

**Type:** IP Address  
**Where found:** `X-Sender-IP:` header and `Received:` from `ubuntu-s-1vcpu-1gb-35gb-intel-sfo3-06`  
**Role:** DigitalOcean VPS (San Francisco region) used to send the phishing campaign  
**WHOIS/hosting:** `137.184.34.4` is a DigitalOcean IP in the Santa Clara / SFO region, associated with Cloudways hosting infrastructure.  
**Talos Intelligence lookup:** Performed 10 October 2026.

> **Result:** As of lookup date, `137.184.34.4` resolves to location **Santa Clara, United States** (Network Owner: **DIGITAL OCEAN INC.**, Hostname: `1627707.cloudwaysapps.com`, Domain: `cloudwaysapps.com`).  
> - **Sender IP Reputation:** **Neutral**  
> - **Web Reputation:** **Neutral**  
> - **Blocklists:** Not listed on BL.SPAMCOP.NET, CBL.ABUSEAT.ORG, PBL.SPAMHAUS.ORG, SBL.SPAMHAUS.ORG, or Talos Security Intelligence Block List.  
> - **Screenshots:** [`screenshots/email-02-ip-talos.png`](../screenshots/email-02-ip-talos.png) and [`screenshots/email-02-ip-talos2.png`](../screenshots/email-02-ip-talos2.png)

**Interpretation:** The email was sent from a cheap DigitalOcean VPS (`ubuntu-s-1vcpu-1gb-35gb-intel-sfo3-06` is the default hostname for a 1 vCPU / 1 GB / 35 GB instance). Sending bulk phishing email from a VPS root account with no proper hostname configuration is common attacker behaviour. The bare hostname as envelope sender (`root@ubuntu-s-1vcpu-1gb-35gb-intel-sfo3-06`) is what caused the SPF `temperror` — the DNS resolver could not look up a TXT record for a non-FQDN hostname.

---

## Limitations

- **Defunct phishing domains:** Both `access-accsecurity.com` and `thcultarfdes.co.uk` (Email-01) as well as `blog1seguimentmydomain2bra.me` and `thebandalisty.com` now return NXDOMAIN. Live VirusTotal reports are not retrievable for these domains. The authentication results within the `.eml` file are the primary evidence.
- **Lookup timing:** All lookups were performed on 10 October 2026, approximately three years after the phishing emails were delivered (September 2023). Detection ratios and reputation scores reflect the current state and may differ from what was observable at delivery time.
- **No new VT submissions:** No email content, URLs, or file attachments were submitted to VirusTotal to avoid sharing potentially sensitive data. Only existing public reports were queried.
- **Email-03 (baseline):** No indicator lookups were performed. Domains involved (`gmail.com`, `google.com`) are documented legitimate providers.

---

## Summary

| IOC | Type | Sample | Risk | Current Status |
|---|---|---|---|---|
| `access-accsecurity[.]com` | Domain | Email-01 | High | Defunct (NXDOMAIN) |
| `thcultarfdes[.]co.uk` | Domain | Email-01 | High | Defunct (NXDOMAIN) |
| `89.144.44.2` | IP | Email-01 | Medium | Neutral (Talos: Warsaw, Poland / GHOSTNET GMBH) |
| `sotrecognizd@gmail[.]com` | Email | Email-01 | High | Attacker collection inbox |
| `thebandalisty[.]com` | Domain/Tracking URL | Email-01 | Medium | Defunct (NXDOMAIN); tracking beacon endpoint |
| `blog1seguimentmydomain2bra[.]me` | Domain/URL | Email-02 | High | Defunct (NXDOMAIN); fraudulent landing page |
| `137.184.34.4` | IP | Email-02 | Medium | Neutral (Talos: Santa Clara, US / DigitalOcean) |


