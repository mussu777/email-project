# IR-001 — Phishing Email Investigation
**Analyst:** Mustak  
**Date of Analysis:** 10 October 2026  
**Sample File:** `samples/email-01-phishing.eml`  
**Sample Source:** `rf-peixoto/phishing_pot` research repository  
**Classification:** Phishing — Brand Impersonation / Credential & Activity Harvesting  
**Severity:** High  

---

## 1. Summary

An email was received purporting to originate from the "Microsoft account security team" informing the recipient of "unusual signin activity" from Moscow, Russia. The visible sender domain (`access-accsecurity.com`) has no relationship with Microsoft. The SMTP envelope sender (`bounce@thcultarfdes.co.uk`) differs completely from the `From:` header. Authentication checks recorded by Microsoft Exchange Online Protection (EOP) revealed that SPF returned `none` (no SPF record for the sending domain), DKIM was `none` (no cryptographic signature), and DMARC evaluated to `permerror action=none`. All interactive elements ("Report The User" button and unsubscribe link) redirect user communication to an attacker-controlled Gmail collection inbox (`sotrecognizd@gmail.com`), while an invisible 1x1 tracking pixel was embedded in the body. Based on brand impersonation, authentication failures, reply redirection, and deceptive indicators, this email is classified as phishing with high confidence.

---

## 2. Evidence

### 2.1 Sender Identity

| Field | Value | Observation |
|---|---|---|
| `From:` | `Microsoft account team <no-reply@access-accsecurity.com>` | Display name impersonates Microsoft; sending domain `access-accsecurity.com` is unrelated |
| `Return-Path:` | `<bounce@thcultarfdes.co.uk>` | Envelope-sender domain differs completely from `From:`; SPF ran against `thcultarfdes.co.uk` |
| `Reply-To:` | `sotrecognizd@gmail.com` | Responses directed to a free consumer Gmail address |
| `Subject:` | `Microsoft account unusual signin activity` | Security alert lure creating urgency and fear |
| `Date:` | `Fri, 8 Sep 2023 05:47:04 +0000` | Timestamp from header |
| `X-Sender-IP:` | `89.144.44.2` | The submitting external host |

**Interpretation:**  
The difference between the `From:` and `Return-Path:` domains indicates that the sending infrastructure is dissociated from the claimed display domain. In legitimate business email, third-party sending services can cause a mismatch; however, here neither domain belongs to Microsoft, both domains are currently defunct (NXDOMAIN), and replies are routed to a private Gmail account.

### 2.2 Routing

**Received Chain (chronological order):**
```
Hop 1 (Submitting): from thcultarfdes.co.uk (89.144.44.2)
  by DB8EUR06FT032.eop-eur06.prod.protection.outlook.com
  with HTTPS; Fri, 8 Sep 2023 05:47:04 +0000
Hop 2 (Internal): by SJ0PR19MB6679.namprd19.prod.outlook.com
  via DB8EUR06FT032.eop-eur06.prod.protection.outlook.com; Fri, 8 Sep 2023 05:47:04 +0000
Hop 3 (Delivery): by MN0PR19MB6312.namprd19.prod.outlook.com; Fri, 8 Sep 2023 05:47:05 +0000
```

**Observations:**  
The email was submitted directly to Microsoft's Exchange Online Protection gateway from IP `89.144.44.2`. The single external hop confirms direct submission by the attacker's server without intermediate relay hops.

### 2.3 Authentication Results

**Authentication-Results header recorded by receiving server:**
```
Authentication-Results: spf=none (sender IP is 89.144.44.2)
  smtp.mailfrom=thcultarfdes.co.uk; dkim=none (message not signed)
  header.d=none; dmarc=permerror action=none header.from=access-accsecurity.com;
```

| Protocol | Result (observed) | Detail |
|---|---|---|
| **SPF** | `none` | Evaluated against `thcultarfdes.co.uk`. The domain published no SPF TXT record (query returns NXDOMAIN). The sending IP `89.144.44.2` was therefore unauthenticated. |
| **DKIM** | `none` | No `DKIM-Signature:` header present. There is no cryptographic proof of message integrity or origin. |
| **DMARC** | `permerror` | Microsoft EOP could not evaluate DMARC for `access-accsecurity.com`. DNS queries return NXDOMAIN. `action=none` indicates no enforcement occurred at delivery. |

**Alignment summary:**
- SPF alignment: Fails (`thcultarfdes.co.uk` ≠ `access-accsecurity.com`).
- DKIM alignment: Absent (no signature).
- DMARC outcome: Fails / permanent error.

### 2.4 Body Content Indicators

| Indicator | Detail |
|---|---|
| Visual Impersonation | Replicas of Microsoft branding, including `#2672ec` blue buttons and Segoe UI fonts |
| Fabricated Security Event | Claims an unauthorised sign-in from Moscow, Russia (`103.225.77.255`) on Firefox/Windows 10 |
| Action Button Hijack | The "Report The User" button links to: `mailto:sotrecognizd@gmail.com?subject=I%20didn%27t%20recognize%20this%20activity` |
| Tracking Pixel | Hidden `1x1` image pointing to `hxxp://thebandalisty[.]com/track/o43062rdzGz...` to confirm inbox delivery |
| Anti-Spam Evasion | Large block of nonsense CSS selectors in `<style>` tags designed to dilute text-to-code ratios |

### 2.5 IOC Lookup Results

| Indicator | Type | Lookup Tool | Result |
|---|---|---|---|
| `access-accsecurity[.]com` | Domain | DNS / Public Records | Defunct (NXDOMAIN); short-lived lookalike domain |
| `thcultarfdes[.]co.uk` | Domain | DNS / Public Records | Defunct (NXDOMAIN); temporary sending domain |
| `89.144.44.2` | IP | Cisco Talos | **Neutral** reputation; Location: Warsaw, Poland; Host: `r2.mscode.pl`; Network: GHOSTNET GMBH. Not listed on Spamhaus or SpamCop |
| `sotrecognizd@gmail[.]com` | Email | Manual Analysis | Free webmail account configured as collection point |
| `thebandalisty[.]com` | Domain | DNS / VT Intelligence | Defunct (NXDOMAIN); previously observed as email tracking beacon |

---

## 3. Classification and Reasoning

**Classification:** Phishing — Brand Impersonation & Collection  
**Confidence:** High  

**Reasoning:**  
1. **Brand Fraud:** The message attempts to represent the Microsoft Account Team while originating from an unassociated domain (`access-accsecurity.com`).
2. **Complete Authentication Breakdown:** Total absence of valid SPF records and DKIM signatures, failing DMARC alignment completely.
3. **Attacker-Controlled Destination:** Interactive elements do not lead to official Microsoft verification portals (`account.microsoft.com`), but route directly to an individual Gmail inbox.
4. **Active Tracking:** Embedding an external tracking beacon confirms intentional reconnaissance against the recipient.

---

## 4. Recommended Response Actions

1. **Defensive Gateway Blocking:**
   - Block domains: `access-accsecurity.com`, `thcultarfdes.co.uk`, and `thebandalisty.com`.
   - Add inbound transport rule to block or quarantine mail referencing `sotrecognizd@gmail.com` in `Reply-To` or body hyperlinks.
2. **IP Mitigation:**
   - Monitor / rate-limit traffic from `89.144.44.2` at the perimeter email gateway.
3. **Internal Remediation:**
   - Query Microsoft 365 / gateway message trace logs for messages with Subject `"Microsoft account unusual signin activity"` or sender `*@access-accsecurity.com`.
   - Purge matching messages from affected mailboxes.
   - Confirm whether any user replied to the `sotrecognizd@gmail.com` address.

---

## 5. Evidence References

| Evidence Item | Location |
|---|---|
| Original Sample | [`samples/email-01-phishing.eml`](../samples/email-01-phishing.eml) |
| Header Analysis | [`analysis/header-analysis.md`](../analysis/header-analysis.md) — Sample 01 |
| SPF / DKIM / DMARC | [`analysis/spf-dkim-dmarc-analysis.md`](../analysis/spf-dkim-dmarc-analysis.md) — Email-01 |
| IOC Documentation | [`analysis/ioc-analysis.md`](../analysis/ioc-analysis.md) — IOC-01 to IOC-05 |
| Talos Screenshot 1 | [`screenshots/email-01-ip-talos.png`](../screenshots/email-01-ip-talos.png) |
| Talos Screenshot 2 | [`screenshots/email-01-ip-talos2.png`](../screenshots/email-01-ip-talos2.png) |

---


