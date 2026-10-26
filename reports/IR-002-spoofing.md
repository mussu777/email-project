# IR-002 — Authentication Issue Investigation
**Analyst:** Mustak  
**Date of Analysis:** 11 October 2026  
**Sample File:** `samples/email-02-authentication-issue.eml`  
**Sample Source:** `rf-peixoto/phishing_pot` research repository  
**Classification:** Phishing — Financial Brand Impersonation / Fake Points Redemption  
**Severity:** High  

---

## 1. Summary

An email was received claiming to be from Banco do Bradesco / Livelo (a major Brazilian banking loyalty program), alerting the recipient that 92,990 loyalty points were expiring immediately. Inspection of the headers revealed severe authentication anomalies: the visible sender domain was `atendimento.com.br`, but the SMTP envelope sender was configured as `root@ubuntu-s-1vcpu-1gb-35gb-intel-sfo3-06` — an unconfigured bare hostname on a DigitalOcean Virtual Private Server. This non-FQDN envelope sender caused SPF and DMARC evaluations to return `temperror` due to DNS lookup timeouts. Microsoft's Exchange Online Protection assigned a composite authentication failure (`compauth=fail reason=001`). Base64 body decoding revealed a fraudulent call-to-action button redirecting users to an external landing page (`hxxps://blog1seguimentmydomain2bra[.]me/`). Based on the combination of brand impersonation, cloud VPS origin, envelope sender malformation, and malicious landing URL, this email is classified as phishing with high confidence.

---

## 2. Evidence

### 2.1 Sender Identity

| Field | Value | Observation |
|---|---|---|
| `From:` | `BANCO DO BRADESCO LIVELO <banco.bradesco@atendimento.com.br>` | Display name impersonates Banco do Bradesco; `atendimento.com.br` is not the bank's official domain (`bradesco.com.br`) |
| `Return-Path:` | `<root@ubuntu-s-1vcpu-1gb-35gb-intel-sfo3-06>` | Bare hostname envelope sender; reveals root execution on a 1 vCPU / 1GB DigitalOcean droplet |
| `Reply-To:` | *Not present* | Standard default routing |
| `Subject:` | `CLIENTE PRIME - BRADESCO LIVELO: Seu cartão tem 92.990 pontos LIVELO expirando hoje!` | High-urgency points expiration social engineering |
| `Date:` | `Tue, 19 Sep 2023 18:35:49 +0000` | Header timestamp |
| `Message-ID:` | `<20230919183549.39DEA3F725@ubuntu-s-1vcpu-1gb-35gb-intel-sfo3-06>` | Hostname matches Return-Path; indicates direct injection from Postfix MTA |
| `X-Sender-IP:` | `137.184.34.4` | Originating DigitalOcean IP address |

**Interpretation:**  
The envelope sender (`Return-Path:`) completely fails standard RFC conventions by omitting a Fully Qualified Domain Name (FQDN). Attackers deploying automated mass-mailing scripts on newly created virtual servers frequently leave default OS hostnames (`ubuntu-s-1vcpu-1gb...`) intact.

### 2.2 Routing

**Received Chain (chronological order):**
```
Hop 1 (Submitting): from ubuntu-s-1vcpu-1gb-35gb-intel-sfo3-06 (137.184.34.4)
  by BN8NAM11FT066.eop-nam11.prod.protection.outlook.com
  with HTTPS; Tue, 19 Sep 2023 18:36:45 +0000
Hop 2 (Internal): by BN0PR03CA0023.namprd03.prod.outlook.com
  via BN8NAM11FT066.eop-nam11.prod.protection.outlook.com; Tue, 19 Sep 2023 18:36:46 +0000
Hop 3 (Delivery): by SA3PR19MB7370.namprd19.prod.outlook.com → MN0PR19MB6312; Tue, 19 Sep 2023 18:36:47 +0000
```

**Observations:**  
The email was routed directly from the single DigitalOcean instance `137.184.34.4` to Microsoft EOP. The local Received header indicates mail submission via Postfix by user ID 0 (`root`).

### 2.3 Authentication Results

**Authentication-Results header recorded by receiving server:**
```
Authentication-Results: spf=temperror (sender IP is 137.184.34.4)
  smtp.mailfrom=ubuntu-s-1vcpu-1gb-35gb-intel-sfo3-06; dkim=none (message not signed)
  header.d=none; dmarc=temperror action=none header.from=atendimento.com.br;
  compauth=fail reason=001
```

| Protocol | Result (observed) | Detail |
|---|---|---|
| **SPF** | `temperror` | Evaluated against `ubuntu-s-1vcpu-1gb-35gb-intel-sfo3-06`. Because this is not an FQDN, DNS TXT queries timed out, producing an indeterminate `temperror` rather than a clean `fail`. |
| **DKIM** | `none` | No `DKIM-Signature:` header present on the message. |
| **DMARC** | `temperror` | Incomplete evaluation resulting from SPF timeout and missing DKIM. Live DNS queries for `_dmarc.atendimento.com.br` confirm no DMARC record is published. `action=none` indicates no policy enforcement. |
| **CompAuth** | `fail (001)` | Microsoft EOP composite authentication heuristic flagged the sender as fraudulent despite the DNS protocol timeouts. |

**Alignment summary:**
- SPF alignment: Indeterminate / Fails.
- DKIM alignment: Absent.
- DMARC outcome: Indeterminate / Fails.

### 2.4 Body Content Indicators

| Indicator | Detail |
|---|---|
| Targeted Financial Lure | Lure targets customers of Bradesco Prime and Livelo reward points |
| Artificial Urgency | Claims points will expire on the date of delivery ("expirando hoje!") |
| Malicious Hyperlink | Base64-decoded HTML reveals call-to-action button ("Resgatar Agora") pointing to: `hxxps://blog1seguimentmydomain2bra[.]me/` |
| Lookalike URL Pattern | Domain `blog1seguimentmydomain2bra[.]me` uses a Portuguese tracking string and `.me` ccTLD, mimicking Portuguese phrasing while having zero connection to Bradesco |

### 2.5 IOC Lookup Results

| Indicator | Type | Lookup Tool | Result |
|---|---|---|---|
| `blog1seguimentmydomain2bra[.]me` | Domain / URL | DNS / WHOIS | Defunct (NXDOMAIN); temporary credential harvesting landing page |
| `137.184.34.4` | IP | Cisco Talos | **Neutral** reputation; Location: Santa Clara, CA, USA; Host: `1627707.cloudwaysapps.com`; Owner: DIGITAL OCEAN INC. Not on SpamCop or Spamhaus lists |
| `atendimento.com.br` | Domain | DNS Query | Cloudflare DNS; no SPF TXT or DMARC records published |

---

## 3. Classification and Reasoning

**Classification:** Phishing — Brand Impersonation & Malicious Landing Page  
**Confidence:** High  

**Reasoning:**  
1. **Misconfigured / Disposable Infrastructure:** Real financial institutions operate hardened mail relays with valid reverse DNS, DKIM signing, and strict DMARC policies (`p=reject`). A bare VPS sending as `root` with a non-FQDN envelope sender is characteristic of ephemeral attack nodes.
2. **Composite Authentication Flag:** Microsoft EOP flagged the message with `compauth=fail` (reason 001), recognizing the domain mismatch and spoofing characteristics.
3. **Deceptive Landing Destination:** The body directs recipients to an unverified `.me` domain specifically formatted to mimic Portuguese brand terminology.

---

## 4. Recommended Response Actions

1. **Gateway Perimeter Blocking:**
   - Block landing domain `blog1seguimentmydomain2bra.me` and IP `137.184.34.4`.
   - Implement gateway rule to reject inbound SMTP sessions where the `MAIL FROM` envelope domain is not a fully qualified domain name (non-FQDN reject).
2. **Domain Protection Advice:**
   - For legitimate domain administrators of `atendimento.com.br`, publish strict SPF records (`-all`) and DMARC policies (`p=reject`) to eliminate domain abuse.
3. **Incident Containment:**
   - Search mail logs for messages delivered from `137.184.34.4` or linking to `blog1seguimentmydomain2bra.me`.
   - Verify web proxy / EDR telemetry for any outbound traffic to `blog1seguimentmydomain2bra.me` from internal workstations.

---

## 5. Evidence References

| Evidence Item | Location |
|---|---|
| Original Sample | [`samples/email-02-authentication-issue.eml`](../samples/email-02-authentication-issue.eml) |
| Header Analysis | [`analysis/header-analysis.md`](../analysis/header-analysis.md) — Sample 02 |
| SPF / DKIM / DMARC | [`analysis/spf-dkim-dmarc-analysis.md`](../analysis/spf-dkim-dmarc-analysis.md) — Email-02 |
| IOC Documentation | [`analysis/ioc-analysis.md`](../analysis/ioc-analysis.md) — IOC-06 to IOC-07 |
| Talos Screenshot 1 | [`screenshots/email-02-ip-talos.png`](../screenshots/email-02-ip-talos.png) |
| Talos Screenshot 2 | [`screenshots/email-02-ip-talos2.png`](../screenshots/email-02-ip-talos2.png) |




