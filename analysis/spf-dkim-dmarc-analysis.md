# SPF / DKIM / DMARC Analysis — Email Threat Investigation Lab
**Analyst:** Mustak  
**Date:** 09 October 2026  
**Samples:** email-01-phishing · email-02-authentication-issue · email-03-legitimate-baseline

---

## 1. Protocol Overview

### 1.1 SPF — Sender Policy Framework (RFC 7208)

SPF allows a domain owner to publish in DNS the IP addresses authorised to send mail on that domain's behalf. **SPF checks the SMTP envelope-sender domain — the address in the `MAIL FROM` command, visible as the `Return-Path:` header — not the visible `From:` header shown to the recipient.** DMARC then separately checks whether the SPF-authenticated domain aligns with the visible `From:` domain.

**Reading an SPF record:**
```
v=spf1 include:_spf.google.com ~all
```

| Qualifier | Meaning |
|---|---|
| `-all` | Hard fail — reject anything not matched (strict) |
| `~all` | Soft fail — flag but do not reject (lenient) |
| `?all` | Neutral — no policy assertion |
| `+all` | Pass everything — insecure, never appropriate |

**SPF result values:**

| Result | Meaning |
|---|---|
| `pass` | Sending IP is authorised for the envelope-sender domain |
| `fail` | Sending IP is explicitly not authorised |
| `softfail` | IP not authorised under a lenient `~all` policy |
| `none` | No SPF record found for the envelope-sender domain |
| `temperror` | DNS lookup failed temporarily (e.g. timeout) — result is indeterminate, not a failure |
| `permerror` | SPF record has a permanent configuration error |

---

### 1.2 DKIM — DomainKeys Identified Mail (RFC 6376)

DKIM adds a cryptographic signature to the email at the sending server. The private key signs selected headers and the body; the public key is published in DNS at `<selector>._domainkey.<domain>`. A receiving server retrieves the public key, verifies the signature, and confirms that the message was not altered in transit.

DKIM proves that the signing domain sent (or approved) the message. DMARC then checks whether that signing domain aligns with the visible `From:` domain.

**Key DKIM-Signature tags:**

| Tag | Meaning |
|---|---|
| `a=` | Algorithm — `rsa-sha256` is current standard |
| `d=` | Signing domain |
| `s=` | Selector (identifies which public key in DNS) |
| `h=` | Headers covered by the signature |
| `bh=` | Hash of the message body |
| `b=` | The cryptographic signature |

**DKIM result values:**

| Result | Meaning |
|---|---|
| `pass` | Signature verified — message content not altered |
| `fail` | Signature invalid |
| `none` | No DKIM-Signature header present |
| `permerror` | Public key not found or record malformed |
| `temperror` | DNS lookup temporarily failed |

---

### 1.3 DMARC — Domain-based Message Authentication, Reporting & Conformance (RFC 7489)

DMARC ties SPF and DKIM together through **alignment**: for a message to pass DMARC, at least one of the following must hold:

- SPF passes **and** the SPF-authenticated domain (envelope sender) aligns with the `From:` domain, **or**
- DKIM passes **and** the DKIM signing domain (`d=`) aligns with the `From:` domain.

> **Important:** The **DMARC result** (`dmarc=pass` or `dmarc=fail` or `dmarc=temperror`) is the observed outcome recorded in `Authentication-Results:`. The **DMARC policy** (`p=none`, `p=quarantine`, `p=reject`) is what the domain owner has published in DNS. These are separate things. A domain with `p=none` that receives a `dmarc=fail` message will still deliver it — `p=none` means monitoring only, no enforcement action.

---

## 2. Per-Sample Authentication Results

### Email-01 — Phishing (Microsoft Impersonation)

**Authentication-Results header (as recorded by receiving Microsoft EOP server):**
```
Authentication-Results: spf=none (sender IP is 89.144.44.2)
  smtp.mailfrom=thcultarfdes.co.uk; dkim=none (message not signed)
  header.d=none; dmarc=permerror action=none header.from=access-accsecurity.com;
```

| Protocol | Observed Result | Detail |
|---|---|---|
| **SPF** | `none` | The envelope-sender domain is `thcultarfdes.co.uk`. No SPF TXT record exists for this domain — confirmed by DNS query returning NXDOMAIN (domain does not exist). The sending IP `89.144.44.2` therefore cannot be evaluated. |
| **DKIM** | `none` | No `DKIM-Signature:` header is present. There is no cryptographic evidence linking this message to any domain. |
| **DMARC** | `permerror` (observed result) | Microsoft EOP could not complete the DMARC evaluation for `access-accsecurity.com`. DNS query for `_dmarc.access-accsecurity.com` returns NXDOMAIN — domain no longer exists. At delivery time in 2023 the domain may have existed with no DMARC record, or it may already have been defunct. The `action=none` confirms no enforcement action was taken. |

**DNS queries performed (09 October 2026):**
```
nslookup -type=TXT thcultarfdes.co.uk
→ Non-existent domain (NXDOMAIN) — domain does not resolve

nslookup -type=TXT _dmarc.access-accsecurity.com
→ Non-existent domain (NXDOMAIN) — no DMARC record; domain does not resolve

nslookup -type=TXT access-accsecurity.com
→ Non-existent domain (NXDOMAIN) — domain does not resolve
```

> **Important limitation:** Both domains (`thcultarfdes.co.uk` and `access-accsecurity.com`) are now defunct — they no longer resolve. This is common for short-lived phishing infrastructure. The DNS results above reflect the current state (October 2026), not the state at delivery (September 2023). The authentication results recorded in the email itself are the authoritative evidence of what was evaluated at delivery time.

**Alignment analysis:**
- SPF alignment: SPF returned `none` (no record for the envelope-sender domain). The envelope-sender domain (`thcultarfdes.co.uk`) and `From:` domain (`access-accsecurity.com`) are different and neither has any connection to `microsoft.com`. Alignment fails.
- DKIM alignment: No DKIM signature — alignment cannot be evaluated.
- DMARC: `permerror` — evaluation could not be completed. Regardless, neither alignment condition is met.

**What this means:** The email cannot demonstrate any authorised connection to either `microsoft.com` or the domains it used. The absence of SPF records, DKIM, and a valid DMARC record are consistent with throwaway phishing infrastructure. Combined with the body content indicators documented in header-analysis.md, this supports a phishing classification.

---

### Email-02 — Authentication Issue (Bradesco Impersonation)

**Authentication-Results header (as recorded by receiving Microsoft EOP server):**
```
Authentication-Results: spf=temperror (sender IP is 137.184.34.4)
  smtp.mailfrom=ubuntu-s-1vcpu-1gb-35gb-intel-sfo3-06; dkim=none (message not signed)
  header.d=none; dmarc=temperror action=none header.from=atendimento.com.br;
  compauth=fail reason=001
```

| Protocol | Observed Result | Detail |
|---|---|---|
| **SPF** | `temperror` | The envelope sender is the bare VPS hostname `ubuntu-s-1vcpu-1gb-35gb-intel-sfo3-06` — not a proper domain. Microsoft's EOP attempted a DNS TXT lookup for this hostname and received a DNS timeout. `temperror` means the result is indeterminate — it is not a pass and not a clean fail. |
| **DKIM** | `none` | No `DKIM-Signature:` header present. |
| **DMARC** | `temperror` (observed result) | Because SPF returned `temperror` and DKIM is absent, DMARC could not reach a conclusive result. `action=none` — no enforcement action taken. Published policy for `atendimento.com.br`: see DNS query below. |

**DNS queries performed (09 October 2026):**
```
nslookup -type=TXT atendimento.com.br
→ Returns SOA record only; no SPF TXT record found.
  (Nameservers: casey.ns.cloudflare.com / dns.cloudflare.com)

nslookup -type=TXT _dmarc.atendimento.com.br
→ Returns SOA record only; no DMARC TXT record found.
```

**Alignment analysis:**
- SPF alignment: SPF `temperror` — no result to align. The envelope sender is a bare hostname (not a domain), which does not align with the `From:` domain (`atendimento.com.br`) regardless.
- DKIM alignment: No DKIM signature — cannot be evaluated.
- DMARC: `temperror` — indeterminate. No DMARC record published for `atendimento.com.br` (confirmed via DNS query), meaning even if both SPF and DKIM had passed, there would have been no DMARC policy to enforce.

**What this means:** The `temperror` results are specifically caused by the attacker using a bare VPS hostname as the envelope sender — a misconfiguration (accidental or deliberate) that prevents a clean SPF evaluation. The absence of DKIM and any DMARC record for the `From:` domain means the email has no authentication protections at all. Microsoft's `compauth=fail reason=001` indicates composite authentication failure — Microsoft's own heuristic flagged this message despite the inconclusive protocol results. The sending infrastructure (a DigitalOcean VPS running Postfix as root) is not consistent with a legitimate financial institution.

---

### Email-03 — Legitimate Baseline (Gmail to Gmail)

**Authentication-Results header (as recorded by receiving Google server):**
```
Authentication-Results: mx.google.com;
  dkim=pass header.i=@gmail.com header.s=20251104 header.b=mjCPQAWQ;
  arc=pass (i=1);
  spf=pass (google.com: domain of reach.rakeshjru@gmail.com designates
    209.85.220.41 as permitted sender) smtp.mailfrom=reach.rakeshjru@gmail.com;
  dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
  dara=pass header.i=@gmail.com
```

| Protocol | Observed Result | Detail |
|---|---|---|
| **SPF** | `pass` | Sending IP `209.85.220.41` is a documented Google mail server. The envelope-sender domain is `gmail.com` (via `reach.rakeshjru@gmail.com`). Google's SPF record redirects to `_spf.google.com`, which covers this IP. |
| **DKIM** | `pass` | `DKIM-Signature` present. Signing domain `d=gmail.com`, selector `s=20251104`. Signature verified successfully — message was not altered in transit. |
| **DMARC** | `pass` (observed result) | Both SPF alignment and DKIM alignment satisfied. Published policy: `p=NONE sp=QUARANTINE dis=NONE`. Note: `p=none` means Gmail does not enforce rejection of failing mail from its own domain — but in this case the result is pass, so policy action is irrelevant. |

**DNS queries performed (09 October 2026):**
```
nslookup -type=TXT gmail.com
→ "v=spf1 redirect=_spf.google.com"

nslookup -type=TXT _dmarc.gmail.com
→ "v=DMARC1; p=none; sp=quarantine; rua=mailto:mailauth-reports@google.com"
```

**Alignment analysis:**
- SPF alignment: Envelope-sender domain is `gmail.com` (from `reach.rakeshjru@gmail.com`). `From:` domain is `gmail.com`. Identical — strict alignment passes.
- DKIM alignment: Signing domain `d=gmail.com` matches `From:` domain `gmail.com`. Strict alignment passes.
- DMARC: Both conditions satisfied — `dmarc=pass`.

**What this means:** This email demonstrates a fully authenticated message from Google's infrastructure. All three protocols pass with strict alignment. The `DKIM-Signature` with selector `20251104` can be verified against Google's published public key. This is the expected result for a person-to-person Gmail message, and it serves as a baseline against which the failing samples are compared.

**Note on DMARC p=none for gmail.com:** Gmail publishes `p=none` for `gmail.com` — this means that if a message *failed* DMARC for `gmail.com`, Google would not instruct receiving servers to quarantine or reject it. This is a known trade-off for a consumer provider with billions of users. The policy does not affect this sample, which passes.

---

## 3. Comparative Summary

| | Email-01 (Phishing) | Email-02 (Auth Issue) | Email-03 (Baseline) |
|---|---|---|---|
| **SPF result** | `none` | `temperror` | `pass` |
| **SPF envelope-sender domain** | `thcultarfdes.co.uk` | bare hostname (not a domain) | `gmail.com` |
| **DKIM result** | `none` | `none` | `pass` |
| **DKIM signing domain** | not present | not present | `gmail.com` (s=20251104) |
| **DMARC result** | `permerror` | `temperror` | `pass` |
| **DMARC policy (published)** | no record (domain defunct) | no record found | `p=none` (gmail.com) |
| **SPF alignment** | Fails (different domains; no SPF record) | Cannot evaluate (temperror) | Passes (gmail.com = gmail.com) |
| **DKIM alignment** | N/A (no signature) | N/A (no signature) | Passes (d=gmail.com) |
| **Overall authentication** | All indeterminate/absent | All indeterminate/absent | All pass |

---

## 4. Key Takeaways from These Samples

1. **SPF `none` and `temperror` are not passes.** Both emails 01 and 02 avoided a clean `spf=fail` — Email-01 because the domain had no record, Email-02 because the envelope sender was a bare hostname. Neither result indicates the email was authorised.

2. **`dmarc=temperror` is indeterminate, not a pass.** Email-02's DMARC `temperror` reflects an inability to evaluate — not a clean result. It is evidence of a poorly configured sending setup, not of legitimacy.

3. **Absent DKIM means no tamper-evidence.** Both phishing samples have no `DKIM-Signature:`. There is no cryptographic link to any domain, and no way to verify the message was not modified in transit.

4. **DMARC result and DMARC policy are separate.** Email-03's `p=none` policy (Gmail) does not undermine the `dmarc=pass` result. For Email-01 and Email-02, the absence of any published DMARC record means no policy governs how receivers should treat those domains' mail.

5. **Current DNS results ≠ DNS results at delivery.** The phishing domains (`thcultarfdes.co.uk`, `access-accsecurity.com`) are now defunct (NXDOMAIN). The authentication results embedded in the `.eml` headers are the evidence of what was evaluated at delivery — later DNS lookups supplement but cannot replace that record.

---

