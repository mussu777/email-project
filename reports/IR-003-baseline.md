# IR-003 — Legitimate Baseline Analysis
**Analyst:** Mustak  
**Date of Analysis:** 12 October 2026  
**Sample File:** `samples/email-03-legitimate-baseline.eml`  
**Sample Source:** Personal communication received on 05 October 2026  
**Classification:** Legitimate — Correctly Authenticated Email (Baseline)  
**Severity:** None  

---

## 1. Purpose

This baseline analysis examines a standard legitimate email exchanged over Google infrastructure. It establishes an authoritative reference for how correctly configured email authentication protocols (SPF, DKIM, DMARC, and ARC) behave in production, creating an analytical contrast against the anomalous and failing mechanisms identified in IR-001 and IR-002.

---

## 2. Evidence

### 2.1 Sender Identity

| Field | Value | Observation |
|---|---|---|
| `From:` | `reach rakesh <reach.rakeshjru@gmail.com>` | Legitimate personal sender |
| `Return-Path:` | `<reach.rakeshjru@gmail.com>` | Matches the visible `From:` address exactly |
| `Reply-To:` | *Not present* | Replies route directly to the sender's authenticated mailbox |
| `Subject:` | `Test` | Standard non-coercive subject line |
| `Date:` | `Mon, 05 Oct 2026 16:48:52 +0530` | Header timestamp |
| `Message-ID:` | `<CAD2TNP1L5g9nSgBCMxR-84F5Nj2cXS1sQjm8Kj1LW-AQ7geHxw@mail.gmail.com>` | Domain is `mail.gmail.com` — fully consistent with Google origin |

**Interpretation:**  
All identity indicators are internally aligned. The SMTP envelope sender matches the `From:` header exactly, satisfying strict domain alignment conditions.

### 2.2 Routing

**Received Chain (chronological order):**
```
Hop 1: from mail-sor-f41.google.com (mail-sor-f41.google.com. [209.85.220.41])
  by mx.google.com with SMTPS id ...; Mon, 05 Oct 2026 04:19:04 -0700 (PDT)
Hop 2 (Final): by 2002:a05:6e02:118f:b0:426:7bc2:a78c with SMTP id ...;
  Mon, 05 Oct 2026 04:19:04 -0700 (PDT)
```

**Observations:**  
Delivery occurred strictly across authenticated Google mail infrastructure. The sending host `209.85.220.41` belongs to Google's published IP blocks referenced by `_spf.google.com`.

### 2.3 Authentication Results

**Authentication-Results header recorded by receiving Google MTA:**
```
Authentication-Results: mx.google.com;
  dkim=pass header.i=@gmail.com header.s=20251104 header.b=mjCPQAWQ;
  arc=pass (i=1);
  spf=pass (google.com: domain of reach.rakeshjru@gmail.com designates 209.85.220.41 as permitted sender)
    smtp.mailfrom=reach.rakeshjru@gmail.com;
  dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
  dara=pass header.i=@gmail.com
```

| Protocol | Result (observed) | Detail |
|---|---|---|
| **SPF** | `pass` | The sending IP `209.85.220.41` is explicitly covered by `_spf.google.com` (included via `gmail.com`). Envelope sender matches `reach.rakeshjru@gmail.com`. |
| **DKIM** | `pass` | Valid cryptographic signature for domain `gmail.com` with selector `20251104`. Validates body hash and message integrity. |
| **DMARC** | `pass` | Both SPF and DKIM satisfy strict domain alignment with `From: gmail.com`. Published DMARC policy is `p=none; sp=quarantine`. |
| **ARC** | `pass (i=1)` | Authenticated Received Chain validates Google internal handling. |

**Alignment summary:**
- SPF alignment: Strict Pass (`gmail.com` == `gmail.com`).
- DKIM alignment: Strict Pass (`d=gmail.com` == `From: gmail.com`).
- DMARC outcome: Complete Pass.

### 2.4 Body Content

The message body contains benign plain-text content without tracking beacons, obfuscated hyperlinks, disguised scripts, or social engineering triggers.

---

## 3. Assessment & Comparative Analysis

**Classification:** Legitimate — Correctly Authenticated Email  
**Confidence:** High  

### Key Differences Observed in Comparison to IR-001 & IR-002:

| Metric | Sample 01 (Phishing) | Sample 02 (Phishing / Auth Issue) | Sample 03 (Baseline) |
|---|---|---|---|
| **Envelope vs From** | Mismatch (`thcultarfdes.co.uk` vs `access-accsecurity.com`) | Malformed bare hostname (`ubuntu-s-1vcpu...`) | Exact Match (`gmail.com` == `gmail.com`) |
| **SPF Result** | `none` (missing TXT record) | `temperror` (DNS timeout on bare hostname) | `pass` (authorized Google MTA) |
| **DKIM Integrity** | `none` (unsigned) | `none` (unsigned) | `pass` (valid RSA-SHA256 signature) |
| **DMARC Result** | `permerror` | `temperror` | `pass` |
| **Body / Links** | Hidden tracking beacon & Reply-To hijacking | Base64-obfuscated fraudulent landing URL | Clean text |

---

## 4. Recommended Actions

None required. This entry serves as the analytical baseline for the Email Threat Investigation Lab.

---

## 5. Evidence References

| Evidence Item | Location |
|---|---|
| Original Sample | [`samples/email-03-legitimate-baseline.eml`](../samples/email-03-legitimate-baseline.eml) |
| Header Analysis | [`analysis/header-analysis.md`](../analysis/header-analysis.md) — Sample 03 |
| SPF / DKIM / DMARC | [`analysis/spf-dkim-dmarc-analysis.md`](../analysis/spf-dkim-dmarc-analysis.md) — Email-03 |



