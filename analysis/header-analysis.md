# Header Analysis — Email Threat Investigation Lab
**Analyst:** Mustak  
**Date:** 08 October 2026  
**Samples:** email-01-phishing · email-02-authentication-issue · email-03-legitimate-baseline

---

## Purpose

This document records the header fields extracted from each email sample and explains what each field reveals about sender identity, routing, and authenticity. Headers are the primary evidence source in email threat investigation: they carry authentication results, routing hops, and sender-identity fields that the user never sees.

> **Methodology note:** Headers were read directly from each `.eml` file. Where a field was absent from a sample, it is recorded as *not present*.

---

## Key Header Fields — Reference

| Header Field | What It Tells You | Caveats |
|---|---|---|
| `From:` | Visible sender address shown to the recipient | Trivially forged by any sender |
| `Return-Path:` (envelope sender / MAIL FROM) | Where bounces are sent; the domain SPF checks against | Can legitimately differ from `From:` when a third-party sending service is used |
| `Reply-To:` | Where replies are directed when the user clicks "Reply" | Absence is normal; a different domain can be suspicious but is not proof of fraud on its own |
| `Received:` chain | Each server that handled the message (bottom = first hop) | Can be partially forged above the first trusted receiving server |
| `Authentication-Results:` | SPF, DKIM, DMARC verdicts recorded by the receiving mail server | Most reliable authentication evidence in the file |
| `DKIM-Signature:` | Cryptographic signature added by the sending server | Proves the signing domain; DMARC checks whether that domain aligns with `From:` |
| `Message-ID:` | Unique ID assigned by the originating server | Domain often reflects the sending infrastructure |
| `X-Sender-IP:` / `X-Originating-IP:` | IP of the client that submitted the message | Added by some providers; not standardised |

---

## Sample 01 — Phishing (Microsoft Account Impersonation)

**Source file:** `samples/email-01-phishing.eml`  
**Sample source:** phishing_pot research dataset (rf-peixoto/phishing_pot)  
**Delivery date in headers:** Fri, 8 Sep 2023 05:47:04 +0000

### Identity Fields

| Field | Recorded Value | Observation |
|---|---|---|
| `From:` | `Microsoft account team <no-reply@access-accsecurity.com>` | Display name impersonates Microsoft; actual domain is `access-accsecurity.com` — unrelated to microsoft.com |
| `Return-Path:` | `bounce@thcultarfdes.co.uk` | Completely different domain from `From:`. SPF ran against `thcultarfdes.co.uk`, not `access-accsecurity.com` or `microsoft.com` |
| `Reply-To:` | `sotrecognizd@gmail.com` | All replies directed to a free Gmail account — an attacker collection inbox |
| `Subject:` | `Microsoft account unusual signin activity` | Mimics a legitimate Microsoft security alert |
| `Message-ID:` | `<032672b4-77ca-42f8-a036-9711e91bd1f3@DB8EUR06FT032.eop-eur06.prod.protection.outlook.com>` | Domain is a Microsoft Exchange Online Protection server — the Message-ID was assigned by the *receiving* EOP filter, not the attacker |
| `X-Sender-IP:` | `89.144.44.2` | The actual IP that submitted the email to Microsoft's filter |
| `Date:` | Fri, 8 Sep 2023 05:47:04 +0000 | Delivery date used to contextualise domain registration age |

**Interpretation of the From/Return-Path difference:**  
The `From:` domain (`access-accsecurity.com`) and the `Return-Path:` domain (`thcultarfdes.co.uk`) are completely different. While a mismatch can occur legitimately (e.g. a mailing service sends on a domain's behalf), in this case neither domain has any documented relationship with Microsoft. The mismatch is one signal among several; the authentication results and body content below establish the full picture.

### Routing (Received Chain — chronological order)

| Hop | Server | Notes |
|---|---|---|
| 1 (first external) | `thcultarfdes.co.uk` (89.144.44.2) → `DB8EUR06FT032.eop-eur06.prod.protection.outlook.com` | Attacker's sending server connects directly to Microsoft EOP |
| 2 | `DB8EUR06FT032` → `SJ0PR19MB6679.namprd19.prod.outlook.com` | Internal Microsoft routing |
| 3 (final delivery) | `SJ0PR19MB6679` → `MN0PR19MB6312.namprd19.prod.outlook.com` | Delivered to recipient mailbox |

**Observations:** The email entered Microsoft's infrastructure directly from an external IP (`89.144.44.2`) with hostname `thcultarfdes.co.uk`. Microsoft's Exchange Online Protection (EOP) assigned the Message-ID — this is standard behaviour. The short external hop chain (one external server) is consistent with a direct-send phishing campaign.

### Phishing Indicators in Body

| Indicator | Detail |
|---|---|
| Microsoft impersonation | HTML styled to look like an official Microsoft security alert (Segoe UI fonts, Microsoft blue `#2672ec`) |
| False login attempt details | Claims a sign-in from Russia/Moscow, IP `103.225.77.255`, Firefox on Windows 10 |
| Deceptive "Report The User" button | Button `href` is a `mailto:sotrecognizd@gmail.com` link — clicking sends an email to the attacker's inbox, not to Microsoft |
| No real action link | There is no link to a credential-harvesting page in this sample; the attack vector is collecting victim responses via the Reply-To and mailto links |
| Tracking pixel | `<img src="http://thebandalisty[.]com/track/o43062rdzGz..." width="1px" height="1px" style="visibility:hidden">` — confirms email open to attacker |
| CSS junk tokens | Hundreds of nonsense CSS class names injected in a `<style>` block — a common anti-spam filter evasion technique |

---

## Sample 02 — Authentication Issue (Banco do Bradesco Impersonation)

**Source file:** `samples/email-02-authentication-issue.eml`  
**Sample source:** phishing_pot research dataset  
**Delivery date in headers:** Tue, 19 Sep 2023 18:36:45 +0000

### Identity Fields

| Field | Recorded Value | Observation |
|---|---|---|
| `From:` | `BANCO DO BRADESCO LIVELO <banco.bradesco@atendimento.com.br>` | Display name impersonates Banco do Bradesco (Brazilian bank); `atendimento.com.br` is a generic "service/support" domain, not bradesco.com.br |
| `Return-Path:` | `root@ubuntu-s-1vcpu-1gb-35gb-intel-sfo3-06` | Envelope sender is literally the `root` user on a DigitalOcean VPS (the hostname reveals the cloud provider and instance size). SPF ran against this bare hostname — not a domain |
| `Reply-To:` | *Not present* | No Reply-To header |
| `Subject:` | `CLIENTE PRIME - BRADESCO LIVELO: Seu cartão tem 92.990 pontos LIVELO expirando hoje!` (Portuguese — "Your card has 92,990 LIVELO points expiring today!") | Financial urgency; points-expiry social engineering |
| `Message-ID:` | `<20230919183549.39DEA3F725@ubuntu-s-1vcpu-1gb-35gb-intel-sfo3-06>` | Domain matches the VPS hostname — confirms the email was sent directly from this server |
| `X-Sender-IP:` | `137.184.34.4` | DigitalOcean IP address (San Francisco region, consistent with the `sfo3` hostname) |
| `Date:` | Tue, 19 Sep 2023 18:35:49 +0000 | |

**Interpretation:**  
The `Return-Path:` reveals the sending infrastructure: a DigitalOcean VPS running Postfix (the `Postfix, from userid 0` Received header confirms this), sending email as `root`. This is a bare, misconfigured (or deliberately minimal) sending setup — not the kind of infrastructure a legitimate bank would use. The `From:` domain (`atendimento.com.br`) differs from the real Banco do Bradesco domain (`bradesco.com.br`). These mismatches are significant signals, but the SPF `temperror` and DMARC `temperror` results (rather than clean failures) are specifically caused by a DNS resolution problem, which is documented under authentication.

### Routing (Received Chain — chronological order)

| Hop | Server | Notes |
|---|---|---|
| 1 (first external) | `ubuntu-s-1vcpu-1gb-35gb-intel-sfo3-06` (137.184.34.4) → `BN8NAM11FT066.eop-nam11.prod.protection.outlook.com` | VPS connects directly to Microsoft EOP |
| 2 | `BN8NAM11FT066` → `BN0PR03CA0023.namprd03.prod.outlook.com` | Internal Microsoft routing |
| 3 (final) | `BN0PR03CA0023` → `SA3PR19MB7370.namprd19.prod.outlook.com` → `MN0PR19MB6312` | Delivered to recipient mailbox |

**Observations:** Direct-send from a DigitalOcean VPS to Microsoft EOP. The VPS hostname (`ubuntu-s-1vcpu-1gb-35gb-intel-sfo3-06`) is the default DigitalOcean hostname for a small instance — indicating minimal configuration, consistent with an attacker spinning up a cheap server for a campaign.

### Body Content

The email body is base64-encoded. Decoded, it is a Portuguese-language HTML email impersonating Bradesco/Livelo (a Brazilian bank rewards programme), urging the recipient to "resgate agora" (redeem now) before points expire. It contains a call-to-action button linking to:

`hxxps://blog1seguimentmydomain2bra[.]me/`

This is the primary IOC — a non-Bradesco domain used as the phishing landing page.

---

## Sample 03 — Legitimate Baseline (Gmail to Gmail)

**Source file:** `samples/email-03-legitimate-baseline.eml`  
**Sample source:** Personal communication received on 05 Oct 2026  
**Delivery date in headers:** Mon, 05 Oct 2026 04:19:04 -0700 (PDT)

### Identity Fields

| Field | Recorded Value | Observation |
|---|---|---|
| `From:` | `Rakesh Mehta <reach.rakeshjru@gmail.com>` | Known sender; Gmail account |
| `Return-Path:` | `<reach.rakeshjru@gmail.com>` | Matches the `From:` address exactly — no third-party sending service involved |
| `Reply-To:` | *Not present* | Absent; replies go to `From:` address by default |
| `Subject:` | `Test` | Simple test message |
| `Message-ID:` | `<CAD2TNP1L5g9nSgBCMxR-84F5Nj2cXS1sQjm8Kj1LW-AQ7geHxw@mail.gmail.com>` | Domain is `mail.gmail.com` — consistent with Gmail infrastructure |
| `Date:` | Mon, 05 Oct 2026 16:48:52 +0530 | |

**Interpretation:**  
All identity fields are internally consistent. The `Return-Path:` and `From:` share the same address; the `Message-ID:` domain is `mail.gmail.com`, consistent with the claimed sender. No Reply-To misdirection is present. This is the expected header profile of a simple person-to-person Gmail message.

### Routing (Received Chain — chronological order)

| Hop | Server | Notes |
|---|---|---|
| 1 | Gmail sender client → `mail-sor-f41.google.com` [209.85.220.41] | Sender's Gmail client submits via Google's sending infrastructure |
| 2 (final) | `mail-sor-f41.google.com` → `mx.google.com` | Received by the recipient's Gmail server |

**Observations:** Two hops entirely within Google's infrastructure, consistent with a Gmail-to-Gmail message. The sending IP `209.85.220.41` is a documented Google mail server. The ARC chain (i=1 and i=2) confirms the message passed through Google's infrastructure cleanly.

---

## Comparative Summary

| Field | Email-01 (Phishing) | Email-02 (Auth Issue) | Email-03 (Baseline) |
|---|---|---|---|
| From domain | `access-accsecurity.com` | `atendimento.com.br` | `gmail.com` |
| Return-Path domain | `thcultarfdes.co.uk` | `ubuntu-s-1vcpu-1gb-35gb-intel-sfo3-06` (bare hostname) | `gmail.com` |
| From / Return-Path match | No — completely different domains | No — bare VPS hostname vs domain | Yes — identical |
| Reply-To present | Yes — attacker Gmail | Not present | Not present |
| Sending IP | `89.144.44.2` | `137.184.34.4` (DigitalOcean) | `209.85.220.41` (Google) |
| Routing hops | 3 (1 external) | 3 (1 external) | 2 (all Google) |
| Authentication results | See spf-dkim-dmarc-analysis.md | See spf-dkim-dmarc-analysis.md | See spf-dkim-dmarc-analysis.md |

---


