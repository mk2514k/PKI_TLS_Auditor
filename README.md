# PKI & TLS Auditor: Custom 2-Tier Certificate Authority & Validation Engine

A private 2-tier certificate authority built from scratch in OpenSSL, wired into an Nginx TLS server, and checked by a Python auditor I wrote to validate the whole chain — cert validity, hostname match, cipher strength, chain of trust, and protocol version. Then I deliberately broke four parts of it to confirm the auditor actually catches what it claims to catch.

## What this is

This isn't a tutorial walkthrough. It's a working private CA — Root CA signs an Intermediate CA, the Intermediate signs a server cert, that cert gets installed on Nginx, and a Python script audits the live TLS connection against six separate checks. Once the whole thing was running cleanly, I broke it on purpose four separate times (expired cert, SAN mismatch, weak cipher, broken chain) and documented exactly what failed, why, and how I fixed it.

## Why I built it

I wanted to actually understand what happens during a TLS handshake instead of just being able to define one. Reading about chain of trust is one thing — generating a root key, watching it sign an intermediate, watching that sign a leaf cert, and then having my own script reject that cert when something's wrong is a completely different level of understanding. The breaking phase mattered just as much as the building phase. Anyone can stand up a CA by following a guide. Fewer people deliberately try to break their own work to see if their tooling actually does its job.

## Architecture

```
Root CA (self-signed, 10yr)
    │  signs
    ▼
Intermediate CA (signed by root, 5yr)
    │  signs
    ▼
Server cert (server.cyberpathway.lab, 1yr)
    │  installed on
    ▼
Nginx (TLS 1.2/1.3, port 443)
    │  audited by
    ▼
Python auditor (6 checks) ──► pass/fail TLS report
```

## Phase breakdown

| Phase | What it proves |
|---|---|
| [Phase 1 — 2-Tier CA](./phase1_2TierCA/README.md) | Built the actual trust chain by hand — root key, intermediate key, signing flow, and the config decisions behind each one. |
| [Phase 2 — Nginx TLS](./phase2_NginxConfig/README.md) | Took the cert chain from Phase 1 and got a real server enforcing TLS 1.2/1.3 only, with the permission and pathing problems that came with it. |
| [Phase 3 — Python Auditor](./phase3_pythonAuditor/README.md) | Wrote the script that checks all of the above — connection, expiry, SAN, cipher, chain, protocol version — and explains every failure in plain language. |
| [Phase 4 — Breaking](./phase4_breaking/README.md) | Broke the system four different ways on purpose and used the auditor to catch each one, which also exposed and fixed real bugs in the auditor itself. |

## The auditor — what it checks

| Check | What it validates | Failure behaviour |
|---|---|---|
| TLS Connection | Handshake completes, protocol negotiated | Fails gracefully, explains whether it's a TLS error or a network error |
| Cert Expiry | Days remaining, expired flag, 30-day warning window | FAIL with remediation, separates "expired" from "expiring soon" |
| Hostname / SAN | Hostname matches a SAN entry (wildcard-aware) | FAIL with explanation — notes that modern TLS ignores CN entirely |
| Cipher Suite | Negotiated cipher checked against a list of known-weak ciphers | Names the specific weakness (e.g. SWEET32, POODLE) and the fix |
| Chain of Trust | Full verification up to the trusted root | Explains what broke — missing intermediate vs. self-signed |
| Protocol Version | Flags TLS 1.0/1.1, SSLv2/v3 | Flags old versions with the relevant CVE/attack context |

Full breakdown of each check, including the code, lives in the [Phase 3 README](./phase3_pythonAuditor/README.md).

## Key decisions

A few choices that aren't obvious just from looking at the code or the configs, but mattered:

**RSA 4096 over ECDSA for the CA keys.** ECDSA is smaller and faster, and I knew that going in. I went with RSA anyway because it's still the default expectation in most enterprise PKI environments, and I wanted the project to reflect what I'd actually run into in a real org, not just what's technically more efficient.

**`copy_extensions = copyall` on the intermediate config.** The first leaf cert I signed came out with completely wrong SANs, even though the CSR had the right ones. OpenSSL doesn't carry CSR extensions over to the signed cert by default — you have to explicitly tell it to. This one cost me a regenerated cert and taught me more about how OpenSSL actually processes a signing request than any guide did.

**A cert bundle instead of just the leaf cert on Nginx.** TLS handshakes were failing intermittently in a way that looked fine locally but wasn't. Turned out Nginx was only serving the leaf cert — clients without the intermediate cached locally had no way to complete the chain walk. Concatenating leaf + intermediate into one `server-chain.pem` fixed it permanently.

## Mistakes made

I'm leaving these in because they're a more honest record of the work than a clean build log would be. Three worth calling out:

- **Locked myself out of my own root key.** I ran `chmod 400` on the private key file *before* confirming the passphrase had saved correctly. Ended up with an inaccessible key and had to delete and regenerate it. Now I always confirm the file's actually written and readable before locking it down.
- **SAN mismatch on the leaf cert.** Covered above under Key Decisions, but worth repeating here because it's the single mistake that taught me the most about how OpenSSL signing actually works under the hood.
- **Corrupted the intermediate private key from a passphrase typo.** When `-aes256` key generation asks for a passphrase twice and the two entries don't match, OpenSSL doesn't always fail cleanly — it can write a malformed key file using whatever it caught on the first entry. Found this the hard way.

Full mistake-by-mistake breakdown, with screenshots, is in each phase's own README and notes file.

## How to run the auditor

```bash
cd phase3_pythonAuditor
python3 auditor.py
# enter the hostname to audit, e.g. server.cyberpathway.lab
```

## Sample output

A clean pass:

```
[PASS] TLS Connection
  Detail     : Connected. TLS version: TLSv1.3

[PASS] Certificate Expiry
  Detail     : Valid for 362 more days (expires 2027-06-29)
```

A deliberate failure (expired cert, from the Phase 4 breaking exercise):

```
[FAIL] Certificate Expiry
  Detail     : Certificate EXPIRED 4 days ago (expired 2026-06-25)
  Why        : An expired certificate is rejected outright by TLS clients — there is no grace period.
  Fix        : Reissue the certificate with a valid expiry window and redeploy to Nginx.
```

Full pass/fail reports for all four breaks are in [Phase 4](./phase4_breaking/README.md).
