# Phase 4: Breaking

[← Root README](../README.md) · [← Phase 3](../phase3_pythonAuditor/README.md) · Full build log: [NOTES.md](https://github.com/mk2514k/PKI_TLS_Auditor/blob/main/phase4_breaking/phase4_notes.md)

## Core Phase Objective

Most people building a PKI project stop after it works. This phase is the part where I tried to break it on purpose. Four separate times, four separate failure modes, all to see if the auditor actually catches what it claims to catch. The answer is yes, but not before Break 1 exposed enough gaps in the auditor itself that I had to fix the tool before I could trust the tool's output.

**The auditor that came out of Break 1 was meaningfully better than the one that went in.** That's not a failure, that's the point of a break/fix cycle. 

## The methodology

Every break followed the same pattern:

```
Apply the break → reload Nginx → run auditor → fail report generated
→ revert to original → reload Nginx → run auditor → pass report generated
```

The fail and pass reports for each break are in the subdirectories below.

## Break 1: Expired cert

**What was broken:** Issued a new leaf cert with a backdated expiry using `startdate`/`enddate` workarounds (OpenSSL won't accept `-days -1` or zero/negative values, so you have to explicitly set start and end dates in the past). Then swapped this into Nginx.

**What the auditor caught:** Certificate expiry FAIL, with exact days since expiry.

**But this is where things got complicated.** Break 1 was the hardest, not because the break itself was complex, but because it exposed real problems in the auditor that had to be fixed before the cycle could continue cleanly:

- The cipher check was crashing with an uncaught `SSLCertVerificationError` instead of producing a FAIL entry. An expired cert causes the TLS handshake to fail at the verification step, and the cipher check didn't have a handler for that exception type. Added the `try/except ssl.SSLCertVerificationError` block.
- The auditor wasn't loading the root CA trust anchor consistently across every check that needed it. Tightened up `CA_CERT` loading.
- The `v3_leaf` section in `intermediateCA.cnf` didn't have a SAN entry, which meant the reissued expired cert came out with no SANs at all. Fixed by pulling SAN config from `leafCert-server.cnf` using the `-extfile` flag on signing.

There was also a CA duplicate entry error. OpenSSL's index.dat won't let you issue a new cert for a subject that already has a valid one on record. I had to revoke the existing valid certs before reissuing the expired one. This is how real CA management works: you can't just issue a duplicate, you have to revoke the existing entry first.

Reports: [`expired cert/tls_report_break1_fail.txt`](https://github.com/mk2514k/PKI_TLS_Auditor/blob/main/phase4_breaking/break1_expired_cert/tls_report_break1_fail.txt)· [`expired cert/tls_report_break1_pass.txt`](https://github.com/mk2514k/PKI_TLS_Auditor/blob/main/phase4_breaking/break1_expired_cert/tls_report_break1_pass.txt)

## Break 2: SAN mismatch

**What was broken:** Created a new leaf cert config (`leafCert-server-SANmismatch.cnf`) with a deliberately wrong SAN (a hostname other than) `server.cyberpathway.lab`. Generated a CSR with that config, signed it through the Intermediate, built a new bundle with the mismatched cert and swapped it into Nginx.

**What the auditor caught:** Hostname/SAN FAIL, listing exactly which SANs were on the cert and which hostname wasn't found.

The output also explains why this matters. Modern TLS ignores the CN field entirely and only checks SANs, so a wrong SAN is a hard failure regardless of what the CN says.

Reports: [`SAN mismatch/tls_report_break2_fail.txt`](https://github.com/mk2514k/PKI_TLS_Auditor/blob/main/phase4_breaking/break2_san_mismatch/tls_report_break2_fail.txt) · [`SAN mismatch/tls_report_break2_pass.txt`](https://github.com/mk2514k/PKI_TLS_Auditor/blob/main/phase4_breaking/break2_san_mismatch/tls_report_break2_pass.txt)


## Break 3: Broken chain of trust

**What was broken:** Created a leaf-only bundle (just `server.cert`) with no Intermediate and swapped it into Nginx. This simulates a misconfigured server that isn't serving the full chain.

**What the auditor caught:** Chain of Trust FAIL, with an explanation that covers exactly why this failure is insidious. Clients that have the Intermediate cached locally (like the machine that built the CA) will appear to connect fine, while fresh clients fail. It's the kind of bug that looks like a user problem until you understand what's actually happening.

![Nginx config with weak cipher break applied](./weak%20cipher%20suite/gninx%20config-weak%20cipher%20break.png)

Reports: [`broken chain of trust/tls_report_break3_fail.txt`](https://github.com/mk2514k/PKI_TLS_Auditor/blob/main/phase4_breaking/break3_broken_chain_of_trust/tls_report_break3_fail.txt) · [`broken chain of trust/tls_report_break3_pass.txt`](https://github.com/mk2514k/PKI_TLS_Auditor/blob/main/phase4_breaking/break3_broken_chain_of_trust/tls_report_break3_pass.txt`)


## Break 4: Weak cipher suite

**What was broken:** Modified `cyberpathway.conf` to include weak ciphers (`RC4`, `3DES`, `AES128-SHA`) and allow older TLS versions (`TLSv1`, `TLSv1.1`). Also patched the corresponding weak cipher entries into the `WEAK_CIPHERS` dictionary in `auditor.py` so the check had the definitions it needed to flag them.

**What the auditor caught:** Cipher Suite FAIL, naming the specific weakness (e.g. SWEET32 for 3DES, POODLE/Lucky13 for CBC-mode ciphers) and pointing directly at the Nginx directive to fix.

Reports: [`weak cipher suite/tls_report_break4_fail.txt`](https://github.com/mk2514k/PKI_TLS_Auditor/blob/main/phase4_breaking/break4_weak_cipher/tls_report_break4_fail.txt) · [`weak cipher suite/tls_report_break4_pass.txt`](https://github.com/mk2514k/PKI_TLS_Auditor/blob/main/phase4_breaking/break4_weak_cipher/tls_report_break4_pass.txt)

## Auditor Enhancements post Break 1:

It's worth being specific about this, because "Break 1 made the auditor more robust" is easy to say but the actual changes matter:

**Pre Break 1:** The cipher check would crash (uncaught exception) when presented with an expired cert. The expiry check depended entirely on Check 1 returning a cert object, with no fallback. The CA trust root wasn't loaded consistently.

**Post Break 1:** `SSLCertVerificationError` is caught and handled gracefully in the cipher check. The expiry check has a clean fallback when the cert can't be retrieved via the normal path. Trust anchor loading is consistent. The auditor produces a complete report even when the target is broken.

Full break-by-break command sequence and raw troubleshooting notes are in [NOTES.md](https://github.com/mk2514k/PKI_TLS_Auditor/blob/main/phase4_breaking/phase4_notes.md).
