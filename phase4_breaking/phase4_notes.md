# Phase 4: Build Notes

[← Back to Phase 4 README](./README.md) · [Root README](../README.md)

Full technical log of every break, the exact issues it surfaced, and how each one was fixed (both the deliberate break and the unintentional ones Break 1 exposed along the way).

## The methodology

Every break/fix cycle ran in this order:

```
1. Apply the specific break (cert swap, config change, etc.)
2. sudo nginx -t       ← confirm config is valid before reloading
3. sudo systemctl reload nginx
4. python3 auditor.py  ← run the auditor against the broken state
5. Report saved automatically (timestamped _fail.txt)
6. Revert to the working state
7. sudo systemctl reload nginx
8. python3 auditor.py  ← run again against the fixed state
9. Report saved automatically (timestamped _pass.txt)
```

The fail and pass `.txt` files in each subdirectory are real output from actual auditor runs- not manually written.

---

## Break 1: Expired Cert

### What the break was supposed to do

Issue a leaf cert with a backdated expiry date, swap it into Nginx, and confirm the auditor's expiry check flags it correctly.

### How the expired cert was generated

`-days -1` doesn't work. OpenSSL won't accept zero or negative day values. The workaround is to explicitly set start and end dates in the past using `-startdate` and `-enddate`:

```bash
openssl ca -config intermediateCA/intermediateCA.cnf \
    -startdate 20260620120000Z \
    -enddate   20260625120000Z \
    -extfile leafCerts/leafCert-server.cnf \
    -extensions v3_leaf \
    -in leafCerts/csr/server.csr \
    -out certs/intermediateCA/issued-certs/server_expired.cert.pem
```

The dates are in `YYYYMMDDHHMMSSZ` format. Both are set in the past relative to when the cert was issued.

### The CA duplicate entry problem

OpenSSL's `index.dat` won't let you issue a new cert for a subject that already has a valid one recorded. Before the expired cert could be generated, all existing valid certs for that subject had to be revoked first:

```bash
openssl ca -config intermediateCA/intermediateCA.cnf \
    -revoke certs/intermediateCA/issued-certs/<serial>.pem
```

This is how real CA management works. You can't just reissue over an existing live cert. The revocation step is mandatory.

### The `v3_leaf` section had no SAN

The `intermediateCA.cnf` file's `v3_leaf` extension section didn't include a SAN entry. This meant the reissued cert, including the expired one, came out with no Subject Alternative Names (SANs) at all, which would cause a separate SAN failure on top of the expiry failure during testing.

Fixed by using `-extfile` to pull the SAN config directly from `leafCert-server.cnf` instead of relying on the extension block in `intermediateCA.cnf`:

```bash
openssl ca -config intermediateCA/intermediateCA.cnf \
    -extfile leafCerts/leafCert-server.cnf \
    -extensions v3_leaf \
    ...
```

This tells OpenSSL to read the extension definitions from the leaf cert's own config file, which already had the correct SAN defined.

### Auditor Response for Break 1

This is where Break 1 became more than just a simple break scenario. Three separate auditor failures surfaced:

**Problem 1: Cipher check crashing with uncaught `SSLCertVerificationError`**

An expired cert causes the TLS handshake to fail at the certificate verification stage. Python raises `ssl.SSLCertVerificationError` in this case. The cipher check (`check_cipher()`) only had a handler for `ssl.SSLError`, not the more specific subclass. Result: uncaught exception, program crashed instead of producing a FAIL entry.

Fix: added an explicit `except ssl.SSLCertVerificationError` handler in `check_cipher()`:

```python
except ssl.SSLCertVerificationError as e:
    audit_result(
        "Cipher Suite",
        False,
        f"Could not negotiate cipher — cert verification failed: {e}",
        explanation="The TLS handshake failed during cipher negotiation because the certificate could not be verified...",
        remediation="Fix the certificate issue flagged above, then re-run to check the cipher suite."
    )
```

**Problem 2: Expiry check couldn't run when Check 1 failed on a cert error**

`check_connection()` returns `None` if the TLS connection fails, and `check_expiry()` skips if it receives `None`. But with an expired cert, the connection *partially* completes, enough to get the cert's data, before being rejected during verification. The auditor was dropping all the cert data on the floor.

Fix: added a fallback `except ssl.SSLCertVerificationError` block inside `check_connection()` that still fetches cert data via a no-verification context when the verified connection fails, so the expiry check can still run and report the actual expiry date.

**Problem 3: CA trust root not loaded consistently**

Certain checks were creating an `ssl.create_default_context()` without loading `CA_CERT`. On a publicly-trusted cert (like `google.com`) this works fine since the system CA store has what it needs. Against the private CA, theres no store and the check fails for the wrong reason. I tightened up every context creation to explicitly call `context.load_verify_locations(CA_CERT)` where verification is enabled.

### The expired cert bundle

Built the expired cert bundle the same way as the normal one- leaf first, then Intermediate:

```bash
cat certs/intermediateCA/issued-certs/server_expired.cert.pem \
    certs/intermediateCA/cert/intermediateCA.cert \
    > phase4_breaking/expired\ cert/expired_bundle.pem
```

Swapped this into the Nginx `ssl_certificate` directive and reloaded. Ran the auditor. Fail report generated. Reverted, ran again, pass report generated.

---

## Break 2: SAN Mismatch

### Break Simulation

Created a new leaf cert config with a deliberately wrong SAN:

```bash
# leafCert-server-SANmismatch.cnf
[alt_names]
DNS.1 = wrong.hostname.lab
```

Generated a CSR from this config, signed it through the Intermediate, built a bundle with the mismatched cert.

```bash
# Generate CSR with the wrong SAN config
openssl req -config leafCerts/leafCert-server-SANmismatch.cnf \
    -key leafCerts/private/server.key \
    -new -out leafCerts/csr/server_sanmismatch.csr

# Sign it
openssl ca -config intermediateCA/intermediateCA.cnf \
    -extfile leafCerts/leafCert-server-SANmismatch.cnf \
    -extensions v3_leaf \
    -in leafCerts/csr/server_sanmismatch.csr \
    -out certs/intermediateCA/issued-certs/server_sanmismatch.cert

# Build bundle
cat certs/intermediateCA/issued-certs/server_sanmismatch.cert \
    certs/intermediateCA/cert/intermediateCA.cert \
    > phase4_breaking/SAN\ mismatch/san_mismatch_bundle.pem
```

### Auditor Response

Hostname/SAN FAIL. Output listed the actual SANs on the cert (`wrong.hostname.lab`) and confirmed `server.cyberpathway.lab` wasn't in the list. The explanation noted that CN is ignored by modern TLS clients. the SAN list is the only thing that counts.

---

## Break 3: Weak Cipher Suite

### Break Simulation

Modified `cyberpathway.conf` to explicitly allow weak ciphers and older TLS versions:

```nginx
ssl_protocols TLSv1 TLSv1.1 TLSv1.2 TLSv1.3;
ssl_ciphers RC4:3DES:AES128-SHA:AES256-SHA:HIGH:!aNULL:!MD5;
ssl_prefer_server_ciphers on;
```

Also made sure the `WEAK_CIPHERS` dictionary in `auditor.py` included entries for `AES128-SHA` and `AES256-SHA` (CBC-mode ciphers that aren't broken in the catastrophic sense but are still considered weak) so the check had definitions to match against.

![Nginx config with weak cipher break](./weak%20cipher%20suite/gninx%20config-weak%20cipher%20break.png)

### Auditor Response

Cipher Suite FAIL. Named the specific weakness for whatever cipher Nginx negotiated during the auditor's test connection (with the attack name and a direct reference to the Nginx directive that needs changing).

---

## Break 4: Broken Chain of Trust

### Break Simulation

Created a leaf-only bundle (just `server.cert`) with no Intermediate appended, and pointed Nginx at it instead of `server-chain.pem`:

```bash
cp phase1_2TierCA/certs/intermediateCA/issued-certs/server.cert \
    phase4_breaking/broken\ chain\ of\ trust/broken_chain_bundle.pem
```

This simulates a real misconfiguration. A server that was set up without knowing that the full chain needs to be served, not just the leaf cert.

### Auditor Response

Chain of Trust FAIL. The explanation called out specifically why this failure can be invisible during local testing: the machine that built the CA has the Intermediate cached, so the chain walk succeeds from there even with a leaf-only bundle. A client connecting fresh (one that doesn't have the Intermediate in its local cache) gets a chain verification error.

This is arguably the most practically useful thing the auditor explains across all four breaks, because it's the kind of misconfiguration that genuinely looks fine to the person who set it up.

---

## Auditor changes made during Phase 4 (summary)

| Change | Triggered by | What it fixed |
|---|---|---|
| `SSLCertVerificationError` handler in `check_cipher()` | Break 1 | Prevented crash on expired cert scenario |
| Fallback cert fetch in `check_connection()` | Break 1 | Allowed expiry check to still run when verified connection fails |
| Consistent `CA_CERT` loading across all contexts | Break 1 | Fixed false failures against private CA certs |
| `-extfile` flag for SAN on expired cert generation | Break 1 | Prevented SANless certs on reissue |
| `AES128-SHA`, `AES256-SHA` added to `WEAK_CIPHERS` | Break 3 | Extended cipher check to catch CBC-mode weak ciphers |

Phase 4 complete.
