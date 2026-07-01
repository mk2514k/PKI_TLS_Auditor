# Phase 3: Build Notes

[← Back to Phase 3 README](./README.md) · [Root README](../README.md)

This is the full technical walkthrough of `auditor.py`, how it's structured, why each piece works the way it does, and the decisions behind the design. The README covers what each check does at a high level; this goes into the actual code and the reasoning underneath it.

## Libraries used

```python
import ssl
import socket
from datetime import datetime, timezone
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import datetime
import io
import sys
```

**`ssl`**: Python's built-in TLS library. Handles SSL context creation, cert verification, handshake negotiation. Most of the connection logic runs through this.

**`socket`**: creates the raw TCP connection before TLS wraps it. The pattern throughout the checks is: open a raw socket with `socket.create_connection()`, then wrap it with `context.wrap_socket()` to do the TLS handshake on top.

**`cryptography`**: more powerful cert parsing than the `ssl` module alone. Used specifically in Check 3 (SAN inspection) because `ssl`'s built-in cert parsing doesn't expose extension data in a clean usable format. `x509.load_der_x509_certificate()` can pull the raw SAN extension values, including wildcard entries, from the cert's binary form.

**`io` and `sys`**: used in the report generation to redirect `stdout` into a `StringIO` buffer so the script can both print the report to terminal *and* write it to a file without running all the checks twice.

## Trust anchor setup

```python
import os
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CA_CERT = os.path.join(BASE_DIR, "..", "phase1_2TierCA", "certs", "rootCA", "cert", "rootCA.cert")
```

`CA_CERT` is the root CA cert from Phase 1. Every SSL context that needs to verify a cert chain loads this as its trust anchor, without it, Python's default context rejects connections because our private CA isn't in the system's trust store.

`os.path.dirname(os.path.abspath(__file__))` resolves to the directory containing `auditor.py` regardless of where it's run from, then navigates to the root cert using a relative path from there. This makes the script portable across different machines cloning the repo, the original build had this hardcoded to an absolute local path, which would have broken immediately for anyone else.

## The `audit_result` function

```python
def audit_result(check_name, passed, detail, explanation=None, remediation=None):
    status = "PASS" if passed else "FAIL"
    print(f"\n[{status}] {check_name}")
    print(f"  Detail     : {detail}")
    if not passed and explanation:
        print(f"  Why        : {explanation}")
    if not passed and remediation:
        print(f"  Fix        : {remediation}")
```

Every check calls this function rather than printing directly. Keeping the output format centralised means every failure looks consistent,same labels, same indentation, same structure. If the format needs changing later, it changes in one place.

The `explanation` and `remediation` parameters only print on failure. A passing check just prints its name and the detail line- no clutter.

## Check 1: `check_connection(hostname, port=443)`

```python
context = ssl.create_default_context()
context.load_verify_locations(CA_CERT)
```

`ssl.create_default_context()` creates a context with hostname checking and cert verification both enabled by default. Loading the root CA cert makes our private CA trusted for this context specifically.

```python
with socket.create_connection((hostname, port), timeout=10) as sock:
    with context.wrap_socket(sock, server_hostname=hostname) as tls_sock:
        detail = f"Connected. TLS version: {tls_sock.version()}"
        audit_result("TLS Connection", True, detail)
        return tls_sock.getpeercert()
```

On success, `tls_sock.getpeercert()` returns the cert as a dictionary. This is what gets passed into Check 2. The `timeout=10` means the check fails cleanly after 10 seconds rather than hanging indefinitely.

**Two separate exception handlers:**

`ssl.SSLError`: handshake-level failure. The TCP connection opened but TLS negotiation failed. This covers untrusted certs, protocol mismatches, and config errors. The explanation in the output reflects this: "the handshake failed *before* a secure connection could be established."

`Exception`: network-level failure. Nothing even connected. Server down, DNS not resolving, wrong port. Different problem, different message.

Returns `None` on any failure, which Check 2 uses to decide whether to skip gracefully.

## Check 2: `check_expiry(cert)`

```python
not_after_str = cert['notAfter']
not_after = datetime.datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
not_after = not_after.replace(tzinfo=timezone.utc)
now = datetime.datetime.now(timezone.utc)
days_left = (not_after - now).days
```

`notAfter` comes back from `ssl` in a specific string format, `strptime` parses it into a datetime object. Both `not_after` and `now` are made UTC-aware before subtracting, which avoids timezone mismatch bugs that would give wrong day counts depending on the local machine's timezone.

**Three branches:**

`days_left < 0`: expired. `abs(days_left)` gives you how many days ago it expired, which is more useful than a negative number in the output.

`days_left < 30`: expiring soon. Flagged as a FAIL rather than a warning because "expiring in 28 days" is an actionable problem, not just information. Renewal takes time.

Else: valid. Reports the exact expiry date and days remaining.

**The None guard at the top:**

```python
if not cert:
    audit_result("Certificate Expiry", False, "No certificate returned — cannot check expiry.", ...)
    return
```

If Check 1 returned `None`, this check skips immediately with an explanation rather than crashing on `cert['notAfter']`.

## Check 3 — `get_raw_cert()` + `check_hostname()`

Check 3 is split into two functions — one to fetch the raw cert bytes, one to do the inspection.

```python
def get_raw_cert(hostname, port=443):
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    ...
    return tls_sock.getpeercert(binary_form=True)
```

`ssl.CERT_NONE` disables cert verification entirely for this fetch. That's intentional — if the cert has a wrong SAN and you try to connect with verification enabled, the connection fails before you can see what SANs are actually on it. The point of this check is to *read* the cert's SAN extension, so you need a connection that succeeds regardless of cert validity.

```python
der_cert = get_raw_cert(hostname, port)
cert = x509.load_der_x509_certificate(der_cert, default_backend())

san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
san_names = san_ext.value.get_values_for_type(x509.DNSName)
```

The raw cert bytes come back as DER-encoded binary. `x509.load_der_x509_certificate()` from the `cryptography` library parses it properly, then `.get_values_for_type(x509.DNSName)` extracts the actual hostname strings from the SAN extension.

**Wildcard matching:**

```python
elif san.startswith("*."):
    wildcard_domain = san[2:]
    if hostname.endswith("." + wildcard_domain):
        matched = True
```

`*.cyberpathway.lab` should match `server.cyberpathway.lab`. This strips the `*.` prefix and checks whether the hostname ends with `.cyberpathway.lab`. This is the correct interpretation of a wildcard SAN.

The failure output lists all the SANs that *were* on the cert, which makes it immediately clear whether you need to add a SAN or change the wrong one.

## Check 4: `check_cipher(hostname, port=443)`

```python
WEAK_CIPHERS = {
    "RC4": ("RC4 is a broken stream cipher. The NOMORE attack (2015)..."),
    "DES": ("DES uses a 56-bit key, trivially brute-forced..."),
    "3DES": ("SWEET32 birthday attack..."),
    "MD5": ("Collision attacks practical since 2004..."),
    "NULL": ("Zero encryption — traffic sent in plaintext..."),
    "EXPORT": ("FREAK attack (2015)..."),
    "ANON": ("No server auth — trivially MITM-able..."),
    "CBC": ("POODLE, Lucky13 padding oracle attacks..."),
    "AES128-SHA": ("CBC mode..."),
    "AES256-SHA": ("CBC mode..."),
}
```

The dictionary maps cipher name substrings to their specific vulnerability explanations. Checking with `if k in cipher_name.upper()` means a negotiated cipher like `TLS_RSA_WITH_3DES_EDE_CBC_SHA` will match on `3DES` and `CBC`,  and both explanations print.

```python
weak_found = {k: v for k, v in WEAK_CIPHERS.items() if k in cipher_name.upper()}
```

This isn't just checking if *any* weakness is present, it collects *all* matches so the output tells you every vulnerability in one pass. A cipher like `RC4-MD5` would flag both.

**The `SSLCertVerificationError` fallback:**

```python
except ssl.SSLCertVerificationError as e:
    audit_result("Cipher Suite", False, f"Could not negotiate cipher — cert verification failed: {e}", ...)
```

This exception handler was added during the Phase 4 break-fix cycle (Break 1 specifically). When an expired cert causes the TLS handshake to fail at the verification step, Python raises `SSLCertVerificationError` rather than `SSLError`. Without this handler, the cipher check would crash with an uncaught exception instead of producing a clean FAIL entry in the report. Adding it meant the auditor could still run all six checks even when the cert was known to be broken — and that mattered for the Phase 4 report output to be complete.

## Check 5 — `check_chain(hostname, port=443)`

```python
context = ssl.create_default_context()
context.load_verify_locations(CA_CERT)
```

Full verification enabled, same as Check 1. The difference here is what happens on failure and the detail on *why* it failed.

```python
cert = tls_sock.getpeercert()
issuer = dict(x[0] for x in cert['issuer'])
subject = dict(x[0] for x in cert['subject'])
```

On a valid chain, the output prints Subject (who this cert belongs to) and Issuer (who signed it). These two fields together give you a human-readable summary of where the cert sits in the chain.

**The `SSLCertVerificationError` failure explanation** is worth reading in full, it covers both the "missing intermediate" case and the "self-signed" case, and explicitly calls out that this failure is often invisible during local testing because the build machine has the Intermediate cached. That's a real operational nuance that most introductory PKI docs don't mention.

## Check 6: `check_tls_version(hostname, port=443)`

```python
context.check_hostname = False
context.verify_mode = ssl.CERT_NONE
context.minimum_version = ssl.TLSVersion.SSLv3 if hasattr(ssl.TLSVersion, 'SSLv3') else ssl.TLSVersion.TLSv1
```

Verification disabled and minimum version deliberately lowered. If you leave Python's default minimum version in place (TLS 1.2), the context will refuse to negotiate TLS 1.0/1.1 even if the server allows them. The check would always pass even on a server with no protocol restrictions. Lowering the minimum means Python will *attempt* whatever the server is willing to negotiate, and then the check catches what actually got agreed.

The `hasattr` guard is there because `ssl.TLSVersion.SSLv3` isn't available on all Python versions, using it on a version that doesn't support it would raise an `AttributeError`. The fallback to `TLSVersion.TLSv1` is conservative, old enough to catch most weak configs.

## Report generation: `main()`

```python
output = io.StringIO()
sys.stdout = output
```

This redirects `stdout` into an in-memory buffer. Every `print()` call for the duration of the audit goes into that buffer instead of the terminal.

```python
sys.stdout = sys.__stdout__
print(report_text)
```

After all checks run, `stdout` gets restored and the buffered output is printed to the terminal *and* written to the file in one go (without running the checks twice).

```python
filename = f"tls_report_{hostname}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
```

Timestamped filenames mean every run produces a new file. This is useful for the Phase 4 break/fix cycle where each break generates a `_fail.txt` and each fix generates a `_pass.txt`, and you can compare them directly.

## What the auditor became after Phase 4

The version of `auditor.py` you see now isn't the first draft. Break 1 in Phase 4 (the expired cert scenario) exposed three separate gaps:

1. No graceful handling for `SSLCertVerificationError` in the cipher check, I added the try/except block
2. No fallback to allow Check 2 to run when Check 1 fails for cert-verification reasons, I added the `SSLCertVerificationError` path that still returns cert data so expiry can be checked
3. The CA trust root wasn't being loaded consistently across all contexts, I tightened up `CA_CERT` loading in every context that needed it

The auditor that went into Phase 4 was good. The one that came out the other side was meaningfully more robust. It handles failure states more gracefully, explains them more specifically, and doesn't crash when the thing it's auditing is broken.
