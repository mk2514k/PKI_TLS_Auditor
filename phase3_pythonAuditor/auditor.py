#IMPORT LIBRARIES----------
 
import ssl
import socket
from datetime import datetime, timezone
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import datetime
import io
import sys
 
# Trust anchor — your root CA. All SSL contexts load this so the auditor
# can verify certs issued by your private 2-tier CA.
CA_CERT = "/home/mk/Documents/CyberSecurityPathway/projects/pki-tls-auditor/phase1_2TierCA/certs/rootCA/cert/rootCA.cert"
 
#AUDIT FUNCT------------
    #if a check fails, this will tell you why and how to resolve
def audit_result(check_name, passed, detail, explanation=None, remediation=None):
    status = "PASS" if passed else "FAIL"
    print(f"\n[{status}] {check_name}")
    print(f"  Detail     : {detail}")
    if not passed and explanation:
        print(f"  Why        : {explanation}")
    if not passed and remediation:
        print(f"  Fix        : {remediation}")
 
 
 
#CHECK 1----------
def check_connection(hostname, port=443):
    print(f"\n[*] Checking TLS connection to {hostname}:{port}")
 
    context = ssl.create_default_context()
    context.load_verify_locations(CA_CERT)
 
 
    try:
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                detail = f"Connected. TLS version: {tls_sock.version()}"
                audit_result("TLS Connection", True, detail)
                return tls_sock.getpeercert()
    except ssl.SSLError as e:
        audit_result(
            "TLS Connection",
            False,
            f"TLS error: {e}",
            explanation=(
                "The TLS handshake failed before a secure connection could be established. "
                "This means the server rejected the connection due to a protocol mismatch, "
                "an untrusted certificate, or a configuration error on either side."
            ),
            remediation="Checking Nginx TLS config, confirming the cert is valid and the CA is trusted by this user."
        )
        return None
    except Exception as e:
        audit_result(
            "TLS Connection",
            False,
            f"Connection failed: {e}",
            explanation="A network-level error prevented any connection. The server may be down or unreachable.",
            remediation="Confirm Nginx is running and the hostname/port are correct."
        )
        return None
 
#CHECK 2----------
def check_expiry(cert):
    if not cert:
        audit_result(
            "Certificate Expiry",
            False,
            "No certificate returned — cannot check expiry.",
            explanation="Expiry cannot be checked if the TLS connection failed or returned no certificate.",
            remediation="Fix the connection issue first, then re-run."
        )
        return
 
    not_after_str = cert['notAfter']
    not_after = datetime.datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
    not_after = not_after.replace(tzinfo=timezone.utc)
    now = datetime.datetime.now(timezone.utc)
    days_left = (not_after - now).days
 
    if days_left < 0:
        audit_result(
            "Certificate Expiry",
            False,
            f"Certificate EXPIRED {abs(days_left)} days ago (expired {not_after.date()})",
            explanation=(
                "An expired certificate is rejected outright by TLS clients — there is no grace period. "
                "Once the expiry date passes, every client attempting a handshake will fail, "
                "regardless of how recently it expired."
            ),
            remediation=(
                "Reissue the certificate with a valid expiry window and redeploy to Nginx. "
                "Renewal should be automated to prevent this."
            )
        )
    elif days_left < 30:
        audit_result(
            "Certificate Expiry (Warning)",
            False,
            f"Certificate expiring in {days_left} days (expires {not_after.date()})",
            explanation=(
                "A cert expiring within 30 days is flagged as a warning. Renewal takes time, "
                "and missed expiry windows are one of the most common causes of unexpected outages."
            ),
            remediation="Begin renewal now. Don't wait for expiry — reissue and redeploy."
        )
    else:
        audit_result(
            "Certificate Expiry",
            True,
            f"Valid for {days_left} more days (expires {not_after.date()})"
        )
 
 
#CHECK 3----------
def get_raw_cert(hostname, port=443):
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
 
    with socket.create_connection((hostname, port), timeout=10) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as tls_sock:
            return tls_sock.getpeercert(binary_form=True)
 
def check_hostname(hostname, port=443):
    der_cert = get_raw_cert(hostname, port)
    cert = x509.load_der_x509_certificate(der_cert, default_backend())
 
    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        san_names = san_ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        san_names = []
 
    matched = False
    for san in san_names:
        if san == hostname:
            matched = True
        elif san.startswith("*."):
            wildcard_domain = san[2:]
            if hostname.endswith("." + wildcard_domain):
                matched = True
 
    detail = f"SANs on cert: {san_names}"
 
    if matched:
        audit_result("Hostname / SAN Match", True, f"{detail} — '{hostname}' matched")
    else:
        audit_result(
            "Hostname / SAN Match",
            False,
            f"{detail} — '{hostname}' not found",
            explanation=(
                "The certificate's Subject Alternative Names list every hostname it's valid for. "
                "If the hostname you're connecting to isn't in that list, the client can't confirm "
                "it's talking to the right server — even if the cert is otherwise valid. "
                "Modern TLS ignores the CN field entirely and only checks SANs."
            ),
            remediation=(
                "Reissue the leaf cert with the correct hostname in the SAN extension. "
                "Don't rely on CN — it's deprecated for hostname verification."
            )
        )
 
 
#CHECK 4----------
#simple list- weak ciphers
WEAK_CIPHERS = {
    "RC4": (
        "RC4 is a broken stream cipher. The NOMORE attack (2015) demonstrated practical "
        "plaintext recovery against RC4 in TLS. It should not appear in any config written after 2013."
    ),
    "DES": (
        "DES uses a 56-bit key, which is trivially brute-forced with modern hardware. "
        "It has been considered broken since the late 1990s."
    ),
    "3DES": (
        "3DES uses a 64-bit block size, making it vulnerable to SWEET32 birthday attacks. "
        "An attacker capturing enough traffic can recover plaintext. Deprecated by NIST in 2017."
    ),
    "MD5": (
        "MD5 as a hashing algorithm in cipher suites is cryptographically broken. "
        "Collision attacks against MD5 have been practical since 2004."
    ),
    "NULL": (
        "NULL cipher suites provide zero encryption — traffic is sent in plaintext. "
        "These exist only for testing and should never appear in a real config."
    ),
    "EXPORT": (
        "EXPORT ciphers were intentionally weakened under 1990s US export law. "
        "They were the basis of the FREAK attack (2015), which allowed forced downgrade to 512-bit RSA."
    ),
    "ANON": (
        "Anonymous cipher suites provide no server authentication. "
        "There is no way to confirm you're talking to the intended server — trivially vulnerable to MITM."
    ),
    "CBC": (
        "CBC mode in TLS 1.2 is vulnerable to padding oracle attacks (POODLE, Lucky13). "
        "Prefer AEAD cipher modes like GCM instead."
    ),
    "AES128-SHA": (
        "AES128-SHA uses CBC mode, which is vulnerable to padding oracle attacks "
        "(POODLE, Lucky13). Prefer AEAD cipher modes like GCM instead."
    ),
    "AES256-SHA": (
        "AES256-SHA uses CBC mode, which is vulnerable to padding oracle attacks "
        "(POODLE, Lucky13). Prefer AEAD cipher modes like GCM instead."
    ),
}
 
def check_cipher(hostname, port=443):
    context = ssl.create_default_context()
    context.load_verify_locations(CA_CERT)
 
    try:
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                cipher_name, tls_version, key_bits = tls_sock.cipher()
                detail = f"Cipher: {cipher_name} | TLS: {tls_version} | Key bits: {key_bits}"
 
                weak_found = {k: v for k, v in WEAK_CIPHERS.items() if k in cipher_name.upper()}
 
                if weak_found:
                    explanations = "\n              ".join(
                        [f"{k}: {v}" for k, v in weak_found.items()]
                    )
                    audit_result(
                        "Cipher Suite",
                        False,
                        detail,
                        explanation=explanations,
                        remediation=(
                            "Remove all weak ciphers from ssl_ciphers in your Nginx config. "
                            "Use Mozilla's SSL config generator (ssl-config.mozilla.org) for a current safe cipher string."
                        )
                    )
                else:
                    audit_result("Cipher Suite", True, detail)
 
    except ssl.SSLCertVerificationError as e:
        audit_result(
            "Cipher Suite",
            False,
            f"Could not negotiate cipher — cert verification failed: {e}",
            explanation="The TLS handshake failed during cipher negotiation because the certificate could not be verified. This is likely caused by an expired or untrusted cert caught in an earlier check.",
            remediation="Fix the certificate issue flagged above, then re-run to check the cipher suite."
        )
 
 
#CHECK 5----------
def check_chain(hostname, port=443):
    context = ssl.create_default_context()
    context.load_verify_locations(CA_CERT)
 
    try:
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                cert = tls_sock.getpeercert()
                issuer = dict(x[0] for x in cert['issuer'])
                subject = dict(x[0] for x in cert['subject'])
 
                detail = (
                    f"Subject: {subject.get('commonName', 'unknown')} | "
                    f"Issuer: {issuer.get('commonName', 'unknown')}"
                )
                audit_result("Chain of Trust", True, detail)
 
    except ssl.SSLCertVerificationError as e:
        audit_result(
            "Chain of Trust",
            False,
            f"Chain verification failed: {e}",
            explanation=(
                "TLS chain verification works by walking from the leaf cert up to a trusted root. "
                "If the intermediate CA cert isn't served by the server, clients that don't have it "
                "cached locally can't complete that walk and will reject the connection. "
                "This silently breaks for some clients and not others — the server itself often works "
                "fine because it has the intermediate locally, which masks the problem during basic testing. "
                "A self-signed cert will also fail here — it has no chain, it vouches only for itself."
            ),
            remediation=(
                "If missing intermediate: concatenate your leaf cert and intermediate cert into a single "
                "bundle file (leaf first, then intermediate) and point ssl_certificate at that bundle. "
                "If self-signed: reissue through your intermediate CA so the chain terminates at your trusted root."
            )
        )
    except Exception as e:
        audit_result("Chain of Trust", False, f"Error during chain check: {e}")
 
 
#CHECK 6----------
WEAK_PROTOCOLS = {
    "TLSv1": (
        "TLS 1.0 (2000) is vulnerable to BEAST and POODLE attacks, which allow an attacker to "
        "decrypt traffic under certain conditions. It was formally deprecated by the IETF in 2021 (RFC 8996). "
        "Allowing it means a client can be forced into a downgrade even if it supports TLS 1.3."
    ),
    "TLSv1.1": (
        "TLS 1.1 (2006) addressed some weaknesses in TLS 1.0 but still lacks the modern AEAD cipher "
        "support that TLS 1.2 and 1.3 require. It was deprecated alongside TLS 1.0 in RFC 8996 (2021). "
        "No current browser or client should be negotiating this version."
    ),
    "SSLv2": (
        "SSL 2.0 is catastrophically broken and has been for decades. It has fundamental design flaws "
        "including no protection against message tampering. It should be impossible to encounter in the wild."
    ),
    "SSLv3": (
        "SSL 3.0 is vulnerable- POODLE attack (2014), allows decryption of secure connections. "
        "Deprecated. If your server is negotiating SSLv3, something is seriously wrong."
    ),
}
 
def check_tls_version(hostname, port=443):
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
 
    # Allow older versions(check can detect if present)
    context.minimum_version = ssl.TLSVersion.SSLv3 if hasattr(ssl.TLSVersion, 'SSLv3') else ssl.TLSVersion.TLSv1
 
    try:
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                negotiated = tls_sock.version()
                detail = f"Negotiated protocol: {negotiated}"
 
                matched_weakness = next(
                    (explanation for proto, explanation in WEAK_PROTOCOLS.items() if proto == negotiated),
                    None
                )
 
                if matched_weakness:
                    audit_result(
                        "TLS Protocol Version",
                        False,
                        detail,
                        explanation=matched_weakness,
                        remediation=(
                            "Set ssl_protocols to 'TLSv1.2 TLSv1.3' only in your Nginx config and reload. "
                            "Remove any TLSv1 or TLSv1.1 entries entirely."
                        )
                    )
                else:
                    audit_result("TLS Protocol Version", True, detail)
 
    except Exception as e:
        audit_result("TLS Protocol Version", False, f"Could not determine protocol version: {e}")
 
 
#GENERATING AUDIT REPORT----------
def main():
    hostname = input("Enter hostname to audit (e.g. localhost): ").strip()
 
    output = io.StringIO()
    sys.stdout = output
 
    print(f"\n{'='*60}")
    print(f"  TLS Audit Report")
    print(f"  Target   : {hostname}")
    print(f"  Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*60}")
 
    cert = check_connection(hostname)
    check_expiry(cert)
    check_hostname(hostname)
    check_cipher(hostname)
    check_chain(hostname)
    check_tls_version(hostname)
 
    print(f"\n{'='*60}")
    print("  Audit complete.")
    print(f"{'='*60}\n")
 
    report_text = output.getvalue()
    sys.stdout = sys.__stdout__
 
    print(report_text)
 
    filename = f"tls_report_{hostname}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    with open(filename, "w") as f:
        f.write(report_text)
 
    print(f"Report saved to: {filename}")
 
 
if __name__ == "__main__":
    main()
 
