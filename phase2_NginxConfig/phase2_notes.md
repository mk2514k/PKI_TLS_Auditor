# Phase 2: Build Notes

[← Back to Phase 2 README](./README.md) · [Root README](../README.md)

Full build log for the Nginx TLS configuration. The README covers the decisions and the headline mistakes, this has the actual command sequence and the reasoning behind each config line.

## Phase Overview

At the end of Phase 1, the cert chain exists and OpenSSL can verify it. But there's no server serving it yet. Phase 2 is about taking that cert chain and wiring it into a live server in a way that actually enforces the security properties you built Phase 1 to provide.

Nginx needs three things to do TLS:
1. The cert (or cert bundle) to present to clients
2. The private key that corresponds to that cert
3. A config that tells it *how* to do TLS- which versions, which ciphers

Getting the certs right in Phase 1 doesn't automatically get the server config right. These are two separate problems.

## Setting up the config structure

The default Nginx config listens on port 80 (HTTP). TLS runs on 443. To get Nginx serving HTTPS, you need a server block that explicitly opens port 443 and tells Nginx to use SSL on it.

The config for this project lives at `phase2_NginxConfig/conf/cyberpathway.conf`, included via the top-level `nginx.conf`.

### Core config decisions, line by line

```nginx
server {
    listen 443 ssl;
    server_name server.cyberpathway.lab;

    ssl_certificate     /path/to/ssl/server-chain.pem;
    ssl_certificate_key /path/to/ssl/server.key;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:!RC4:!MD5:!aNULL:!eNULL:!EXPORT:!DES:!3DES;
    ssl_prefer_server_ciphers on;
}
```

**`listen 443 ssl`**: this is the one that bit me on Mistake 1. Forgetting this means Nginx never opens the port. Nothing answers. It looks like a connection problem when it's actually a config problem.

**`ssl_protocols TLSv1.2 TLSv1.3`**: no TLS 1.0, no TLS 1.1. Both formally deprecated in RFC 8996 (2021). BEAST affected TLS 1.0, POODLE affected TLS 1.1. Leaving them in gives clients a downgrade path that doesn't need to exist. TLS 1.2 is the minimum for anything you'd call "modern." TLS 1.3 strips out the legacy handshake steps that were the source of most downgrade attacks.

**`ssl_ciphers`**: the cipher string starts with preferred ECDHE+ECDSA/RSA in GCM mode (AEAD: no padding oracle vulnerability), then uses the `!` prefix to explicitly exclude RC4, MD5, anonymous ciphers, NULL ciphers, EXPORT ciphers, and CBC-mode DES/3DES. GCM mode is preferred over CBC because CBC's padding requirements are what makes POODLE and Lucky13 attacks possible in the first place.

**`ssl_prefer_server_ciphers on`**: lets the server's cipher preference list win during negotiation rather than the client's. Without this, a client could propose a weaker cipher from the allowed list and Nginx would accept it even if a stronger one was available. Keeping control on the server side means the cipher string above is actually enforced.

**`server_name server.cyberpathway.lab`**: hostname that matches the SAN on the leaf cert. Has to match or every connection will fail the SAN check, including your own auditor.

## Mistake 1: Nginx wasn't listening on port 443

After writing the server block and running `sudo systemctl reload nginx`, nothing was answering on 443. `curl https://server.cyberpathway.lab` just timed out.

Cause: the default Nginx config doesn't include a 443 listener. You have to put it there explicitly. The `listen 443 ssl;` line was missing from the initial draft.

Fix: added `listen 443 ssl;` to the server block, re-tested, reloaded.

## Mistake 2: Private key permission was 400

After fixing the port issue, Nginx started throwing permission errors when trying to load the private key. The key file had been set to `chmod 400` (read-only, owner only) at the end of Phase 1 — which made sense for securing the key, but broke Nginx's ability to read it during startup.

Fix:
```bash
sudo chmod 644 phase2_NginxConfig/ssl/server.key
```

644 is broader than ideal for a private key (it's world-readable), but Nginx's worker process runs as a separate user and needs read access. For a production setup the right answer is `chown` to give the Nginx user ownership specifically. For a local lab, 644 is the working fix.

## Mistake 3: Same permission issue on the cert file

Same problem, different file. The `server.cert` file was also locked down. Nginx needs to read both the cert and the key on startup.

Fix:
```bash
sudo chmod 644 phase2_NginxConfig/ssl/server.cert
```

## Mistake 4 — Nginx couldn't follow the file paths

After reorganising the SSL files into the `ssl/` subfolder (rather than having them scattered across Phase 1's folder structure), the `ssl_certificate` and `ssl_certificate_key` directives in the config were still pointing at the old absolute paths. Nginx couldn't find anything at those locations.

Fix: updated both directives in `cyberpathway.conf` to the correct paths for the new folder layout. Tested with `sudo nginx -t` before reloading to confirm Nginx could actually parse and follow the paths.

## Mistake 5 — TLS handshake failing, Intermediate CA not found

This one was the most confusing because it wasn't consistent. Connecting from the same machine that built the CA worked fine — but that machine already had the Intermediate cert cached from Phase 1. A fresh connection from a client that didn't have it cached would fail the chain walk.

The problem: Nginx was only serving `server.cert` (the leaf cert). A client receiving only the leaf cert has no way to verify who signed it without separately fetching the Intermediate. Most real-world CAs handle this by embedding a URL to the Intermediate in the cert's AIA (Authority Information Access) extension — but this is a private CA with no public AIA. So the client just fails.

Fix: build a cert bundle that includes both the leaf cert and the Intermediate cert, in the right order — leaf first, then Intermediate:

```bash
cat phase2_NginxConfig/ssl/server.cert \
    phase1_2TierCA/certs/intermediateCA/cert/intermediateCA.cert \
    > phase2_NginxConfig/ssl/server-chain.pem
```

Then point `ssl_certificate` at `server-chain.pem` instead of `server.cert`. Now Nginx serves the full chain in the handshake and clients can verify all the way up to the root without needing anything cached.

## Testing the config before reloading

This is worth making a habit of `sudo nginx -t` will catch syntax errors and bad paths before they cause a reload failure:

```bash
sudo nginx -t
# nginx: the configuration file ... syntax is ok
# nginx: configuration file ... test is successful
```

Then:

```bash
sudo systemctl reload nginx
```

Not restart `reload` sends a signal to Nginx to re-read its config without killing active connections. Restart would drop everything mid-flight.

## Confirming the TLS handshake

```bash
openssl s_client -connect server.cyberpathway.lab:443 \
    -CAfile phase1_2TierCA/certs/rootCA/cert/rootCA.cert
```

A clean handshake will show the negotiated protocol (`TLSv1.3`), the cipher suite, and the cert chain walking up through Intermediate to Root. If the chain is broken or the cert doesn't match the hostname, OpenSSL will say so explicitly.

Adding the hostname to `/etc/hosts` is also required for local resolution to work:

```
127.0.0.1    server.cyberpathway.lab
```

Without this, DNS can't resolve the hostname to your local Nginx instance and nothing connects regardless of how correct the TLS config is.

Phase 2 complete.
