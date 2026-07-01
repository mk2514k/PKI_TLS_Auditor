# Phase 2 — Nginx TLS Configuration

[← Root README](../README.md) · [← Phase 1](../phase1_2TierCA/README.md) · [Phase 3 →](../phase3_pythonAuditor/README.md) · Full build log: [NOTES.md](./NOTES.md)

## What this phase proves

Getting a cert chain to pass OpenSSL verification is one thing. Getting a real server to actually serve that chain over TLS, correctly, to a connecting client — that's another problem entirely. This phase took the certs from Phase 1 and wired them into Nginx with a config that enforces TLS 1.2/1.3 only, rejects weak ciphers, and serves the full cert bundle so clients can walk the chain without already having the Intermediate cached. It generated five separate mistakes before the TLS handshake completed cleanly, most of them around file permissions and pathing — the kind of thing that doesn't show up in guides.

## File structure

```
phase2_NginxConfig/
├── conf/
│   ├── cyberpathway.conf   ← the actual TLS server block
│   └── nginx.conf          ← top-level Nginx config
└── ssl/
    ├── server.cert
    ├── server-chain.pem    ← leaf + intermediate, concatenated
    └── server.key
```

## Key decisions

**TLS 1.2 and 1.3 only.** The config explicitly lists `ssl_protocols TLSv1.2 TLSv1.3` — nothing older. TLS 1.0 and 1.1 are both formally deprecated (RFC 8996, 2021) and vulnerable to BEAST and POODLE attacks respectively. Allowing them gives clients a downgrade path that doesn't need to exist.

**Cipher string — no weak entries.** The `ssl_ciphers` directive uses a string that explicitly excludes CBC-mode ciphers (POODLE, Lucky13) and anything with RC4, NULL, or EXPORT in the name. AEAD ciphers (GCM) are preferred throughout. Mozilla's SSL config generator was the reference point — it's the standard tool for this and it's worth knowing about.

**`server-chain.pem` — the cert bundle.** This was the fix for a frustrating intermittent TLS failure (Mistake 5 below). Nginx needs to serve the full chain for clients that don't have the Intermediate CA cached — leaf cert alone isn't enough, because the client can't complete the chain walk to the trusted root without it. The bundle is just the leaf cert and the Intermediate cert concatenated into one file, leaf first:

```bash
cat server.cert ../phase1_2TierCA/certs/intermediateCA/cert/intermediateCA.cert > server-chain.pem
```

Simple fix, but it took a failed handshake and some digging to understand *why* serving just the leaf cert was breaking things for clients that hadn't already fetched the Intermediate.

## Mistakes made

**Mistake 1 — Nginx wasn't listening on port 443 at all.** The default Nginx config only listens on port 80. After writing the TLS server block and reloading, nothing was actually answering on 443 because I hadn't explicitly opened and configured that port in the server block. The `listen 443 ssl;` directive has to be there.

**Mistake 2 — Private key permissions were 400.** The key file was read-only (from the `chmod 400` applied back in Phase 1), which meant Nginx couldn't read it when starting up. Fixed with `sudo chmod 644`. This felt uncomfortable to do — 644 is broader than ideal for a private key — but Nginx's worker process runs as a different user and needs read access. The right long-term answer here is to make the key readable by the Nginx user specifically, not world-readable, but `chmod 644` is the working fix for a local lab.

**Mistake 3 — Same permission issue on the cert file.** Same root cause, same fix. The cert files had been locked down the same way as the keys at the end of Phase 1. `sudo chmod 644` on `server.cert` as well.

**Mistake 4 — Nginx couldn't resolve the file paths.** Moving the cert and key into a dedicated `ssl/` subfolder introduced pathing issues — Nginx was looking for files at the old absolute paths that no longer existed. Easier to update the config's `ssl_certificate` and `ssl_certificate_key` directives to point at the new paths and move on than to chmod everything in the old directory tree.

**Mistake 5 — TLS handshake failing intermittently — missing Intermediate.** This was the trickiest one to diagnose because it wasn't consistent. The handshake would work fine when connecting from the same machine (which had the Intermediate cached), but fail for clients that didn't. Cause: Nginx was only serving the leaf cert. A client receiving just the leaf cert has no way to verify who signed it unless it already has the Intermediate locally. Fix: bundle the leaf and Intermediate into `server-chain.pem` and point `ssl_certificate` at the bundle instead.

![Nginx config file](../screenshots/nginx%20config%20file.png)

## Verifying it works

After every config change, always test before reloading:

```bash
sudo nginx -t
```

Output should be:

```
nginx: the configuration file /etc/nginx/nginx.conf syntax is ok
nginx: configuration file /etc/nginx/nginx.conf test is successful
```

Then reload (not restart — restart kills in-flight connections):

```bash
sudo systemctl reload nginx
```

And verify the TLS handshake from the command line:

```bash
openssl s_client -connect server.cyberpathway.lab:443 -CAfile phase1_2TierCA/certs/rootCA/cert/rootCA.cert
```

Full decision-by-decision breakdown and the raw troubleshooting trail for all five mistakes are in [NOTES.md](./NOTES.md).
