# Phase 1- Build Notes

[← Back to Phase 1 README](./README.md) · [Root README](../README.md)

This is the full build log — every command, every config decision, every "wait, why did that happen" moment. The README has the polished version of the mistakes; this has the raw trail of getting there.

## Background- what a 2-tier CA actually is

**Root CA**
Self-signed. Sits at the top of the chain and issues certs to the Sub/Intermediate CA. Because revoking or expiring the root cert breaks trust for the *entire* chain underneath it, it's given a long expiration (5-30 years in real deployments) and is meant to operate in a highly secure, rarely-touched environment. You don't want to be regenerating your root often.

**Intermediate (Sub) CA**
Second link in the chain. Its cert is signed by the root. It issues certs either to another intermediary or directly to end entities (servers, in this case). It gets a shorter expiration than the root, because it's closer to day-to-day use and more exposed.

**CRL- Certificate Revocation List**
A list of certs that have been revoked before their natural expiry, including the revocation timestamp, signed by the CA's own private key. There are two flavours: a *base* CRL, which is every revoked cert ever (grows large, gets unwieldy to read), and a *delta* CRL, which is just the latest updates — smaller, easier to check against quickly.

## Setting up the environment

Before generating any keys, OpenSSL needs a random data file to seed its RNG (random number generator) from. This isn't optional- it actually matters for security, not just as a formality.

Computers can't generate truly random numbers — they pull from an entropy pool built from things like timing jitter and hardware noise. OpenSSL draws from that pool when it generates keys. "Seeding" gives the RNG a starting point to grow that entropy pool from. The reason this matters at all: the whole PKI is only as strong as its private keys, and the keys are only as strong as the randomness used to generate them. A weak seed means a theoretically guessable key, even if everything else about the setup is correct.

### The data directory files

Inside each CA's `data/` folder, OpenSSL expects specific filenames:

- `index.dat` : the logbook. Tracks every cert the CA has issued, their status, and metadata. I tried renaming this at one point and OpenSSL stopped recognizing it — it specifically expects this name (it's *not* the CRL, easy to assume it is at first glance since it's tracking certs).
- `serial.dat` : the stamp. Keeps the running serial number so every issued cert gets a unique identifier.
- `crl_number` : version counter, used the next time a CRL gets generated.

### Final folder structure

```
Phase1_2TierCA/
├── auditor/
│   └── sample_reports/
├── certs/
│   ├── intermediateCA/
│   │   ├── cert/
│   │   └── issued-certs/
│   └── rootCA/
│       ├── cert/
│       └── issued-certs/
├── intermediateCA/
│   ├── csr/
│   ├── data/
│   │   ├── crl_number
│   │   ├── index.dat
│   │   └── serial.dat
│   └── private/
├── leafCerts/
│   ├── csr/
│   └── private/
├── notes.md
├── rootCA/
│   ├── data/
│   │   ├── crl_number
│   │   ├── index.dat
│   │   └── serial.dat
│   └── private/
└── screenshots/
```

## Root CA config (`rootCA.cnf`)

Started from a tutorial base config and amended it to match my own folder structure and naming.

**`policy_strict` vs `policy_any`** — went with `policy_strict` to mirror real enterprise PKI behaviour:

```
countryName             = match
stateOrProvinceName     = match
organizationName        = match
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional
```

`match` means anything the Root CA signs has to carry the same country/state/org as the CA itself — stops the CA from signing a cert claiming to belong to a completely different organization.

**Key size** — set to 4096 bits. Higher bit count, more secure key. General enterprise convention (which I matched here):

- Root CA — 4096, 10 years
- Intermediate CA — 4096, 5 years
- Leaf certs — 2048, 1-2 years

**RSA over ECDSA** — went with RSA since it's still the industry default in most environments I'd realistically encounter, even though ECDSA is more efficient and produces smaller keys.

The `req_distinguished_name` section in the config is where the Root CA's actual identity gets defined — this is what shows up when anything inspects the cert later.

## Generating the Root CA private key

Chose RSA 4096 (reasoning above), modified the key generation command to match my folder paths.

**Mistake — locked myself out of my own key.** Typed the PEM passphrase, but it didn't save correctly — and before checking that, I ran `chmod 400` on the key file. With 400 permissions and a key that hadn't saved properly, I had no way back in. Deleted it, regenerated, and this time confirmed the file actually saved and was readable *before* locking down permissions.

PEM passphrase used: `mk-rootCA!2026cybers3c`

![Passphrase mistake, step 1](../screenshots/pem%20passphrase%20mistake1.png)
![Passphrase mistake, step 2](../screenshots/pem%20passphrase%20mistake2.png)

## Generating the Root CA cert

Used the absolute filepath throughout rather than relative — longer to type, but it removed any ambiguity about which file I was pointing at while I was still getting comfortable with the structure. Pathways have been sanitised for publication

```bash
projects/pki-tls-auditor/rootCA/rootCA.cnf \
projects/pki-tls-auditor/rootCA/private/rootCA.key \
  -new -x509 -sha256 -extensions v3_ca -days 3650 \
  projects/pki-tls-auditor/certs/rootCA/cert/rootCA.cert
```

Inspected the result with `x509 -text` to confirm the fields matched what I expected.

**Mistake- generic CommonName.** First version of the cert had CommonName set to just `mk`. Worked, but it was confusing later when I had the Intermediate cert sitting next to it and couldn't tell them apart at a glance during inspection. Deleted and regenerated with `mk-rootCA` instead.

## Intermediate CA config

Lifespan set to 1825 days (5 years) — shorter than the root, in line with the industry convention noted above.

Added an `alt_names` block to this config — this is where the leaf certs generated *from* this Intermediate get their SAN entries defined.

## Generating the Intermediate CA private key

Same process as the Root key.

```bash
openssl genrsa -aes256 -out projects/pki-tls-auditor/intermediateCA/private/intermediateCA.key 4096
```

PEM passphrase: `mk-1ntermediateCA?2026cybers3c`

## Generating the Intermediate's CSR

A few differences worth noting compared to the Root cert generation command:

- This is a *request* for a cert, not a cert itself — no `-x509` flag (that flag is what self-signs the Root cert)
- No `-days` flag — expiry gets set later, when the Root actually signs it
- Output goes to `csr/`, not `cert/`, since it's not signed yet

## Signing the Intermediate's CSR (Root signs Intermediate)

Used the Root's passphrase here, since the Root is the one doing the signing. OpenSSL asks for double confirmation in the terminal, printing the distinguished name fields back for review before committing.

Ran an inspection afterward to confirm the signed cert's issuer field correctly pointed back to the Root.

![Intermediate cert inspection, part 1]([../screenshots/intermediateCA-cert-inspection1.png](https://github.com/mk2514k/PKI_TLS_Auditor/blob/28aa54495f8e664599412dc4531ae8aefd8d57b2/screenshots/intermediateCA-cert-inspection1.png)
![Intermediate cert inspection, part 2]([../screenshots/intermediateCA-cert-inspection2.png](https://github.com/mk2514k/PKI_TLS_Auditor/blob/28aa54495f8e664599412dc4531ae8aefd8d57b2/screenshots/intermediateCA-cert-inspection2.png)

## Verifying the chain (midpoint check)

```bash
openssl verify -CAfile <path>/cert/rootCA.cert <path>/certs/intermediateCA/cert/intermediateCA.cert
```

![Chain verification at the midpoint](../screenshots/verification%20of%20chain%20midpoint.png)

## Generating the leaf cert

Realised partway through that I needed a dedicated `leafCerts/` folder — hadn't planned for it in the original tree, added it once I got here.

**Mistake — corrupted the Intermediate's private key.** When OpenSSL generates a key with `-aes256`, it prompts for the passphrase twice to confirm they match. When the two entries didn't match here, OpenSSL didn't fail cleanly — it either creates an empty/malformed key file and exits, or it encrypts the key using whatever was typed on the *first* prompt before catching the mismatch. Either way, the result is a key that looks like it exists but doesn't actually work. Took a bit of trial and error to realise this was what had happened rather than assuming I'd mistyped the key generation command itself.

![Intermediate private key corrupted](../screenshots/intermediateCA%20private%20key%20corrupted-mistake.png)
![Intermediate private key fixed](../screenshots/intermediateCA%20cert%20private%20key%20fixed.png)

**Mistake — wrong SANs on the signed leaf cert.** The leaf's own config had the correct SAN (`server.cyberpathway.lab`) — but the *signed* cert came out with `your-server.internal` instead. Root cause: the Intermediate CA's signing process doesn't carry over a CSR's requested extensions by default — it just ignores them unless explicitly told to copy them. Fixed by regenerating the CSR and re-signing with `copy_extensions = copyall` set in the Intermediate's config, which forces OpenSSL to actually honour the SANs the CSR was asking for.

![SAN mismatch, step 1](../screenshots/sans%20mismatch-mistake1.png)
![SAN mismatch, step 2](../screenshots/sans%20mismatch-mistake2.png)

Inspected the corrected leaf cert to confirm the SAN now matched:

![Leaf cert inspection, part 1](../screenshots/leafCert%20inspection%201.png)
![Leaf cert inspection, part 2](../screenshots/leafCert%20inspection%202.png)

## Full chain verification

```bash
openssl verify -CAfile certs/rootCA/cert/rootCA.cert -untrusted certs/intermediateCA/cert/intermediateCA.cert certs/intermediateCA/issued-certs/server.cert
```

A clean result confirms the leaf walks all the way up to the trusted root through the Intermediate without breaking anywhere in between.

![Full chain verification](../screenshots/verification%20of%20full%20chain.png)

Phase 1 complete.
