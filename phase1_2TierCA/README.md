# Phase 1: 2 Tier CA Authority

[← Back to root README](../README.md) · Full build log: [NOTES.md](https://github.com/mk2514k/PKI_TLS_Auditor/blob/main/phase1_2TierCA/phase1_notes.md)

## Core Phase Objective

This is where the actual trust chain gets built. A self-signed Root CA that signs an Intermediate CA, which then signs the leaf cert that everything downstream depends on. Doing this by hand is what made "chain of trust" stop being a phrase from a textbook; it became something tangible-something I could point at and explain: *this* cert is trusted because this one signed it, which is trusted because this one signed it.
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


## Architectural Decisions

**Root CA: RSA 4096, 10-year lifespan.**

**Intermediate: RSA 4096, 5-year lifespan.**

**Leaf: RSA 2048, 1-year lifespan.** 

This isn't arbitrary. It mirrors the convention most enterprise PKI setups actually use. The root sits the furthest from anything client-facing and operates in the most locked-down environment, so it gets the longest life and the strongest key. Each tier down trades some of that lifespan for closer proximity to what's actually serving traffic.

**`policy_strict` over `policy_any` on the Root CA config.** `policy_any` lets a CSR's distinguished name fields be whatever the requester puts in them. `policy_strict` forces country, state, and organisation fields on any cert the CA signs to *match* the CA's own. This is what real enterprise CAs actually enforce, since it stops anyone from getting a cert signed under a name that doesn't belong to the org's hierarchy. I used `match` on country/state/org, left organizational unit optional, and required `supplied` on commonName.

**RSA over ECDSA.** ECDSA keys are smaller and faster, and I knew that going in. I picked RSA anyway because it's still the default in most enterprise environments I'm likely to actually run into, and the goal here was to mirror real infrastructure decisions, not just pick whatever's technically newer.

## Technical Challenges & Takeaways

**Locked myself out of the Root CA's own private key:** 

I typed the PEM passphrase, then ran `chmod 400` on the key file *before* confirming it had actually saved correctly. The passphrase entry hadn't gone through cleanly, the key was unusable, and `chmod 400` meant I couldn't even get back in to check. Ket had to be deleted and a new key needed to be regenerated. Now I check the file is readable and correct before I lock permissions down. It sounds obvious in hindsight, wasn't as obvious at 11pm mid-build.


**Generic CommonName on the Root cert:** #

First pass, I left the CommonName as just `mk` instead of something identifiable like `mk-rootCA`. Worked fine technically, but it made the cert inspection output confusing later when comparing it against the Intermediate cert. Deleted it, regenerated with a proper CN.


**Corrupted the Intermediate CA's private key from a passphrase mismatch:** 

When OpenSSL generates a key with `-aes256`, it asks for the passphrase twice to confirm. If the two entries don't match, OpenSSL doesn't always fail loudly — it can write a malformed or empty key file using whatever it caught from the first prompt, and just move on. I didn't catch this until I tried to use the key later. Full detail on diagnosing this is in the notes.

![Private key corrupted from a passphrase mismatch](../screenshots/intermediateCA%20private%20key%20corrupted-mistake.png)


**Signed leaf cert had the wrong SANs entirely:** 

Even though the SAN was correctly set in the leaf's own config file, the cert OpenSSL produced had a completely different SAN (`your-server.internal` instead of `server.cyberpathway.lab`). The cause: by default, OpenSSL doesn't carry a CSR's requested extensions over to the signed certificate — the Intermediate CA just ignores them unless told otherwise. Fixed by regenerating the CSR and re-signing with `copy_extensions = copyall` in the Intermediate's config, which forces OpenSSL to actually honour what the CSR asked for.


## Verifying the chain

Once the Root, Intermediate, and leaf certs all existed, the only thing that actually proves the chain works is asking OpenSSL to verify it:

```bash
openssl verify -CAfile certs/rootCA/cert/rootCA.cert certs/intermediateCA/cert/intermediateCA.cert
```

A working chain returns:

```
intermediateCA.cert: OK
```

![Full chain verification output](../screenshots/verification%20of%20full%20chain.png)

Command-by-command build sequence, every config file decision, and the raw troubleshooting trail for all four mistakes above live in [NOTES.md]([./NOTES.md](https://github.com/mk2514k/PKI_TLS_Auditor/blob/main/phase1_2TierCA/phase1_notes.md)).
