# ups3rt — wildcard certificate manager

Obtains wildcard TLS certificates from Let's Encrypt, stores them in S3,
and renews them automatically before they expire.

---

## How it works

### 1. ACME account bootstrap

On first run the service generates an **EC P-256 key** (`/data/account.key`)
and registers a Let's Encrypt account against that key.  On every subsequent
run the same key file is reloaded and `newAccount` is called again.

Let's Encrypt returns HTTP 409 if the key is already registered, which the
`acme` library surfaces as `ConflictError`.  The error carries the existing
account URL in its `Location` header.  The service catches this, writes the
URL into `acme.net.account`, and continues — this is required because all
post-registration requests must include the account URL as a Key ID (`kid`)
in the JWS header rather than the raw public key (`jwk`).  Without it,
Let's Encrypt rejects every subsequent call with *"No Key ID in JWS header"*.

### 2. Per-domain certificate issuance

For each domain listed in `UPS3RT_DOMAINS` the service checks whether the
current certificate (if any) expires within `UPS3RT_RENEW_BEFORE_DAYS` days
(default 30).  If renewal is needed:

1. A **per-domain EC P-256 key** is loaded from (or generated at)
   `/data/certs/<domain>/privkey.pem`.  The same key is reused across
   renewals so downstream consumers do not need to be updated on every cycle.

2. A **CSR** is generated for both `*.domain` and `domain` (the bare apex),
   because wildcard certificates do not cover the apex by themselves.

3. An **ACME order** is submitted.  Let's Encrypt responds with one or two
   *authorizations* — one for the wildcard identifier and one for the bare
   domain — each carrying a **DNS-01 challenge**.

### 3. DNS-01 challenge via Cloudflare

DNS-01 proves domain ownership by publishing a short token as a DNS TXT
record under `_acme-challenge.<domain>`.  The service:

1. Calls the Cloudflare API to **create** a TXT record for every pending
   authorization (there can be two: one for `*.domain`, one for `domain`
   — both point at the same `_acme-challenge.<domain>` name).
2. Waits `UPS3RT_CF_PROPAGATION` seconds (default 60) for DNS propagation.
3. Tells Let's Encrypt "go ahead and check" for each authorization.
4. **Always deletes** the TXT records in a `finally` block, whether
   validation succeeded or not.

### 4. Certificate download and storage

Once Let's Encrypt validates the challenges it issues the certificate.
The service splits the returned PEM chain into individual files and writes
them to `/data/certs/<domain>/`:

| File | Contents |
|---|---|
| `fullchain.pem` | End-entity cert + intermediate chain (use this for most servers) |
| `cert.pem` | End-entity certificate only |
| `chain.pem` | Intermediate chain only |
| `privkey.pem` | EC P-256 private key (PKCS#8 PEM) |

### 5. S3 upload

All four files are uploaded to `s3://<UPS3RT_S3_BUCKET>/certs/<domain>/`.
Each S3 object carries an object metadata key:

```
last-refreshed: 2025-03-01T12:00:00+00:00
```

This lets you inspect when a certificate was last pushed without downloading
the file itself (`aws s3api head-object ...`).

### 6. Renewal loop

After processing all domains the daemon sleeps for `UPS3RT_RENEWAL_INTERVAL`
seconds (default 43 200 = 12 h) and repeats.  Because the expiry check
short-circuits issuance for healthy certs, most iterations are a no-op.
Let's Encrypt certificates are valid for 90 days; with the 30-day renewal
window you get roughly 60 days of buffer.

---

## Persistent state layout

```
/data/
  account.key              EC P-256 ACME account key (shared across domains)
  certs/
    example.com/
      privkey.pem          EC P-256 domain key  (unique per domain)
      cert.pem
      chain.pem
      fullchain.pem
    other.org/
      ...
```

---

## Configuration reference

| Variable | Required | Default | Description |
|---|---|---|---|
| `UPS3RT_DOMAINS` | yes | — | Comma-separated domains. Subdomains (e.g. `sub.example.com`) are fine; the Cloudflare zone is found by walking up parent labels |
| `UPS3RT_ACME_EMAIL` | yes | — | Let's Encrypt account e-mail |
| `UPS3RT_S3_BUCKET` | yes | — | S3 bucket for certificate upload |
| `CF_Token` | yes | — | Cloudflare API token (Zone:Read + DNS:Edit) |
| `UPS3RT_DATA_DIR` | no | `/data` | Persistent state root |
| `UPS3RT_RENEWAL_INTERVAL` | no | `43200` | Seconds between renewal checks |
| `UPS3RT_RENEW_BEFORE_DAYS` | no | `30` | Renew when fewer than N days remain |
| `UPS3RT_CF_PROPAGATION` | no | `60` | Seconds to wait for DNS propagation |
| `UPS3RT_ACME_DIRECTORY` | no | LE production | ACME directory URL |
| `UPS3RT_METRICS_PORT` | no | `9402` | Port for the Prometheus `/metrics` endpoint. The exporter recomputes all values on every scrape from disk — no background thread — so the port being up does not mean a cycle is in progress. |

Every variable marked *yes* can alternatively be supplied as a Docker secret
mounted at `/run/secrets/<variable-name>`.

---

## Cloudflare token permissions

Create a scoped API token (not the Global API Key) with:

- **Zone → Zone → Read** (so the service can look up your zone ID; for a subdomain this is the *parent* zone, e.g. `example.com` for `sub.example.com`)
- **Zone → DNS → Edit** (so it can create and delete `_acme-challenge` TXT records)

Scope it to only the zones you need.
