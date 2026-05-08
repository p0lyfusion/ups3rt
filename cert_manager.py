#!/usr/bin/env python3
"""
Wildcard certificate manager daemon.

Obtains / renews wildcard certs via Let's Encrypt (ACME v2) using a
Cloudflare DNS-01 challenge, uploads them to S3, and loops indefinitely
to keep them fresh.

Required env vars (or Docker secrets at /run/secrets/<name>):
  UPS3RT_DOMAINS        Comma-separated domains (apex or subdomain; the Cloudflare
                        zone is found by walking up parent labels), e.g.
                        "example.com,sub.other.org"
  UPS3RT_ACME_EMAIL     Contact e-mail for the Let's Encrypt account
  UPS3RT_S3_BUCKET      Target S3 bucket name
  CF_Token              Cloudflare API token with Zone:Read + DNS:Edit

Optional env vars:
  UPS3RT_DATA_DIR          Persistent state root (default: /data)
  UPS3RT_RENEWAL_INTERVAL  Seconds between renewal checks (default: 43200 = 12 h)
  UPS3RT_RENEW_BEFORE_DAYS Renew when fewer than N days remain (default: 30)
  UPS3RT_CF_PROPAGATION    Seconds to wait for DNS propagation (default: 60)
  UPS3RT_ACME_DIRECTORY    ACME directory URL (default: Let's Encrypt production)
  UPS3RT_S3_ENDPOINT       S3-compatible endpoint URL (default: Timeweb Cloud)
  UPS3RT_S3_REGION         S3 region name (default: ru-1)

S3 layout per domain:
  certs/{domain}/fullchain.pem
  certs/{domain}/privkey.pem
  certs/{domain}/cert.pem
  certs/{domain}/chain.pem

Every S3 object gets an object metadata key "last-refreshed" (ISO-8601 UTC).
"""

import json
import logging
import os
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

import cloudflare
import josepy
from acme import challenges, client, crypto_util, errors as acme_errors, messages
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from connect import s3
from metrics import start_metrics_server

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

def _secret(env_var: str) -> str:
    """Read from env var, falling back to a Docker secret file."""
    val = os.environ.get(env_var)
    if val:
        return val
    secret_path = Path("/run/secrets") / env_var
    if secret_path.exists():
        return secret_path.read_text().strip()
    raise RuntimeError(
        f"Required secret not found: set env var {env_var!r} "
        f"or mount it at {secret_path}"
    )


DOMAINS: list[str] = [
    d.strip().strip(".").lower()
    for d in os.environ["UPS3RT_DOMAINS"].split(",")
    if d.strip().strip(".")
]
ACME_EMAIL: str = _secret("UPS3RT_ACME_EMAIL")
S3_BUCKET: str = _secret("UPS3RT_S3_BUCKET")
CF_TOKEN: str = _secret("CF_Token")

DATA_DIR = Path(os.environ.get("UPS3RT_DATA_DIR", "/data"))
RENEWAL_INTERVAL = int(os.environ.get("UPS3RT_RENEWAL_INTERVAL", str(12 * 3600)))
RENEW_BEFORE_DAYS = int(os.environ.get("UPS3RT_RENEW_BEFORE_DAYS", "30"))
CF_PROPAGATION = int(os.environ.get("UPS3RT_CF_PROPAGATION", "60"))
ACME_DIRECTORY = os.environ.get(
    "UPS3RT_ACME_DIRECTORY",
    "https://acme-v02.api.letsencrypt.org/directory",
)


# ---------------------------------------------------------------------------
# Key helpers
# ---------------------------------------------------------------------------

def _load_or_create_ec_key(path: Path) -> ec.EllipticCurvePrivateKey:
    """Load an EC P-256 private key from *path*, or generate and save a new one."""
    if path.exists():
        return serialization.load_pem_private_key(path.read_bytes(), password=None)
    key = ec.generate_private_key(ec.SECP256R1())
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    log.info("Generated new EC P-256 key at %s", path)
    return key


# ---------------------------------------------------------------------------
# ACME client
# ---------------------------------------------------------------------------

def _build_acme_client() -> tuple[client.ClientV2, josepy.JWKEC]:
    """Create (or reuse) an ACME account and return a ready ClientV2."""
    acct_key = _load_or_create_ec_key(DATA_DIR / "account.key")
    jwk = josepy.JWKEC(key=acct_key)
    net = client.ClientNetwork(jwk, user_agent="ups3rt-cert-manager/1.0", alg=josepy.jwa.ES256)
    directory = messages.Directory.from_json(net.get(ACME_DIRECTORY).json())
    acme = client.ClientV2(directory, net)
    try:
        acme.new_account(
            messages.NewRegistration.from_data(
                email=ACME_EMAIL,
                terms_of_service_agreed=True,
            )
        )
        log.info("ACME account registered (directory: %s)", ACME_DIRECTORY)
    except acme_errors.ConflictError as e:
        # Account with this key already exists. The error carries the account
        # URL (Location header). Set it on the network client so subsequent
        # requests use KID instead of JWK in the JWS header — without this
        # Let's Encrypt rejects every post-registration request.
        acme.net.account = messages.RegistrationResource(
            uri=e.location,
            body=messages.Registration(),
        )
        log.info("ACME account already exists, reusing (directory: %s)", ACME_DIRECTORY)
    return acme, jwk


# ---------------------------------------------------------------------------
# Cloudflare DNS helpers
# ---------------------------------------------------------------------------

def _zone_id(cf: cloudflare.Cloudflare, domain: str) -> str:
    """Find the active zone containing *domain*, walking up parent labels.

    A subdomain such as ``sub.quic.foo`` usually has no zone of its own and
    lives inside ``quic.foo``; try the most specific candidate first.
    """
    labels = domain.split(".")
    candidates = [".".join(labels[i:]) for i in range(len(labels) - 1)]  # no bare TLD
    for candidate in candidates:
        zone = next(iter(cf.zones.list(name=candidate, status="active")), None)
        if zone:
            log.info("[%s] Using Cloudflare zone %s (%s)", domain, candidate, zone.id)
            return zone.id
    raise RuntimeError(
        f"No active Cloudflare zone found for domain {domain!r} "
        f"(tried: {', '.join(candidates)})"
    )


@contextmanager
def _managed_txt_records(
    cf: cloudflare.Cloudflare,
    zone_id: str,
    records: list[tuple[str, str]],  # [(dns_name, txt_value), ...]
) -> Iterator[None]:
    """Create TXT records, yield, then unconditionally delete them."""
    created_ids: list[str] = []
    try:
        for name, value in records:
            rec = cf.dns.records.create(
                zone_id=zone_id,
                name=name,
                type="TXT",
                content=value,
                ttl=60,
            )
            created_ids.append(rec.id)
            log.info("DNS TXT created: %s  →  %r", name, value)
        yield
    finally:
        for rec_id in created_ids:
            try:
                cf.dns.records.delete(rec_id, zone_id=zone_id)
                log.info("DNS TXT deleted: %s", rec_id)
            except Exception:
                log.warning("Failed to delete DNS TXT record %s", rec_id, exc_info=True)


# ---------------------------------------------------------------------------
# Certificate state helpers
# ---------------------------------------------------------------------------

def _cert_dir(domain: str) -> Path:
    return DATA_DIR / "certs" / domain


def _needs_renewal(domain: str) -> bool:
    cert_path = _cert_dir(domain) / "cert.pem"
    if not cert_path.exists():
        log.info("[%s] No existing certificate found", domain)
        return True
    cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
    remaining = cert.not_valid_after_utc - datetime.now(timezone.utc)
    log.info("[%s] Certificate expires in %d day(s)", domain, remaining.days)
    return remaining.days < RENEW_BEFORE_DAYS


def _save_cert_files(domain: str, fullchain_pem: str) -> None:
    """Persist cert + chain PEMs to DATA_DIR/certs/{domain}/."""
    cert_dir = _cert_dir(domain)
    cert_dir.mkdir(parents=True, exist_ok=True)

    raw = fullchain_pem.encode() if isinstance(fullchain_pem, str) else fullchain_pem
    delimiter = b"-----END CERTIFICATE-----\n"
    split_at = raw.index(delimiter) + len(delimiter)
    cert_pem = raw[:split_at]
    chain_pem = raw[split_at:]

    (cert_dir / "fullchain.pem").write_bytes(raw)
    (cert_dir / "cert.pem").write_bytes(cert_pem)
    (cert_dir / "chain.pem").write_bytes(chain_pem)
    # privkey.pem is written by _load_or_create_ec_key before CSR generation


# ---------------------------------------------------------------------------
# Core issuance logic
# ---------------------------------------------------------------------------

def issue_or_renew(
    domain: str,
    acme: client.ClientV2,
    jwk: josepy.JWKEC,
    cf: cloudflare.Cloudflare,
) -> bool:
    """
    Issue or renew a wildcard certificate for *domain*.

    Returns True when a new certificate was obtained, False when skipped.
    Raises on unrecoverable errors.
    """
    if not _needs_renewal(domain):
        log.info("[%s] Certificate is still fresh — skipping", domain)
        return False

    log.info("[%s] Starting certificate issuance", domain)
    cert_dir = _cert_dir(domain)

    # Domain private key (persisted; reused across renewals for key continuity)
    domain_key = _load_or_create_ec_key(cert_dir / "privkey.pem")
    domain_key_pem = domain_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )

    # Resolve the zone before placing an order so a lookup failure doesn't
    # leave a dangling order at the CA.
    zone_id = _zone_id(cf, domain)

    csr_der = crypto_util.make_csr(domain_key_pem, [f"*.{domain}", domain])
    order = acme.new_order(csr_der)

    # Collect pending DNS-01 challenges across all authorizations
    pending: list[tuple[object, object]] = []  # [(challb, auth), ...]
    txt_records: list[tuple[str, str]] = []

    for auth in order.authorizations:
        if auth.body.status == messages.STATUS_VALID:
            continue
        challb = next(
            (c for c in auth.body.challenges if isinstance(c.chall, challenges.DNS01)),
            None,
        )
        if challb is None:
            raise RuntimeError(
                f"[{domain}] No DNS-01 challenge offered for "
                f"{auth.body.identifier.value!r}"
            )
        # _acme-challenge always lives under the bare (non-wildcard) domain
        base = auth.body.identifier.value.lstrip("*.").lstrip(".")
        txt_name = f"_acme-challenge.{base}"
        txt_value = challb.chall.validation(jwk)

        txt_records.append((txt_name, txt_value))
        pending.append((challb, auth))

    if not pending:
        log.info("[%s] All authorizations already valid", domain)

    # Keep the TXT records until the CA has finished validating: Let's Encrypt
    # checks asynchronously from several vantage points, so deleting them right
    # after answer_challenge() causes "secondary validation" NXDOMAIN failures.
    # (An empty txt_records list makes this a no-op.)
    with _managed_txt_records(cf, zone_id, txt_records):
        if pending:
            log.info("[%s] Waiting %ds for DNS propagation", domain, CF_PROPAGATION)
            time.sleep(CF_PROPAGATION)
            for challb, _ in pending:
                acme.answer_challenge(challb, challb.response(jwk))
            log.info("[%s] Challenges answered", domain)

        log.info("[%s] Finalizing order", domain)
        order = acme.poll_and_finalize(order)
    _save_cert_files(domain, order.fullchain_pem)
    log.info("[%s] Certificate saved to %s", domain, _cert_dir(domain))
    return True


# ---------------------------------------------------------------------------
# S3 upload
# ---------------------------------------------------------------------------

def upload_to_s3(domain: str) -> None:
    cert_dir = _cert_dir(domain)
    now_dt = datetime.now(timezone.utc)
    now_iso = now_dt.isoformat()
    metadata = {"last-refreshed": now_iso}

    for filename in ("fullchain.pem", "privkey.pem", "cert.pem", "chain.pem"):
        filepath = cert_dir / filename
        if not filepath.exists():
            log.warning("[%s] Missing file, skipping upload: %s", domain, filepath)
            continue
        key = f"certs/{domain}/{filename}"
        s3.put_object(
            Bucket=S3_BUCKET,
            Key=key,
            Body=filepath.read_bytes(),
            Metadata=metadata,
        )
        log.info(
            "[%s] Uploaded s3://%s/%s  (last-refreshed: %s)",
            domain, S3_BUCKET, key, now_iso,
        )

    # Write a local sidecar so the metrics exporter can read last-refreshed
    # without making S3 API calls on every Prometheus scrape.
    meta_path = cert_dir / ".meta.json"
    meta_path.write_text(
        json.dumps({"last_refreshed_ts": now_dt.timestamp(), "last_refreshed_iso": now_iso})
    )
    log.debug("[%s] Wrote %s", domain, meta_path)


# ---------------------------------------------------------------------------
# Daemon loop
# ---------------------------------------------------------------------------

def run_cycle(
    acme: client.ClientV2,
    jwk: josepy.JWKEC,
    cf: cloudflare.Cloudflare,
) -> None:
    for domain in DOMAINS:
        try:
            obtained = issue_or_renew(domain, acme, jwk, cf)
            if obtained:
                upload_to_s3(domain)
        except Exception:
            log.exception("[%s] Error during cycle — continuing with next domain", domain)


def main() -> None:
    log.info(
        "cert-manager starting  domains=%s  bucket=%s  interval=%ds",
        DOMAINS, S3_BUCKET, RENEWAL_INTERVAL,
    )
    start_metrics_server()
    acme, jwk = _build_acme_client()
    cf = cloudflare.Cloudflare(api_token=CF_TOKEN)

    while True:
        run_cycle(acme, jwk, cf)
        log.info("Cycle complete — sleeping %ds until next check", RENEWAL_INTERVAL)
        time.sleep(RENEWAL_INTERVAL)


if __name__ == "__main__":
    main()
