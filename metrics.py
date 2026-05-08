#!/usr/bin/env python3
"""
Prometheus metrics exporter for ups3rt.

Exposes three gauges per domain on GET /metrics:

  ups3rt_cert_valid{domain}
      1 if the certificate exists on disk and has not yet expired, 0 otherwise.

  ups3rt_cert_expiry_timestamp{domain}
      Unix timestamp at which the certificate expires.

  ups3rt_cert_last_refreshed_timestamp{domain}
      Unix timestamp of the last successful S3 upload, as written by
      cert_manager into DATA_DIR/certs/<domain>/.meta.json.

  ups3rt_cert_seconds_until_renewal{domain}
      Seconds remaining before the certificate enters the renewal window
      (expiry_ts - RENEW_BEFORE_DAYS*86400 - now).  Goes negative when
      renewal is overdue.

Can be run standalone or imported and started via start_metrics_server().
Configuration is read from the same env vars as cert_manager.py.
"""

import json
import logging
import os
import time
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from prometheus_client import REGISTRY, start_http_server
from prometheus_client.core import GaugeMetricFamily

log = logging.getLogger(__name__)

DATA_DIR = Path(os.environ.get("UPS3RT_DATA_DIR", "/data"))
METRICS_PORT = int(os.environ.get("UPS3RT_METRICS_PORT", "9402"))
RENEW_BEFORE_DAYS = int(os.environ.get("UPS3RT_RENEW_BEFORE_DAYS", "30"))


class CertCollector:
    """
    Custom Prometheus collector.

    Recomputes all metric values on every scrape by reading cert files and
    .meta.json from disk — no background threads, no stale in-memory state.
    """

    def collect(self):
        valid_fam = GaugeMetricFamily(
            "ups3rt_cert_valid",
            "1 if the certificate exists and has not expired, 0 otherwise",
            labels=["domain"],
        )
        expiry_fam = GaugeMetricFamily(
            "ups3rt_cert_expiry_timestamp",
            "Unix timestamp when the certificate expires",
            labels=["domain"],
        )
        refreshed_fam = GaugeMetricFamily(
            "ups3rt_cert_last_refreshed_timestamp",
            "Unix timestamp of the last successful S3 upload",
            labels=["domain"],
        )
        renewal_fam = GaugeMetricFamily(
            "ups3rt_cert_seconds_until_renewal",
            "Seconds until the certificate enters the renewal window "
            "(negative means renewal is overdue)",
            labels=["domain"],
        )

        certs_root = DATA_DIR / "certs"
        if not certs_root.exists():
            yield from (valid_fam, expiry_fam, refreshed_fam, renewal_fam)
            return

        for cert_path in sorted(certs_root.glob("*/cert.pem")):
            domain = cert_path.parent.name
            try:
                cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
            except Exception:
                log.warning("[%s] Could not parse cert.pem", domain, exc_info=True)
                valid_fam.add_metric([domain], 0.0)
                continue

            now_ts = datetime.now(timezone.utc).timestamp()
            expiry_ts = cert.not_valid_after_utc.timestamp()
            renewal_ts = expiry_ts - RENEW_BEFORE_DAYS * 86400

            valid_fam.add_metric([domain], 1.0 if expiry_ts > now_ts else 0.0)
            expiry_fam.add_metric([domain], expiry_ts)
            renewal_fam.add_metric([domain], renewal_ts - now_ts)

            meta_path = cert_path.parent / ".meta.json"
            if meta_path.exists():
                try:
                    meta = json.loads(meta_path.read_text())
                    refreshed_fam.add_metric([domain], float(meta["last_refreshed_ts"]))
                except Exception:
                    log.warning("[%s] Could not read .meta.json", domain, exc_info=True)

        yield valid_fam
        yield expiry_fam
        yield refreshed_fam
        yield renewal_fam


def start_metrics_server(port: int = METRICS_PORT) -> None:
    """Register the collector and start the HTTP server (non-blocking)."""
    REGISTRY.register(CertCollector())
    start_http_server(port)
    log.info("Metrics server listening on :%d /metrics", port)


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )
    start_metrics_server()
    log.info("Running standalone — press Ctrl+C to stop")
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        pass
