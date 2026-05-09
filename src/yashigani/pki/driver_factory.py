"""
Yashigani PKI — CA driver factory.

Reads YASHIGANI_PKI_CA_MODE (default: internal) and returns the matching driver.

  internal — InternalCADriver (two-tier Yashigani CA, default, current behaviour)
  byo      — ByoCADriver (customer-supplied signing endpoint)

Fail-closed: unknown mode raises RuntimeError at startup; never falls back silently.

Last updated: 2026-05-09T00:00:00+01:00
"""
from __future__ import annotations

import os

from yashigani.pki.drivers.base import CADriver


def get_ca_driver() -> CADriver:
    """Return the configured CA driver.

    Called once per request in the PKI admin routes — cheap because both
    drivers are stateless (they read paths from env at construction time,
    not at call time).
    """
    mode = os.getenv("YASHIGANI_PKI_CA_MODE", "internal").strip().lower()

    if mode == "internal":
        from yashigani.pki.drivers.internal_ca import InternalCADriver  # noqa: PLC0415
        return InternalCADriver()

    if mode == "byo":
        from yashigani.pki.drivers.byo_ca import ByoCADriver  # noqa: PLC0415
        return ByoCADriver()

    raise RuntimeError(
        f"Unknown YASHIGANI_PKI_CA_MODE={mode!r}. "
        "Allowed values: internal | byo. "
        "Check your .env file or Helm values."
    )
