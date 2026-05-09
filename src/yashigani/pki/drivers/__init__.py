"""
Yashigani PKI CA driver abstraction.

Two implementations:
  InternalCADriver  — uses the built-in Yashigani two-tier CA (default).
  ByoCADriver       — submits CSRs to a customer-supplied signing endpoint
                      (step-ca / HashiCorp Vault PKI / any RFC-compliant CSR endpoint).

Selected at runtime via YASHIGANI_PKI_CA_MODE (default: internal).

Last updated: 2026-05-09T00:00:00+01:00
"""

from yashigani.pki.drivers.base import (
    CADriver,
    CertChainInfo,
    DriverError,
    RotateResult,
)
from yashigani.pki.drivers.internal_ca import InternalCADriver
from yashigani.pki.drivers.byo_ca import ByoCADriver

__all__ = [
    "CADriver",
    "CertChainInfo",
    "DriverError",
    "RotateResult",
    "InternalCADriver",
    "ByoCADriver",
]
