"""
Yashigani PKI — CA driver base class and shared types.

All CA drivers (internal and BYO) implement CADriver.

Last updated: 2026-05-09T00:00:00+01:00
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional


class DriverError(RuntimeError):
    """Raised when a CA driver operation fails.  Never fall back silently."""


@dataclass
class CertChainInfo:
    """Parsed metadata for the current cert chain.

    Contains the backoffice-facing summary of the leaf cert plus chain details.
    Private key material is NEVER included here.
    """
    # Leaf cert details
    subject_cn: str
    issuer_cn: str
    serial_hex: str
    not_before: str          # ISO-8601 UTC
    not_after: str           # ISO-8601 UTC
    fingerprint_sha256: str  # lowercase hex, no colons
    # SANs
    dns_sans: list[str] = field(default_factory=list)
    uri_sans: list[str] = field(default_factory=list)
    ip_sans: list[str] = field(default_factory=list)
    # Chain depth
    chain_depth: int = 1
    # CA mode that produced this cert
    ca_mode: str = "internal"
    # Is the cert within its renewal window?
    needs_renewal: bool = False
    # ISO-8601 UTC of last rotation (None = unknown)
    last_rotated_at: Optional[str] = None


@dataclass
class RotateResult:
    """Result of a cert rotation operation."""
    success: bool
    new_chain: Optional[CertChainInfo] = None
    error: Optional[str] = None


class CADriver(ABC):
    """Abstract base — CA driver contract."""

    @abstractmethod
    def get_chain_info(self, service_name: str) -> CertChainInfo:
        """Return parsed cert-chain metadata for *service_name*.

        Must NOT return private key material.
        Raises DriverError on any failure.
        """

    @abstractmethod
    def rotate(self, service_name: str) -> RotateResult:
        """Trigger cert rotation for *service_name*.

        For InternalCADriver: re-runs rotate_leaves for that service.
        For ByoCADriver: generates a fresh CSR, submits to signing endpoint,
        receives signed cert, validates chain back to BYO CA, writes leaf.

        Never silently falls back.  Raises DriverError on unrecoverable failure.
        """

    @abstractmethod
    def get_pem_bundle(self, service_name: str) -> bytes:
        """Return the PEM bundle for *service_name*: leaf + intermediate(s).

        The private key is NEVER included.
        Raises DriverError if the bundle cannot be produced.
        """
