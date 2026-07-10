"""
Yashigani DB — pgcrypto encryption options (single source of truth).

v4.1 issue #144 (DB-crypto half): pgp_sym_encrypt() defaults to AES-128
(RFC 4880 algo id 7). Every encrypt call site in the codebase MUST pass
PGP_SYM_ENCRYPT_OPTIONS so data is encrypted with AES-256 (algo id 9).

pgp_sym_decrypt() reads the cipher algorithm from the PGP SKESK packet
itself, so NO decrypt-side option is needed — AES-128 rows written before
migration 0027 and AES-256 rows decrypt with the same call.

Packet layout ground truth (verified against postgres:16 pgcrypto,
2026-07-06): pgp_sym_encrypt output starts with a new-format
Symmetric-Key Encrypted Session Key packet —

    byte 0: 0xC3 (new-format packet header, tag 3)
    byte 1: body length (13 for pgcrypto's S2K mode 3)
    byte 2: version (4)
    byte 3: symmetric cipher algo id — 7=AES-128, 8=AES-192, 9=AES-256

so ``get_byte(col, 3)`` is the cheap cipher inspection predicate used by
migration 0027 and the integration tests.

This constant is interpolated into SQL as a quoted literal. It is a static
module constant, never user input — do not make it configurable.

Last updated: 2026-07-06T00:00:00+00:00
"""
from __future__ import annotations

# Options string for pgp_sym_encrypt(data, key, options).
PGP_SYM_ENCRYPT_OPTIONS = "cipher-algo=aes256"

# RFC 4880 §9.2 symmetric algorithm id for AES-256 — byte 3 of the SKESK
# packet emitted by pgp_sym_encrypt. Used by tests/migrations to assert the
# cipher actually applied to a stored value.
AES256_PGP_ALGO_ID = 9

__all__ = ["PGP_SYM_ENCRYPT_OPTIONS", "AES256_PGP_ALGO_ID"]
