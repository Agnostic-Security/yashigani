"""
Yashigani Audit — Log writer with volume sink and multi-SIEM forwarding.
Volume sink is always active and cannot be disabled.
SIEM forwarding is optional and failure-tolerant.

v0.9.0 (F-12): Every event carries a ``prev_event_hash`` field — SHA-384 of
the preceding event's canonical JSON, forming a tamper-evident hash chain.
The first event of each calendar day anchors with SHA-384 of the date string
"YYYY-MM-DD".  The chain can be verified offline with scripts/audit_verify.py.

Last updated: 2026-05-03
"""
from __future__ import annotations

import dataclasses
import hashlib
import ipaddress
import json
import logging
import os
import socket
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

from yashigani.audit.config import AuditConfig
from yashigani.audit.masking import CredentialMasker
from yashigani.audit.schema import AuditEvent, SiemDeliveryFailedEvent
from yashigani.audit.scope import MaskingScopeConfig

logger = logging.getLogger(__name__)

_RETRY_DELAYS = [1.0, 5.0, 25.0]  # seconds


# ---------------------------------------------------------------------------
# Hash-chain helpers (F-12)
# ---------------------------------------------------------------------------

def _canonical_json(event_dict: dict) -> str:
    """
    Produce a deterministic, compact JSON string for hashing.

    The ``prev_event_hash`` field is excluded from the canonical form so that
    the hash of event N does not depend on event N's own chain link — only on
    the content of the preceding event.
    """
    d = {k: v for k, v in event_dict.items() if k != "prev_event_hash"}
    return json.dumps(d, sort_keys=True, separators=(",", ":"), default=str)


def _sha384_hex(text: str) -> str:
    return hashlib.sha384(text.encode("utf-8")).hexdigest()


def _day_anchor(date_str: str) -> str:
    """SHA-384 of a 'YYYY-MM-DD' string — used as the chain anchor for the first event of each day."""
    return _sha384_hex(date_str)


class AuditWriteError(Exception):
    """Raised when the volume sink write fails. Callers must abort the operation."""


# ---------------------------------------------------------------------------
# SIEM target URL validation (YSG-RISK-007.C #3ax, CWE-918)
# ---------------------------------------------------------------------------

def validate_siem_url(url: str) -> str:
    """Validate a SIEM target URL to prevent SSRF (CWE-918, YSG-RISK-007.C).

    Rules:
    1. Scheme MUST be ``https``.
    2. Unless YASHIGANI_TEST_MODE=1, the host must not resolve to an RFC 1918 /
       loopback / link-local / multicast address.
    3. Hosts in YASHIGANI_SIEM_HOSTNAMES (comma-separated) bypass the DNS
       resolution check (explicit allowlist for known SIEM SaaS endpoints).
    4. DNS lookup is skipped when YASHIGANI_TEST_MODE=1 but https is still
       enforced.

    Raises ``ValueError`` on any violation.  Callers in the Pydantic model
    surface this as HTTP 422; callers in the writer surface it as a delivery
    error so the event is dropped with a logged SIEM failure rather than
    silently forwarded to an unsafe URL.
    """
    parsed = urlparse(url)
    scheme = (parsed.scheme or "").lower()
    host = (parsed.hostname or "").lower()

    if scheme != "https":
        raise ValueError(
            f"SIEM target URL must use https:// — got scheme {scheme!r} "
            "(CWE-918, YSG-RISK-007.C)"
        )

    if not host:
        raise ValueError("SIEM target URL must contain a hostname.")

    # Explicit allowlist bypasses DNS resolution.
    raw_allowlist = os.getenv("YASHIGANI_SIEM_HOSTNAMES", "").strip()
    allowed = {h.strip().lower() for h in raw_allowlist.split(",") if h.strip()}
    if host in allowed:
        return url

    # Skip DNS / IP-range gate in test mode (https is still required).
    if os.getenv("YASHIGANI_TEST_MODE") == "1":
        return url

    # Resolve hostname and reject private / loopback / link-local ranges.
    try:
        ip = ipaddress.ip_address(socket.gethostbyname(host))
    except OSError:
        # DNS failure — fail closed.
        raise ValueError(
            f"SIEM target URL hostname {host!r} could not be resolved — "
            "DNS failure treated as unsafe (CWE-918)."
        )

    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast:
        raise ValueError(
            f"SIEM target URL hostname {host!r} resolves to {ip!s} "
            "(private / loopback / link-local / multicast) — "
            "SSRF to internal infrastructure blocked (CWE-918)."
        )

    return url


# ---------------------------------------------------------------------------
# SIEM target
# ---------------------------------------------------------------------------

@dataclass
class SiemTarget:
    name: str
    target_type: str       # webhook | splunk_hec | elastic_opensearch
    url: str
    auth_header: str = "Authorization"
    auth_value: str = ""   # secret — never logged; empty for mesh_mtls targets
    enabled: bool = True
    mesh_mtls: bool = False  # when True, authenticate by presenting THIS service's
                             # internal-mesh leaf via pki.client_ssl_context()
                             # (Pattern A) instead of a shared header secret — for
                             # internal SIEMs that trust the Yashigani mesh CA, e.g.
                             # the bundled Wazuh indexer (serves a DNS:wazuh-indexer
                             # leaf, trusts ca_root+ca_intermediate). No shared secret.


def siem_targets_from_env(env_var: str = "YASHIGANI_SIEM_TARGETS") -> list["SiemTarget"]:
    """Load audit SIEM-forwarding targets from deployment config at startup.

    The target set is owned by the deployment layer (install.sh / compose env),
    NOT the running app's admin state — so forwarding survives restarts and is
    populated when a SIEM (e.g. the bundled Wazuh) is selected at install time.

    ``env_var`` holds a JSON array; each entry:
        {"name","target_type","url","auth_value", ["auth_header"], ["enabled"]}
    Unset / empty / malformed → ``[]`` (forward to none). Never raises — a bad
    config must not stop the gateway from starting (audit still writes locally).
    """
    raw = os.getenv(env_var, "").strip()
    if not raw:
        return []
    try:
        data = json.loads(raw)
    except (ValueError, TypeError):
        logger.warning("%s is not valid JSON — no SIEM targets loaded", env_var)
        return []
    if not isinstance(data, list):
        logger.warning("%s must be a JSON array — no SIEM targets loaded", env_var)
        return []
    targets: list[SiemTarget] = []
    for i, entry in enumerate(data):
        if not isinstance(entry, dict):
            logger.warning("%s[%d] is not an object — skipped", env_var, i)
            continue
        try:
            targets.append(
                SiemTarget(
                    name=entry["name"],
                    target_type=entry["target_type"],
                    url=entry["url"],
                    auth_header=entry.get("auth_header", "Authorization"),
                    # auth_value optional: mesh_mtls (cert-identity) targets and
                    # unauthenticated webhooks carry no shared secret.
                    auth_value=entry.get("auth_value", ""),
                    enabled=bool(entry.get("enabled", True)),
                    mesh_mtls=bool(entry.get("mesh_mtls", False)),
                )
            )
        except (KeyError, TypeError) as exc:
            logger.warning("%s[%d] missing/invalid field (%s) — skipped", env_var, i, exc)
    logger.info("Loaded %d SIEM target(s) from %s", len(targets), env_var)
    return targets


# ---------------------------------------------------------------------------
# Writer
# ---------------------------------------------------------------------------

class AuditLogWriter:
    """
    Thread-safe audit log writer.
    Primary: newline-delimited JSON to a mounted volume file.
    Secondary: optional SIEM forwarding (webhook / Splunk HEC / Elastic).

    v0.9.0 (F-12): maintains an in-memory hash chain. Each event's
    ``prev_event_hash`` is set to SHA-384 of the preceding event's canonical
    JSON (or the day-anchor for the first event of each calendar day).
    """

    def __init__(
        self,
        config: AuditConfig,
        masking_scope: Optional[MaskingScopeConfig] = None,
        siem_targets: Optional[list[SiemTarget]] = None,
    ) -> None:
        self._config = config
        self._masking_scope = masking_scope or MaskingScopeConfig()
        self._siem_targets: list[SiemTarget] = siem_targets or []
        self._masker = CredentialMasker()
        self._lock = threading.Lock()
        self._log_path = Path(config.log_path)
        self._log_path.parent.mkdir(parents=True, exist_ok=True)
        self._file = self._open_log_file()
        # Hash-chain state (protected by self._lock)
        self._chain_last_hash: Optional[str] = None   # hash of the most recent event
        self._chain_current_day: Optional[str] = None  # "YYYY-MM-DD" of last event
        # v2.25.2 — optional DB audit sink (PostgresSink). Wired via
        # attach_db_sink() from the service lifespan AFTER the asyncpg pool is
        # open.  The file sink above is and remains the canonical durability
        # anchor; the DB sink is a fire-and-forget MIRROR whose failure modes
        # (queue full, DB down, pool not ready) are fully isolated from the
        # request path and from the file write.  Typed loosely to avoid an
        # import cycle (sinks.py imports nothing from writer at module load).
        self._db_sink = None  # type: ignore[var-annotated]

    # -- Public API ----------------------------------------------------------

    def write(
        self,
        event: AuditEvent,
        agent_id: Optional[str] = None,
        user_handle: Optional[str] = None,
        component: Optional[str] = None,
    ) -> None:
        """
        Write an audit event to the volume sink (always) and forward to
        enabled SIEM targets (best-effort). Raises AuditWriteError if the
        volume write fails — the caller MUST abort their operation.

        The ``prev_event_hash`` field is injected immediately before
        serialisation so that the hash chain is always consistent on disk.
        """
        if self._masking_scope.should_mask(event, agent_id, user_handle, component):
            event = self._masker.mask_event(event)
            object.__setattr__(event, "masking_applied", True) if dataclasses.is_dataclass(event) else setattr(event, "masking_applied", True)
        else:
            # Masking did NOT run (e.g. AUDIT_INTEGRITY_EVENTS exemption).
            # Record the truth so an auditor reading the persisted record is not
            # misled by the dataclass default of masking_applied=True.
            # YCS-20260529-v250-W6-01 / FIX-01 (honesty — Lu GRC gate).
            object.__setattr__(event, "masking_applied", False) if dataclasses.is_dataclass(event) else setattr(event, "masking_applied", False)

        with self._lock:
            # Compute and inject prev_event_hash before serialisation
            event_dict = event.to_dict()
            today = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d")
            if self._chain_current_day != today or self._chain_last_hash is None:
                # First event of the day (or first ever): anchor with day hash
                prev_hash = _day_anchor(today)
                self._chain_current_day = today
            else:
                prev_hash = self._chain_last_hash
            event_dict["prev_event_hash"] = prev_hash

            # Update in-memory chain pointer with this event's canonical hash
            self._chain_last_hash = _sha384_hex(_canonical_json(event_dict))

            record = json.dumps(event_dict, default=str)
            try:
                self._rotate_if_needed()
                self._file.write(record + "\n")
                self._file.flush()
            except OSError as exc:
                raise AuditWriteError(
                    f"Audit volume write failed: {exc}. "
                    "The triggering operation must be aborted."
                ) from exc

        # v2.25.2 — DB sink mirror (fire-and-forget, fully isolated).
        # Runs AFTER the canonical file write has succeeded and OUTSIDE the
        # file lock.  event_dict here is the masked, hash-chained dict that was
        # just persisted to file — masked tokens only, no raw PII (masking is
        # applied above before serialisation; client IPs are stored as
        # client_ip_hash by the event schema).  enqueue_nowait never blocks and
        # never raises, so a full queue / down DB cannot affect this request.
        if self._db_sink is not None:
            self._mirror_to_db_sink(event_dict)

        # SIEM forwarding is fire-and-forget (never blocks volume write)
        if self._siem_targets:
            threading.Thread(
                target=self._forward_to_siem,
                args=(event, record),
                daemon=True,
            ).start()

    def _write_raw(self, line: str) -> None:
        """
        Write a raw newline-terminated string to the volume sink.
        Used by FileSink (multi-sink writer) to delegate file I/O here
        so rotation, locking, and path management remain centralised.
        Raises AuditWriteError if the write fails.
        """
        with self._lock:
            try:
                self._rotate_if_needed()
                self._file.write(line + "\n")
                self._file.flush()
            except OSError as exc:
                raise AuditWriteError(
                    f"Audit volume write failed (_write_raw): {exc}. "
                    "The triggering operation must be aborted."
                ) from exc

    def close(self) -> None:
        with self._lock:
            try:
                self._file.close()
            except OSError:
                pass

    def add_siem_target(self, target: SiemTarget) -> None:
        self._siem_targets.append(target)

    # -- DB sink (PostgresSink) — v2.25.2 ------------------------------------

    def attach_db_sink(self, db_sink) -> None:
        """Attach an already-started PostgresSink as a fire-and-forget mirror.

        Called from the service lifespan after the asyncpg pool is open and
        db_sink.start() has been invoked.  Idempotent-safe: replacing an
        existing sink simply swaps the reference.

        The DB sink is a SECONDARY mirror.  The file sink remains the canonical
        durability anchor; nothing about the file write path depends on this.
        """
        self._db_sink = db_sink

    def _mirror_to_db_sink(self, event_dict: dict) -> None:
        """Fire-and-forget mirror of a masked event_dict to the DB sink.

        Invoked AFTER the canonical file write succeeds, OUTSIDE the file lock.
        Fully isolated: any failure (no sink, queue full, enqueue error) is
        swallowed so the request and the file write are never affected.  The
        DB sink itself only does a non-blocking put_nowait — no DB I/O happens
        on this thread; the background drain loop performs the INSERTs.
        """
        sink = self._db_sink
        if sink is None:
            return
        try:
            # enqueue_nowait is sync, loop-agnostic, and never raises.
            sink.enqueue_nowait(event_dict)
        except Exception as exc:  # noqa: BLE001 — defence in depth; must not propagate
            logger.warning("Audit DB sink mirror failed (dropped, file write intact): %s", exc)

    # -- Volume sink ---------------------------------------------------------

    def _open_log_file(self):
        return open(self._log_path, "a", encoding="utf-8", buffering=1)

    def _rotate_if_needed(self) -> None:
        """Rotate log file if it exceeds max_file_size_mb. Lock must be held."""
        try:
            size_mb = self._log_path.stat().st_size / (1024 * 1024)
        except FileNotFoundError:
            return
        if size_mb < self._config.max_file_size_mb:
            return

        self._file.close()
        ts = datetime.now(tz=timezone.utc).strftime("%Y%m%d-%H%M%S")
        rotated = self._log_path.with_suffix(f".log.{ts}")
        self._log_path.rename(rotated)
        self._file = self._open_log_file()
        self._delete_old_logs()

    def _delete_old_logs(self) -> None:
        """Remove rotated logs older than retention_days."""
        cutoff = time.time() - (self._config.retention_days * 86400)
        parent = self._log_path.parent
        for p in parent.glob("audit.log.*"):
            try:
                if p.stat().st_mtime < cutoff:
                    p.unlink()
            except OSError:
                pass

    # -- SIEM forwarding -----------------------------------------------------

    def _forward_to_siem(self, event: AuditEvent, raw_json: str) -> None:
        for target in self._siem_targets:
            if not target.enabled:
                continue
            self._send_with_retry(event, raw_json, target)

    def _send_with_retry(
        self, event: AuditEvent, raw_json: str, target: SiemTarget
    ) -> None:
        last_status: Optional[int] = None
        last_error: str = ""
        for attempt, delay in enumerate(_RETRY_DELAYS):
            try:
                self._send_to_target(raw_json, target)
                return
            except Exception as exc:
                last_error = type(exc).__name__
                last_status = getattr(exc, "status_code", None)
                if attempt < len(_RETRY_DELAYS) - 1:
                    time.sleep(delay)

        # All retries exhausted — log delivery failure to volume sink
        failure = SiemDeliveryFailedEvent(
            account_tier="system",
            siem_target_name=target.name,
            siem_target_type=target.target_type,
            failed_audit_event_id=event.audit_event_id,
            http_status=last_status,
            error=last_error,
            retry_attempted=True,
        )
        try:
            record = json.dumps(failure.to_dict(), default=str)
            with self._lock:
                self._file.write(record + "\n")
                self._file.flush()
        except OSError:
            logger.error(
                "SIEM delivery failure AND volume write failure for event %s",
                event.audit_event_id,
            )

    def _send_to_target(self, raw_json: str, target: SiemTarget) -> None:
        import urllib.request
        import urllib.error

        # Re-assert SSRF safety at send time — the URL may have been stored
        # before the validator was in place (YSG-RISK-007.C #3ax, CWE-918).
        validate_siem_url(target.url)

        body, content_type = self._format_for_target(raw_json, target)
        headers = {"Content-Type": content_type}
        # Cert-identity (mesh_mtls) targets carry no shared secret — the client
        # cert IS the credential. Only set the auth header when a value exists.
        if target.auth_value:
            headers[target.auth_header] = target.auth_value
        req = urllib.request.Request(
            url=target.url,
            data=body.encode("utf-8"),
            method="POST",
            headers=headers,
        )
        # mesh_mtls: present this service's internal-mesh leaf via the canonical
        # PKI helper (Pattern A — own leaf + ca_root anchor, TLS 1.3, peer verify
        # + hostname). The bundled Wazuh indexer trusts the Yashigani mesh CA and
        # serves a DNS:wazuh-indexer leaf, so the writer is authenticated by cert
        # identity (a low-privilege mesh leaf, NOT the wazuh admin credential).
        ctx = self._mesh_client_ctx() if target.mesh_mtls else None
        try:
            with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
                if resp.status >= 300:
                    raise RuntimeError(f"HTTP {resp.status}")
        except urllib.error.HTTPError as exc:
            exc.status_code = exc.code  # type: ignore[attr-defined]
            raise

    def _mesh_client_ctx(self):
        """Lazily build + cache this service's internal-mesh client SSLContext.

        Uses pki.ssl_context.client_ssl_context() (resolves THIS service's own
        leaf via current_service()). Cached because building it reads cert files
        and verifies the bootstrap token on every call.
        """
        ctx = getattr(self, "_mesh_ctx", None)
        if ctx is None:
            from yashigani.pki.ssl_context import client_ssl_context
            ctx = client_ssl_context()
            self._mesh_ctx = ctx
        return ctx

    @staticmethod
    def _format_for_target(raw_json: str, target: SiemTarget) -> tuple[str, str]:
        if target.target_type == "webhook":
            return raw_json, "application/json"

        event_dict = json.loads(raw_json)

        if target.target_type == "splunk_hec":
            import time as _time
            payload = json.dumps({
                "time": _time.time(),
                "event": event_dict,
                "sourcetype": "yashigani",
            })
            return payload, "application/json"

        if target.target_type == "elastic_opensearch":
            index_line = json.dumps({"index": {"_index": "yashigani-audit"}})
            ndjson = index_line + "\n" + raw_json + "\n"
            return ndjson, "application/x-ndjson"

        raise ValueError(f"Unknown SIEM target type: {target.target_type!r}")
