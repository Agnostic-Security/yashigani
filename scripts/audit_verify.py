#!/usr/bin/env python3
"""
Yashigani Audit — Hash-chain integrity verifier (F-12).

Walks the audit log from a given start date, re-computes each event's
expected ``prev_event_hash``, and reports any breaks in the chain.

Usage
-----
    python scripts/audit_verify.py --from 2026-01-01
    python scripts/audit_verify.py --from 2026-01-01 --log-path /data/audit/audit.log
    python scripts/audit_verify.py --from 2026-01-01 --prometheus-push http://pushgw:9091

Exit codes
----------
    0  — no chain breaks detected
    1  — one or more chain breaks detected
    2  — usage / configuration error
"""
from __future__ import annotations

import argparse
import hashlib
import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger("audit_verify")


# ---------------------------------------------------------------------------
# Constants / Prometheus metric
# ---------------------------------------------------------------------------

_METRIC_NAME = "yashigani_audit_chain_breaks_total"
_DEFAULT_LOG_PATH = "/data/audit/audit.log"


def _try_expose_prometheus(breaks_total: int, push_url: Optional[str]) -> None:
    """
    Optionally push the chain-break gauge to a Prometheus Pushgateway.
    Failure is non-fatal and logged as a warning.
    """
    if push_url is None:
        return
    try:
        from prometheus_client import CollectorRegistry, Gauge, push_to_gateway
        registry = CollectorRegistry()
        g = Gauge(
            _METRIC_NAME,
            "Total number of audit log hash-chain breaks detected by audit_verify",
            registry=registry,
        )
        g.set(breaks_total)
        push_to_gateway(push_url, job="audit_verify", registry=registry)
        logger.info("Prometheus: pushed %s=%d to %s", _METRIC_NAME, breaks_total, push_url)
    except ImportError:
        logger.warning(
            "prometheus_client not installed — skipping Pushgateway export. "
            "Install with: pip install prometheus-client"
        )
    except Exception as exc:
        logger.warning("Prometheus push failed: %s", exc)


# ---------------------------------------------------------------------------
# Hash helpers (must match writer.py exactly)
# ---------------------------------------------------------------------------

def _canonical_json(event_dict: dict) -> str:
    """
    Re-produce the canonical form used by AuditLogWriter.
    Strips ``prev_event_hash`` from the dict before hashing.
    """
    d = {k: v for k, v in event_dict.items() if k != "prev_event_hash"}
    return json.dumps(d, sort_keys=True, separators=(",", ":"), default=str)


def _sha384_hex(text: str) -> str:
    return hashlib.sha384(text.encode("utf-8")).hexdigest()


def _day_anchor(date_str: str) -> str:
    """SHA-384 of a 'YYYY-MM-DD' string."""
    return _sha384_hex(date_str)


# ---------------------------------------------------------------------------
# Log file reader (handles rotation suffixes)
# ---------------------------------------------------------------------------

def _collect_log_files(log_path: Path) -> list[Path]:
    """
    Return the primary log file plus any rotated siblings (audit.log.TIMESTAMP),
    sorted oldest-first by name so events are processed in order.
    """
    parent = log_path.parent
    files = []
    if log_path.exists():
        files.append(log_path)
    rotated = sorted(parent.glob(f"{log_path.name}.*"))
    # Rotated files have a timestamp suffix — reversed so oldest is first
    all_files = rotated + files
    return all_files


def _parse_events_from_file(path: Path, from_dt: datetime) -> list[tuple[datetime, dict]]:
    """Read NDJSON from a single file, return (parsed_timestamp, event) pairs
    at or after from_dt.

    YSG-RISK-177 (Iris integration audit, LOW #5): callers used to discard
    the already-parsed ``ts`` datetime and re-sort on the RAW timestamp
    STRING instead (see main(), pre-fix). datetime.isoformat() omits the
    microsecond component entirely when it is exactly zero (e.g.
    "...T10:15:22+00:00" vs "...T10:15:22.500000+00:00"), and any future/
    legacy record with a differently-formatted timestamp (naive, "Z" suffix,
    different precision) would sort incorrectly against isoformat()'s
    "+00:00" convention under pure string comparison. Returning the parsed
    ``datetime`` here (already computed for the from_dt cutoff filter below)
    lets the caller sort on well-defined datetime comparison instead of
    format-fragile string comparison — equal-second records order
    deterministically by their real chronological value, not by which ISO
    variant happened to serialise them.
    """
    events: list[tuple[datetime, dict]] = []
    with path.open("r", encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError as exc:
                logger.warning("Skipping malformed JSON at %s:%d — %s", path, lineno, exc)
                continue
            ts_raw = event.get("timestamp", "")
            try:
                ts = datetime.fromisoformat(ts_raw)
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=timezone.utc)
            except ValueError:
                logger.warning("Skipping event with unparseable timestamp at %s:%d", path, lineno)
                continue
            if ts < from_dt:
                continue
            events.append((ts, event))
    return events


# ---------------------------------------------------------------------------
# Chain verifier
# ---------------------------------------------------------------------------

def verify_chain(events: list[dict]) -> list[dict]:
    """
    Walk the event list in order, verifying the hash chain.

    Returns a list of dicts describing each break:
        {
            "event_index":    int,   # 0-based position in the input list
            "event_id":       str,
            "timestamp":      str,
            "expected_hash":  str,
            "actual_hash":    str,
        }
    """
    breaks = []
    last_hash: Optional[str] = None
    current_day: Optional[str] = None

    for idx, event in enumerate(events):
        ts_raw = event.get("timestamp", "")
        try:
            ts = datetime.fromisoformat(ts_raw)
        except ValueError:
            ts = datetime.now(tz=timezone.utc)
        event_day = ts.strftime("%Y-%m-%d")

        # Determine expected prev_event_hash for this event
        if current_day != event_day or last_hash is None:
            expected = _day_anchor(event_day)
            current_day = event_day
        else:
            expected = last_hash

        actual = event.get("prev_event_hash", "")

        if actual != expected:
            breaks.append({
                "event_index": idx,
                "event_id": event.get("audit_event_id", "<unknown>"),
                "timestamp": ts_raw,
                "expected_hash": expected,
                "actual_hash": actual,
            })
            logger.error(
                "Chain break at event #%d (id=%s, ts=%s): "
                "expected prev_hash=%.16s…, got %.16s…",
                idx,
                event.get("audit_event_id", "<unknown>"),
                ts_raw,
                expected,
                actual if actual else "<missing>",
            )

        # Advance chain pointer: compute hash of this event's canonical form
        last_hash = _sha384_hex(_canonical_json(event))

    return breaks


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Verify Yashigani audit log hash-chain integrity.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--from",
        dest="from_date",
        required=True,
        metavar="YYYY-MM-DD",
        help="Start date (inclusive, UTC) — events before this date are skipped.",
    )
    parser.add_argument(
        "--log-path",
        default=_DEFAULT_LOG_PATH,
        metavar="PATH",
        help=f"Path to audit.log (default: {_DEFAULT_LOG_PATH}).",
    )
    parser.add_argument(
        "--prometheus-push",
        default=None,
        metavar="URL",
        help="Prometheus Pushgateway URL (optional). "
             "E.g. http://pushgateway:9091",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Emit DEBUG-level logging.",
    )
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s — %(message)s",
    )

    try:
        from_dt = datetime.fromisoformat(args.from_date).replace(tzinfo=timezone.utc)
    except ValueError:
        logger.error("Invalid --from date: %r — use YYYY-MM-DD format.", args.from_date)
        return 2

    log_path = Path(args.log_path)
    if not log_path.parent.exists():
        logger.error("Log directory does not exist: %s", log_path.parent)
        return 2

    log_files = _collect_log_files(log_path)
    if not log_files:
        logger.warning("No audit log files found at %s", log_path)
        _try_expose_prometheus(0, args.prometheus_push)
        return 0

    logger.info("Scanning %d log file(s) from %s onward...", len(log_files), args.from_date)

    timestamped_events: list[tuple[datetime, dict]] = []
    for lf in log_files:
        logger.debug("Reading %s", lf)
        timestamped_events.extend(_parse_events_from_file(lf, from_dt))

    # YSG-RISK-177 (Iris integration audit, LOW #5): sort on the PARSED
    # datetime, not the raw timestamp string — see _parse_events_from_file's
    # docstring. Stable sort (Python's sort() guarantee) preserves each
    # file's on-disk order for any exact datetime tie, which is the correct
    # tie-break (physical append order within a file is itself
    # chronological — see writer.py's cross-process lock).
    timestamped_events.sort(key=lambda pair: pair[0])
    all_events: list[dict] = [event for _ts, event in timestamped_events]

    logger.info("Loaded %d event(s) to verify.", len(all_events))

    if not all_events:
        logger.info("No events in range — nothing to verify.")
        _try_expose_prometheus(0, args.prometheus_push)
        return 0

    breaks = verify_chain(all_events)

    _try_expose_prometheus(len(breaks), args.prometheus_push)

    if breaks:
        logger.error(
            "CHAIN INTEGRITY FAILURE: %d break(s) detected across %d event(s).",
            len(breaks),
            len(all_events),
        )
        for b in breaks:
            print(
                f"  BREAK event_index={b['event_index']} "
                f"id={b['event_id']} ts={b['timestamp']}\n"
                f"    expected={b['expected_hash']}\n"
                f"    actual  ={b['actual_hash']}"
            )
        return 1

    logger.info(
        "Chain OK — %d event(s) verified, 0 breaks.", len(all_events)
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
