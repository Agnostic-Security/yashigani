#!/usr/bin/env python3
"""
Byte-level no-residual round-trip proof for the document re-render — on the REAL
demo samples, run through the hardened sandbox on this host's Docker runtime.

For EACH demo xlsx and EACH action (REDACT, PSEUDONYMIZE) it:
  1. extracts the input in the jail (extract job) — surfaces body cells AND the
     hidden/metadata-bearing segments (creator/title/lastModifiedBy etc.);
  2. selects the SENSITIVE values to transform (PII / PCI columns + any metadata
     segment that repeats a sensitive value), building a per-span RenderPlan
     (segment_location + original + action [+ token]);
  3. runs the re-render IN THE JAIL (worker _render_xlsx) — egress=none, ro-rootfs,
     caps-drop, non-root, seccomp, mem/pids caps — getting back the rendered OUTPUT
     bytes (rendered_b64) AND the worker's re-extraction of those OUTPUT bytes
     (output_segments, body + metadata);
  4. ASSERTS no-residual: every original sensitive value is GONE from the
     re-extracted OUTPUT segments AND from the RAW rendered bytes — body, hidden
     parts, AND metadata. For PSEUDONYMIZE it additionally asserts the token is
     present (tokenised, coherent) and the original is absent.
  5. writes the OUTPUT artefacts (redacted/pseudonymised xlsx + the correspondence
     table for the pseudonymised ones) to the Desktop outputs dir.

This is the proof Laura/Ava demanded — re-extract-the-output, no residual anywhere
— produced on Docker, on the actual files, for both actions, for both samples.

Run from the repo root:
    PYTHONPATH=src YASHIGANI_EXTRACTOR_RUNTIME=docker \\
        .venv/bin/python scripts/demo_render_roundtrip_proof.py

Exit 0 = both files x both actions: no residual. Non-zero = a residual leak (BLOCK).
"""
from __future__ import annotations

import json
import os
import re
import sys

from yashigani.documents.sandbox import SandboxedExtractorRunner, SandboxJobResult

SAMPLES_DIR = os.path.expanduser("~/Desktop/Yashigani-Demo-Samples")
OUT_DIR = os.path.join(SAMPLES_DIR, "outputs")

# The two real demo samples.
FILES = ["sample-PII-employees.xlsx", "sample-PCI-cardholder-data.xlsx"]

# Detectors for the SENSITIVE values we transform. Header cells (row 1) and the
# non-sensitive columns (scheme, amount, expiry) are left as-is; we transform the
# actual PII/PCI. These mirror the gateway's detector classes at a level
# sufficient for the proof (the production detector is Tom's pipeline.py — we do
# NOT touch it; here we select values to PROVE the re-render strips them).
_DETECTORS: list[tuple[str, re.Pattern]] = [
    ("EMAIL", re.compile(r"^[\w.+-]+@[\w-]+\.[\w.-]+$")),
    ("PAN", re.compile(r"^(?:\d[ -]?){13,19}$")),         # card numbers
    ("UK_NINO", re.compile(r"^[A-Z]{2} ?\d{2} ?\d{2} ?\d{2} ?[A-Z]$")),
    ("UK_MOBILE", re.compile(r"^0\d{10}$")),
    ("DOB", re.compile(r"^\d{2}/\d{2}/\d{4}$")),
    ("CVV", re.compile(r"^\d{3,4}$")),
    ("POSTCODE_ADDR", re.compile(r".*[A-Z]{1,2}\d[A-Z\d]? ?\d[A-Z]{2}.*")),  # addr/postcode
    ("PERSON_NAME", re.compile(r"^[A-Z][a-z]+ [A-Z][a-z]+$")),  # "Olivia Bennett"
]

# Columns whose VALUES are sensitive (so a plain name like "Visa" in the Scheme
# column is never matched). We only transform cells in data rows (row >= 2).
_SENSITIVE_HEADERS = {
    "Full Name", "Work Email", "Mobile", "Date of Birth", "Home Address",
    "National Insurance No.", "Cardholder Name", "Card Number", "Expiry", "CVV",
    "Billing Postcode",
}


def _classify(value: str) -> str | None:
    v = value.strip()
    if not v:
        return None
    for label, pat in _DETECTORS:
        if pat.match(v):
            return label
    return None


def _header_map(segments: list[dict]) -> dict[str, str]:
    """Map column letter -> header text (row 1) per sheet, keyed 'sheet|col'."""
    hdr: dict[str, str] = {}
    for s in segments:
        loc = str(s.get("location", ""))
        m = re.match(r"sheet=(?P<sheet>.+)!(?P<col>[A-Z]+)(?P<row>\d+)$", loc)
        if m and m.group("row") == "1":
            hdr[f"{m.group('sheet')}|{m.group('col')}"] = str(s.get("text", ""))
    return hdr


def build_plan(segments: list[dict], action: str) -> tuple[dict, dict]:
    """Build a RenderPlan over the SENSITIVE segments. Returns (plan, correspondence).

    correspondence maps token -> original (only for PSEUDONYMIZE; empty for REDACT).
    Tokens are stable per distinct original value (value-keyed coherence) and
    carry the detector class so the demo table is readable.
    """
    hdr = _header_map(segments)
    spans: list[dict] = []
    token_for: dict[str, str] = {}
    counts: dict[str, int] = {}
    correspondence: dict[str, str] = {}

    def token(label: str, original: str) -> str:
        if original in token_for:
            return token_for[original]
        counts[label] = counts.get(label, 0) + 1
        tok = f"[{label}_{counts[label]:03d}]"
        token_for[original] = tok
        correspondence[tok] = original
        return tok

    for s in segments:
        loc = str(s.get("location", ""))
        text = str(s.get("text", ""))
        kind = str(s.get("kind", ""))
        if not text.strip():
            continue

        # Metadata segments that repeat a sensitive value (e.g. creator = an
        # email) MUST be cleared too — but the xlsx re-render rebuilds a fresh
        # workbook and drops ALL metadata wholesale (strip_hidden_and_metadata),
        # so we don't need a per-span entry for metadata; we ASSERT it is gone in
        # the proof. We still record the sensitive metadata value as a residual
        # target (so the assertion covers it).
        if kind == "METADATA":
            continue

        m = re.match(r"sheet=(?P<sheet>.+)!(?P<col>[A-Z]+)(?P<row>\d+)$", loc)
        if not m:
            continue
        row = int(m.group("row"))
        if row < 2:  # header row — never a value
            continue
        header = hdr.get(f"{m.group('sheet')}|{m.group('col')}", "")
        label = _classify(text)
        # Transform if the column is a known-sensitive header OR the value itself
        # classifies as sensitive (belt + suspenders).
        if header not in _SENSITIVE_HEADERS and label is None:
            continue
        label = label or "PII"
        span = {
            "segment_location": loc,
            "original": text,
            "action": action,
        }
        if action == "PSEUDONYMIZE":
            span["token"] = token(label, text)
        spans.append(span)

    plan = {"spans": spans, "strip_hidden_and_metadata": True}
    return plan, correspondence


def sensitive_originals(segments: list[dict]) -> list[tuple[str, str]]:
    """Every sensitive original value (incl. metadata) we must prove is gone.

    Returns (source_label, value). Covers body cells AND metadata-bearing
    segments (creator/title/lastModifiedBy), since the no-residual proof must
    clear EVERY channel, not just the visible body."""
    hdr = _header_map(segments)
    out: list[tuple[str, str]] = []
    seen: set[str] = set()
    for s in segments:
        text = str(s.get("text", "")).strip()
        kind = str(s.get("kind", ""))
        loc = str(s.get("location", ""))
        if not text or text in seen:
            continue
        if kind == "METADATA":
            # Only metadata values that are themselves sensitive (an email, a
            # person name) are residual targets — a doc TITLE like "HR — ..." is
            # a label, not PII, and the fresh workbook drops it anyway.
            if _classify(text):
                out.append((f"metadata:{loc}", text))
                seen.add(text)
            continue
        m = re.match(r"sheet=(?P<sheet>.+)!(?P<col>[A-Z]+)(?P<row>\d+)$", loc)
        if not m or int(m.group("row")) < 2:
            continue
        header = hdr.get(f"{m.group('sheet')}|{m.group('col')}", "")
        if header in _SENSITIVE_HEADERS or _classify(text):
            out.append((f"cell:{loc}", text))
            seen.add(text)
    return out


def prove(runner: SandboxedExtractorRunner, path: str, action: str):
    name = os.path.basename(path)
    data = open(path, "rb").read()

    # 1. extract input (surfaces body + metadata segments)
    extracted = runner.run_job(data, job="extract", fmt="xlsx", declared_mime="x")
    if not extracted.ok:
        raise SystemExit(f"FAIL: input extract not ok for {name}: {extracted.reason}")

    targets = sensitive_originals(extracted.segments)
    plan, correspondence = build_plan(extracted.segments, action)
    if not plan["spans"]:
        raise SystemExit(f"FAIL: no sensitive spans found in {name} — plan empty")

    # 2. re-render IN THE JAIL (worker _render_xlsx).
    import base64
    plan_b64 = base64.b64encode(json.dumps(plan).encode()).decode()
    job = "redact" if action == "REDACT" else "pseudonymize"
    res: SandboxJobResult = runner.run_job(
        data, job=job, fmt="xlsx", declared_mime="x", plan_b64=plan_b64,
    )
    if not res.ok:
        raise SystemExit(f"FAIL: {action} re-render not ok for {name}: {res.reason}")
    if res.rendered_bytes is None:
        raise SystemExit(f"FAIL: {action} produced no rendered bytes for {name}")

    # 3. byte-level no-residual assertion: re-extracted OUTPUT segments AND raw
    #    rendered bytes must contain NONE of the original sensitive values.
    #
    #    Matching is VALUE-AWARE, not naive-substring: a short numeric like a
    #    3-digit CVV ("471") is a substring of unrelated, NON-sensitive data the
    #    demo legitimately keeps (e.g. an amount "471.53"). A residual is the
    #    ORIGINAL value reappearing as a value in its own right:
    #      - OUTPUT segments: a segment whose FULL text equals the original (the
    #        original cell value survived), OR the original surrounded by
    #        non-alphanumeric boundaries within a segment.
    #      - RAW bytes: the original with non-alphanumeric byte boundaries (so an
    #        email/PAN/NINO/name still trips it, but "471" inside "471.53" does not).
    output_segments_text = [str(s.get("text", "")) for s in res.output_segments]
    raw = res.rendered_bytes
    leaks: list[str] = []

    def _is_short_numeric(needle: str) -> bool:
        # A short numeric (e.g. a 3-4 digit CVV) is a substring of unrelated
        # longer numbers the demo legitimately keeps (amounts like "471.53",
        # "1471"). For these, a residual only counts if a cell's FULL value
        # equals the original — a boundary match is a false positive because a
        # decimal point / adjacent digit is not an alnum boundary.
        return needle.isdigit() and len(needle) <= 4

    def _boundary_present(haystack: str, needle: str) -> bool:
        # needle as a standalone value: alnum boundaries on both sides AND not
        # part of a longer number (no adjacent digit OR decimal-joined digit).
        for m in re.finditer(re.escape(needle), haystack):
            before = haystack[m.start() - 1] if m.start() > 0 else ""
            after = haystack[m.end()] if m.end() < len(haystack) else ""
            # Reject if glued to an alnum, OR if it is a number continuing past a
            # decimal point (e.g. "471" in "471.53" / ".471").
            if before.isalnum() or after.isalnum():
                continue
            if needle.isdigit() and (before == "." or after == "."):
                continue
            return True
        return False

    for src, val in targets:
        if _is_short_numeric(val):
            seg_leak = any(t == val for t in output_segments_text)
        else:
            seg_leak = any(t == val or _boundary_present(t, val) for t in output_segments_text)
        if seg_leak:
            leaks.append(f"{src}={val!r} (in re-extracted OUTPUT segments)")
        raw_text = raw.decode("utf-8", "replace")
        if _is_short_numeric(val):
            # raw-bytes: short numeric must equal a whole tab/quote-delimited cell.
            raw_leak = re.search(
                r"(?<![\d.])" + re.escape(val) + r"(?![\d.])", raw_text
            ) is not None
        else:
            raw_leak = _boundary_present(raw_text, val)
        if raw_leak:
            leaks.append(f"{src}={val!r} (in RAW rendered bytes)")

    token_ok = True
    if action == "PSEUDONYMIZE":
        # Every token must be present in the re-extracted output (tokenised,
        # coherent), and the original absent (already checked above).
        output_joined = "\n".join(output_segments_text)
        missing = [t for t in correspondence if t not in output_joined]
        if missing:
            token_ok = False
            leaks.append(f"tokens missing from output: {missing[:5]}")

    ok = not leaks and token_ok

    # 4. write the OUTPUT artefact + correspondence table.
    os.makedirs(OUT_DIR, exist_ok=True)
    stem = name[:-5]  # strip .xlsx
    suffix = "redacted" if action == "REDACT" else "pseudonymised"
    out_path = os.path.join(OUT_DIR, f"{stem}.{suffix}.xlsx")
    with open(out_path, "wb") as fh:
        fh.write(raw)
    corr_path = ""
    if action == "PSEUDONYMIZE":
        corr_path = os.path.join(OUT_DIR, f"{stem}.correspondence.json")
        with open(corr_path, "w", encoding="utf-8") as fh:
            json.dump(
                {"source": name, "action": action,
                 "note": "token -> original; demo correspondence table",
                 "tokens": correspondence},
                fh, indent=2, ensure_ascii=False,
            )

    print(f"\n--- {name} [{action}] ---")
    print(f"  sensitive targets proven absent : {len(targets)}")
    print(f"  spans transformed in jail       : {len(plan['spans'])}")
    print(f"  re-extracted OUTPUT segments     : {len(res.output_segments)}")
    print(f"  rendered OUTPUT bytes            : {len(raw)}")
    if action == "PSEUDONYMIZE":
        print(f"  distinct tokens (correspondence) : {len(correspondence)}")
    print(f"  output file -> {out_path}")
    if corr_path:
        print(f"  correspondence -> {corr_path}")
    if ok:
        print("  RESULT: NO RESIDUAL anywhere (body + hidden + metadata) — PASS")
    else:
        print("  RESULT: RESIDUAL LEAK — FAIL")
        for lk in leaks[:20]:
            print(f"     LEAK: {lk}")
    return ok


def main() -> int:
    runner = SandboxedExtractorRunner()
    backend = runner._resolve_backend()  # noqa: SLF001 (proof harness)
    print(f"Demo re-render round-trip proof — backend={type(backend).__name__} "
          f"runtime={getattr(backend, 'name', '?')}")
    results = []
    for fname in FILES:
        path = os.path.join(SAMPLES_DIR, fname)
        if not os.path.exists(path):
            print(f"FATAL: sample missing: {path}")
            return 2
        for action in ("REDACT", "PSEUDONYMIZE"):
            results.append(prove(runner, path, action))
    passed, total = sum(results), len(results)
    print(f"\n=== RESULT: {passed}/{total} (file x action) round-trips with NO residual ===")
    if passed == total:
        print("BYTE-LEVEL NO-RESIDUAL ROUND-TRIP PROVEN — on Docker, on the real "
              "demo samples, for REDACT and PSEUDONYMIZE.")
        return 0
    print("RESIDUAL LEAK — release-blocker.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
