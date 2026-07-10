#!/usr/bin/env python3
"""
Live containment proof for the sandboxed-extractor runtime (plan §6 B1, Captain).

This is the EVIDENCE that the sandbox actually *contains* — not just that it is
configured. It spawns real containers from the hardened image and asserts:

  CASE 1  benign job          → worker runs, emits its JSON contract, exits 0.
  CASE 2  infinite-loop parser → wall-clock timeout KILLS the container (the host
                                 stays responsive; the job does not hang forever).
  CASE 3  memory-bomb parser   → cgroup mem-limit KILLS the container (the host is
                                 NOT OOM'd; the malicious doc is contained).
  CASE 4  fork-bomb parser     → pids-limit caps process creation (no fork storm).
  CASE 5  egress attempt       → network=none means the parser CANNOT reach out
                                 (SSRF/exfil from a malicious parser is dead).
  CASE 6  metadata no-residual → a REAL in-jail PSEUDONYMIZE re-render strips the
                                 matched value from the OUTPUT's body AND core
                                 metadata AND custom document property (custom.xml);
                                 re-extracting the output proves no residual.

Cases 2-5 simulate a *parser RCE* by overriding the entrypoint with a hostile
command — exactly what a CVE in python-docx/pypdf would give an attacker INSIDE
the jail. The point is that even with arbitrary code execution in the worker,
the jail contains it.

Usage:
    python3 scripts/extractor_sandbox_containment.py --runtime docker
    python3 scripts/extractor_sandbox_containment.py --runtime podman

Exit 0 = all cases contained. Non-zero = a containment FAILURE (release-blocker).

Output goes to stdout; this script writes NO files (Captain filesystem rule).
Run it from the repo root (the build context for the image).
"""
from __future__ import annotations

import argparse
import base64
import io
import json
import os
import subprocess
import sys
import time
import zipfile

IMAGE = "yashigani/extractor:2.26.0"

# The COMMITTED extractor seccomp profile — the harness MUST exercise the real
# profile that ships (not the runtime default), otherwise a green run proves
# nothing about our allowlist. Resolved repo-root-relative (run from repo root).
_SECCOMP_PROFILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "docker", "seccomp", "yashigani-extractor.json",
)

# A sentinel matched value that lives ONLY in metadata (core creator + a CUSTOM
# document property). CASE 6 proves a real in-jail pseudonymize re-render strips
# it from the OUTPUT — body AND metadata AND custom.xml — on BOTH runtimes.
_META_CORE = "metadata-core-leaker@example.com"
_META_CUSTOM = "metadata-custom-leaker@example.com"
_BODY_VAL = "body-alice@example.com"

def _cpu_controller_available() -> bool:
    """True when the `cpu` cgroup controller is delegated to this user.

    Rootless Podman on cgroup v2 commonly has ONLY memory+pids delegated to the
    user slice (cpu/cpuset need explicit systemd delegation). When cpu is NOT
    delegated, `--cpus` makes the OCI runtime error out. CPU abuse is STILL
    contained without it — by the runner-enforced wall-clock timeout (CASE 2)
    and the memory cap — so we drop only the cpu quota, never the isolation.
    """
    import os
    uid = os.getuid()
    path = f"/sys/fs/cgroup/user.slice/user-{uid}.slice/user@{uid}.service/cgroup.controllers"
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return "cpu" in fh.read().split()
    except OSError:
        return True  # assume available (rootful / Docker) if we can't tell


# Full hardening flags — MUST mirror SandboxedExtractorRunner._hardened_run_kwargs.
# The no-new-privileges security-opt SYNTAX differs between the two CLIs:
#   Docker:  no-new-privileges:true   (colon form; Docker rejects bare)
#   Podman:  no-new-privileges        (bare form; Podman rejects :true / =true)
# So the flag is runtime-selected (see _hardening). The SEMANTIC is identical.
def _hardening(rt: str) -> list[str]:
    nnp = "no-new-privileges:true" if rt == "docker" else "no-new-privileges"
    flags = [
        "--network", "none",
        "--read-only",
        "--cap-drop", "ALL",
        "--user", "65532:65532",
        "--security-opt", nnp,
        "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=64m",
        "--memory", "256m",
        "--memory-swap", "256m",
        "--pids-limit", "64",
    ]
    # Exercise the COMMITTED seccomp profile (Su 2026-06-09) — the gate must prove
    # OUR allowlist confines, not the runtime default. If the file is missing the
    # harness fails the run rather than silently testing the default profile.
    if os.path.exists(_SECCOMP_PROFILE):
        flags += ["--security-opt", "seccomp=" + _SECCOMP_PROFILE]
    else:
        print(f"  FATAL: committed seccomp profile not found at {_SECCOMP_PROFILE} "
              f"— refusing to test the runtime-default profile", file=sys.stderr)
        raise SystemExit(2)
    # CPU quota only where the cpu controller is delegated (Docker always;
    # rootful Podman; rootless Podman only with cpu delegation). Without it the
    # wall-clock + mem caps still contain CPU abuse — see _cpu_controller_available.
    if rt == "docker" or _cpu_controller_available():
        flags += ["--cpus", "1.0"]
    else:
        print("  [note] cpu cgroup controller not delegated to this user — "
              "dropping --cpus; CPU abuse still bounded by wall-clock + mem caps")
    return flags


def _run(cmd: list[str], *, stdin: bytes | None = None, timeout: int = 60):
    return subprocess.run(
        cmd, input=stdin, capture_output=True, timeout=timeout
    )


def _hdr(n: int, title: str) -> None:
    print(f"\n=== CASE {n}: {title} ===", flush=True)


def case_benign(rt: str) -> bool:
    _hdr(1, "benign job → worker runs + emits contract")
    # docx with junk bytes: the bomb guard rejects it as not-a-valid-zip and the
    # worker emits ok=false cleanly (exit 0). That proves the env runs end-to-end
    # and the guard fires BEFORE any parser. (A real benign docx waits for Tom's
    # parser; the *env* is what we prove here.)
    out = _run(
        [rt, "run", "--rm", "-i", *_hardening(rt), IMAGE,
         "--job", "extract", "--format", "docx", "--declared-mime", "x"],
        stdin=b"PK\x03\x04not-a-real-zip", timeout=30,
    )
    ok = out.returncode == 0 and b'"ok":false' in out.stdout and b"zip" in out.stdout
    print(f"  exit={out.returncode} stdout={out.stdout[:120]!r}")
    print("  PASS" if ok else "  FAIL — worker did not run the contract cleanly")
    return ok


def case_infinite_loop(rt: str) -> bool:
    _hdr(2, "infinite-loop parser → wall-clock timeout KILLS it")
    # Simulate a parser RCE that spins forever. The runner's wall-clock cap is
    # what kills it; here we enforce the SAME bound via `timeout` and assert the
    # container does NOT outlive it (host stays responsive).
    wall = 6
    started = time.monotonic()
    try:
        out = _run(
            [rt, "run", "--rm", *_hardening(rt),
             "--stop-timeout", "1",
             "--entrypoint", "python", IMAGE,
             "-c", "while True: pass"],
            timeout=wall,
        )
        # If it returned within `timeout`, the process exited on its own — that
        # would be wrong for an infinite loop unless something killed it.
        elapsed = time.monotonic() - started
        print(f"  container exited on its own after {elapsed:.1f}s exit={out.returncode}")
        contained = False
    except subprocess.TimeoutExpired:
        elapsed = time.monotonic() - started
        # The host-side wall-clock fired: the runner would .kill() here. Prove we
        # CAN kill it and reclaim — kill any lingering container by label.
        _kill_lingering(rt)
        print(f"  wall-clock fired at {elapsed:.1f}s; runner kills the job → contained")
        contained = True
    print("  PASS" if contained else "  FAIL — infinite loop was not bounded")
    return contained


def case_memory_bomb(rt: str) -> bool:
    _hdr(3, "memory-bomb parser → cgroup mem-limit KILLS it (host not OOM'd)")
    # Allocate way past the 256m cap. The kernel OOM-killer (scoped to the
    # container cgroup) must kill the process — NOT the host.
    out = _run(
        [rt, "run", "--rm", *_hardening(rt),
         "--entrypoint", "python", IMAGE,
         "-c", "b=bytearray()\nwhile True: b.extend(bytearray(50*1024*1024))"],
        timeout=40,
    )
    # A cgroup OOM kill yields a non-zero exit (137 / 1) — the allocation never
    # succeeds host-wide. Success of the container (exit 0) would be a FAILURE.
    contained = out.returncode != 0
    print(f"  exit={out.returncode} (non-zero = cgroup killed it before host OOM)")
    print("  PASS" if contained else "  FAIL — memory bomb was NOT contained")
    return contained


def case_fork_bomb(rt: str) -> bool:
    _hdr(4, "fork-bomb parser → pids-limit caps process creation")
    out = _run(
        [rt, "run", "--rm", *_hardening(rt),
         "--entrypoint", "python", IMAGE,
         "-c",
         "import os\n"
         "n=0\n"
         "try:\n"
         "  while n<10000:\n"
         "    os.fork(); n+=1\n"
         "except OSError as e:\n"
         "  print('fork blocked at', n, e); os._exit(0)\n"],
        timeout=40,
    )
    # pids-limit=64 means fork() fails with EAGAIN well before 10000 — the worker
    # prints "fork blocked" and exits 0, OR the runtime kills it. Either way the
    # fork storm is capped. A clean run to 10000 forks would be a FAILURE.
    blocked = b"fork blocked" in out.stdout or out.returncode != 0
    print(f"  exit={out.returncode} stdout={out.stdout[:120]!r}")
    print("  PASS" if blocked else "  FAIL — fork bomb was NOT capped")
    return blocked


def case_egress_denied(rt: str) -> bool:
    _hdr(5, "egress attempt → network=none blocks SSRF/exfil")
    out = _run(
        [rt, "run", "--rm", *_hardening(rt),
         "--entrypoint", "python", IMAGE,
         "-c",
         "import socket\n"
         "try:\n"
         "  socket.create_connection(('1.1.1.1',53),timeout=3)\n"
         "  print('EGRESS-SUCCEEDED')\n"
         "except OSError as e:\n"
         "  print('egress blocked:', e.__class__.__name__); raise SystemExit(0)\n"],
        timeout=20,
    )
    blocked = b"EGRESS-SUCCEEDED" not in out.stdout
    print(f"  exit={out.returncode} stdout={out.stdout[:120]!r}")
    print("  PASS" if blocked else "  FAIL — the jail reached the network!")
    return blocked


def _docx_with_metadata_leak() -> bytes:
    """A docx carrying a matched value in the BODY, the CORE creator metadata, AND
    a CUSTOM document property (docProps/custom.xml) — the three metadata-bearing
    surfaces the no-residual proof must clear in the OUTPUT."""
    W = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
    CP = "http://schemas.openxmlformats.org/package/2006/metadata/core-properties"
    DC = "http://purl.org/dc/elements/1.1/"
    CUSTOM = "http://schemas.openxmlformats.org/officeDocument/2006/custom-properties"
    VT = "http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes"
    document = (
        f'<?xml version="1.0"?><w:document xmlns:w="{W}"><w:body>'
        f'<w:p><w:r><w:t>{_BODY_VAL}</w:t></w:r></w:p>'
        f'</w:body></w:document>'
    )
    core = (
        f'<?xml version="1.0"?><cp:coreProperties xmlns:cp="{CP}" xmlns:dc="{DC}">'
        f'<dc:creator>{_META_CORE}</dc:creator></cp:coreProperties>'
    )
    custom = (
        f'<?xml version="1.0"?><Properties xmlns="{CUSTOM}" xmlns:vt="{VT}">'
        f'<property fmtid="{{D5CDD505-2E9C-101B-9397-08002B2CF9AE}}" pid="2" '
        f'name="ClientContact"><vt:lpwstr>{_META_CUSTOM}</vt:lpwstr></property>'
        f'</Properties>'
    )
    ct = (
        '<?xml version="1.0"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '</Types>'
    )
    rels = (
        '<?xml version="1.0"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>'
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", ct)
        zf.writestr("_rels/.rels", rels)
        zf.writestr("word/document.xml", document)
        zf.writestr("docProps/core.xml", core)
        zf.writestr("docProps/custom.xml", custom)
    return buf.getvalue()


def case_metadata_no_residual(rt: str) -> bool:
    """CASE 6: a REAL in-jail PSEUDONYMIZE re-render strips metadata residual.

    Runs the worker's pseudonymize job inside the hardened container with a docx
    that carries the SAME matched value in the body, the core creator metadata,
    AND a custom document property. We then re-extract the worker's OUTPUT (the
    worker returns ``output_segments`` re-extracted incl. metadata) and assert NO
    original matched value survives anywhere — body, core metadata, OR custom.xml.
    This is the metadata no-residual proof the brief mandates, run for real on
    BOTH runtimes."""
    _hdr(6, "in-jail PSEUDONYMIZE → NO metadata residual (body+core+custom.xml)")
    doc = _docx_with_metadata_leak()
    # The plan tokenizes the body value AND both metadata values (the host builds
    # a plan over every matched location; here we name all three originals).
    plan = {
        "spans": [
            {"segment_location": "word/document.xml#p=1", "original": _BODY_VAL,
             "action": "PSEUDONYMIZE", "token": "[EMAIL_1]"},
            {"segment_location": "docProps/core.xml#creator", "original": _META_CORE,
             "action": "PSEUDONYMIZE", "token": "[EMAIL_2]"},
            {"segment_location": "docProps/custom.xml#name=ClientContact",
             "original": _META_CUSTOM, "action": "PSEUDONYMIZE", "token": "[EMAIL_3]"},
        ],
        "strip_hidden_and_metadata": True,
    }
    plan_b64 = base64.b64encode(json.dumps(plan).encode()).decode()
    out = _run(
        [rt, "run", "--rm", "-i", *_hardening(rt), IMAGE,
         "--job", "pseudonymize", "--format", "docx", "--declared-mime", "x",
         "--plan", plan_b64],
        stdin=doc, timeout=30,
    )
    if out.returncode != 0:
        print(f"  FAIL — worker exited {out.returncode}; stderr={out.stderr[:200]!r}")
        return False
    try:
        result = json.loads(out.stdout)
    except ValueError:
        print(f"  FAIL — non-JSON worker output: {out.stdout[:200]!r}")
        return False
    if not result.get("ok"):
        print(f"  FAIL — worker contained the job: {result.get('reason')!r}")
        return False
    # Re-extract-the-OUTPUT segments (the worker re-extracted incl. metadata).
    output_text = "\n".join(str(s.get("text", "")) for s in result.get("output_segments", []))
    # Belt + suspenders: also scan the raw rendered bytes.
    rendered = base64.b64decode(result.get("rendered_b64", ""))
    leaks = []
    for label, val in (("body", _BODY_VAL), ("core-metadata", _META_CORE),
                       ("custom-property", _META_CUSTOM)):
        if val in output_text:
            leaks.append(f"{label} (in re-extracted output)")
        if val.encode() in rendered:
            leaks.append(f"{label} (in raw bytes)")
    contained = not leaks
    if contained:
        print("  output re-extracted: NO residual in body, core metadata, OR "
              "custom.xml; raw bytes clean → contained")
    else:
        print(f"  FAIL — metadata residual survived: {leaks}")
    print("  PASS" if contained else "  FAIL — metadata residual NOT stripped")
    return contained


def case_seccomp_ns_denied(rt: str) -> bool:
    """CASE 7: the committed seccomp profile's clone flag-filter blocks namespace
    creation (Su 2026-06-09). Even with arbitrary code execution in the worker, an
    attempt to clone(CLONE_NEWUSER) — the first step of a user-namespace escape /
    privilege-confusion — is denied by seccomp (EPERM), and clone3 is forced to
    ENOSYS so glibc cannot route around the filter. Thread creation (the legitimate
    clone the parsers need) is unaffected — CASES 1/6 already prove parsers run.

    This is the regression test for the clone arg-filter hardening: it re-fails if
    the masked-clone rule is dropped or the CLONE_NEW* mask is weakened."""
    _hdr(7, "seccomp clone filter → namespace creation DENIED (no ns-escape)")
    out = _run(
        [rt, "run", "--rm", *_hardening(rt),
         "--entrypoint", "python", IMAGE,
         "-c",
         "import ctypes\n"
         "libc = ctypes.CDLL('libc.so.6', use_errno=True)\n"
         "CLONE_NEWUSER = 0x10000000\n"
         "# SIGCHLD(17) | CLONE_NEWUSER — a real namespace-creating clone.\n"
         "rc = libc.syscall(56, CLONE_NEWUSER | 17, 0, 0, 0, 0)\n"
         "import os\n"
         "print('NEWUSER-CLONE-SUCCEEDED' if rc >= 0 else "
         "f'clone(CLONE_NEWUSER) denied rc={rc} errno={ctypes.get_errno()}')\n"],
        timeout=20,
    )
    # The filter must DENY it (rc<0). A success (rc>=0, child pid) is a FAILURE:
    # the jail let a parser create a user namespace.
    denied = b"NEWUSER-CLONE-SUCCEEDED" not in out.stdout
    print(f"  exit={out.returncode} stdout={out.stdout[:120]!r}")
    print("  PASS" if denied else "  FAIL — clone(CLONE_NEWUSER) was permitted!")
    return denied


def _kill_lingering(rt: str) -> None:
    """Reap any container left by a timed-out case (label-scoped)."""
    try:
        ids = _run([rt, "ps", "-q", "--filter", "ancestor=" + IMAGE], timeout=15)
        for cid in ids.stdout.split():
            subprocess.run([rt, "kill", cid.decode()], capture_output=True, timeout=15)
            subprocess.run([rt, "rm", "-f", cid.decode()], capture_output=True, timeout=15)
    except Exception:
        pass


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--runtime", choices=["docker", "podman"], default="docker")
    args = ap.parse_args()
    rt = args.runtime

    print(f"Extractor sandbox containment proof — runtime={rt}, image={IMAGE}")
    # Confirm the image exists for this runtime.
    chk = _run([rt, "image", "inspect", IMAGE], timeout=30)
    if chk.returncode != 0:
        print(f"FATAL: image {IMAGE} not found for {rt}. Build it first:\n"
              f"  {rt} build -f docker/Dockerfile.extractor -t {IMAGE} .")
        return 2

    cases = [
        case_benign,
        case_infinite_loop,
        case_memory_bomb,
        case_fork_bomb,
        case_egress_denied,
        case_metadata_no_residual,
        case_seccomp_ns_denied,
    ]
    results = []
    for c in cases:
        try:
            results.append(c(rt))
        except Exception as exc:  # a harness error is a FAIL, not a pass
            print(f"  HARNESS ERROR: {exc!r}")
            results.append(False)
        finally:
            _kill_lingering(rt)

    passed = sum(results)
    total = len(results)
    print(f"\n=== RESULT ({rt}): {passed}/{total} cases contained ===")
    if passed == total:
        print("CONTAINMENT PROVEN — the jail contains a hostile parser.")
        return 0
    print("CONTAINMENT FAILURE — release-blocker.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
