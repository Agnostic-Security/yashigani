"""
Yashigani Document Enforcement — the per-job sandboxed extractor runtime (B1).

This is the hardened execution environment that runs untrusted document parsers
(and, next slice, the REDACT/PSEUDONYMIZE re-render — red-team F6) in isolation.
It is the deliverable named in the plan §6 / §8.6 B1 and the TODO seams Tom left
in ``extractor.py`` (``_UnavailableExtractor`` → this).

WHAT IT ENFORCES (plan §6 + red-team F1/F6):
  - **Per-job ephemeral container**, reusing the existing Pool Manager
    ``ContainerBackend`` (Docker/Podman SDK) — NOT a parallel mechanism.  One
    container per parse job, killed + removed after the job (or on timeout).
  - **egress = NONE**  → ``network_mode="none"`` (Docker) / ``--network none``
    (Podman).  A malicious parser cannot SSRF or exfiltrate.
  - **read-only rootfs**, **all caps dropped**, **non-root**,
    **no-new-privileges**, **seccomp** (docker/seccomp/yashigani-extractor.json),
    **AppArmor** where applicable.
  - **No host mounts beyond the single input doc (read-only)** — the document is
    passed on **stdin**, not bind-mounted, so there is no host path the container
    can traverse.  The result comes back on **stdout** (the output channel).
  - **Resource limits**: memory ceiling, CPU quota, **PID cap**, and a
    **wall-clock timeout** enforced by the runner (kill-on-breach).
  - **Decompression-bomb guards** run *inside* the worker (bomb_guard.py) before
    any parser sees a part — a bomb is *killed*, not allowed to OOM.
  - **Fail-closed**: parser crash / non-zero exit / timeout / limit-hit / no
    backend / output-cap breach → the runner returns a failure the caller maps
    to BLOCK, never a partial-allow.

THE SEAM FOR TOM (next slice):
  Tom adds the actual OOXML/PDF parsers + the re-render as a **worker** that runs
  INSIDE this sandbox.  The contract is process-level and language-agnostic:

      stdin  : raw document bytes (the single read-only input)
      argv   : [worker, "--job", "extract"|"redact"|"pseudonymize",
                        "--format", "docx"|"xlsx"|"pptx"|"pdf",
                        "--declared-mime", "<mime>"]
      stdout : ONE JSON object — the SandboxJobResult schema (see
               docker/extractor/worker.py) — segments + extraction_complete,
               OR {"ok": false, "reason": "..."} on a guarded failure.
      exit 0 : worker produced a JSON result (ok true OR ok false-with-reason).
      exit !=0 / killed / timeout : fail-closed BLOCK (the worker died).

  Tom plugs his parser into docker/extractor/worker.py's ``_extract_<fmt>``
  dispatch; he does NOT touch this runner or the container hardening.

Captain owns: this runner, the Dockerfile, seccomp/AppArmor, compose override,
and Docker/Podman/K8s parity.  Su security-reviews the seccomp profile.
"""
from __future__ import annotations

import json
import logging
import os
import uuid
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Sandbox configuration — hardening knobs (plan §6).  Conservative defaults;
# operator-overridable via env (config layer surfaces these).
# ---------------------------------------------------------------------------

#: The hardened extractor image.  Built from docker/Dockerfile.extractor and
#: pinned by digest in production (Verification Protocol §7).
ENV_IMAGE = "YASHIGANI_EXTRACTOR_IMAGE"
DEFAULT_IMAGE = "yashigani/extractor:2.26.0"

#: Wall-clock cap per job (seconds).  Over this → kill + BLOCK.
ENV_TIMEOUT_S = "YASHIGANI_EXTRACTOR_TIMEOUT_S"
DEFAULT_TIMEOUT_S = 20

#: Memory ceiling per job.  A bomb that slips the in-worker guard still cannot
#: OOM the host — the cgroup kills the container.
ENV_MEM_LIMIT = "YASHIGANI_EXTRACTOR_MEM_LIMIT"
DEFAULT_MEM_LIMIT = "512m"

#: CPU quota per job (fractional cores).
ENV_CPU_LIMIT = "YASHIGANI_EXTRACTOR_CPUS"
DEFAULT_CPU_LIMIT = 1.0

#: PID cap per job — kills fork-bombs.
ENV_PIDS_LIMIT = "YASHIGANI_EXTRACTOR_PIDS_LIMIT"
DEFAULT_PIDS_LIMIT = 64

#: Cap on the JSON result the worker may emit on stdout (output amplification,
#: red-team F6 — a small input must not yield a giant output).
ENV_MAX_OUTPUT_BYTES = "YASHIGANI_EXTRACTOR_MAX_OUTPUT_BYTES"
DEFAULT_MAX_OUTPUT_BYTES = 32 * 1024 * 1024  # 32 MiB

#: Path to the seccomp profile (mounted/installed node-side; Su reviews it).
DEFAULT_SECCOMP_PATH = "docker/seccomp/yashigani-extractor.json"
ENV_SECCOMP_PATH = "YASHIGANI_EXTRACTOR_SECCOMP_PATH"

#: AppArmor profile name (loaded node-side via apparmor_parser).
DEFAULT_APPARMOR_PROFILE = "yashigani-extractor"
ENV_APPARMOR_PROFILE = "YASHIGANI_EXTRACTOR_APPARMOR"


def _cpu_controller_available() -> bool:
    """True when the `cpu` cgroup-v2 controller is delegated to this user.

    Docker (rootful) and rootful Podman always have it. Rootless Podman on
    cgroup-v2 commonly has ONLY memory+pids delegated unless the operator has
    enabled cpu delegation (a systemd drop-in). When cpu is NOT delegated,
    requesting a CPU quota makes the OCI runtime error — so the runner degrades
    the quota (NOT the isolation): CPU abuse stays bounded by the wall-clock
    timeout + memory cap. See docs/operator note in the Dockerfile/compose."""
    uid = os.getuid()
    path = (
        f"/sys/fs/cgroup/user.slice/user-{uid}.slice/"
        f"user@{uid}.service/cgroup.controllers"
    )
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return "cpu" in fh.read().split()
    except OSError:
        # Rootful / Docker / non-cgroup-v2 — assume available.
        return True


class SandboxUnavailableError(Exception):
    """No container backend is available to run the sandbox.

    Fail-closed: the caller maps this to a BLOCK (we never run an untrusted
    parser in-process as a fallback — that is exactly the RCE surface the
    sandbox exists to remove, red-team F1/F6)."""


class SandboxJobError(Exception):
    """The sandboxed job failed (crash / timeout / non-zero exit / over-cap).

    Fail-closed: the caller maps this to BLOCK with ``reason`` as the precise
    audit/alert reason — never a partial-allow."""

    def __init__(self, reason: str, *, killed: bool = False) -> None:
        super().__init__(reason)
        self.reason = reason
        self.killed = killed


@dataclass(frozen=True)
class SandboxConfig:
    """Resolved hardening configuration for one sandboxed job."""

    image: str = DEFAULT_IMAGE
    timeout_s: int = DEFAULT_TIMEOUT_S
    mem_limit: str = DEFAULT_MEM_LIMIT
    cpus: float = DEFAULT_CPU_LIMIT
    pids_limit: int = DEFAULT_PIDS_LIMIT
    max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES
    seccomp_path: str = DEFAULT_SECCOMP_PATH
    apparmor_profile: str = DEFAULT_APPARMOR_PROFILE

    @classmethod
    def from_env(cls) -> "SandboxConfig":
        def _int(name: str, default: int) -> int:
            raw = os.environ.get(name)
            if raw is None:
                return default
            try:
                v = int(raw.strip())
            except ValueError:
                return default
            return v if v > 0 else default

        def _float(name: str, default: float) -> float:
            raw = os.environ.get(name)
            if raw is None:
                return default
            try:
                v = float(raw.strip())
            except ValueError:
                return default
            return v if v > 0 else default

        return cls(
            image=os.environ.get(ENV_IMAGE, DEFAULT_IMAGE),
            timeout_s=_int(ENV_TIMEOUT_S, DEFAULT_TIMEOUT_S),
            mem_limit=os.environ.get(ENV_MEM_LIMIT, DEFAULT_MEM_LIMIT),
            cpus=_float(ENV_CPU_LIMIT, DEFAULT_CPU_LIMIT),
            pids_limit=_int(ENV_PIDS_LIMIT, DEFAULT_PIDS_LIMIT),
            max_output_bytes=_int(ENV_MAX_OUTPUT_BYTES, DEFAULT_MAX_OUTPUT_BYTES),
            seccomp_path=os.environ.get(ENV_SECCOMP_PATH, DEFAULT_SECCOMP_PATH),
            apparmor_profile=os.environ.get(ENV_APPARMOR_PROFILE, DEFAULT_APPARMOR_PROFILE),
        )


@dataclass
class SandboxJobResult:
    """Structured result of a sandboxed parse job (decoded from worker stdout).

    ``ok=False`` is a *guarded* failure (the worker caught a bomb/limit and
    exited 0 with a reason) — still maps to BLOCK, but distinguishes "we
    contained it cleanly" from "the worker died" (``SandboxJobError``).
    """

    ok: bool
    reason: str = ""
    segments: list[dict] = field(default_factory=list)
    extraction_complete: bool = False
    detected_format: str = ""
    # Re-render (REDACT/PSEUDONYMIZE) outputs — empty for an extract job.
    #: The freshly re-rendered artefact bytes (decoded from the worker's base64).
    rendered_bytes: Optional[bytes] = None
    #: The re-extracted OUTPUT segments — the host asserts no-residual / tokenized
    #: over these (the proof Laura demands: re-extract-the-output).
    output_segments: list[dict] = field(default_factory=list)
    output_extraction_complete: bool = False

    @classmethod
    def from_stdout(cls, raw: bytes, max_bytes: int) -> "SandboxJobResult":
        if len(raw) > max_bytes:
            # Output amplification (F6) — a small input produced a giant output.
            raise SandboxJobError(
                f"worker output {len(raw)} bytes exceeds cap {max_bytes} "
                f"— output-amplification, fail-closed"
            )
        try:
            obj = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as exc:
            raise SandboxJobError(
                f"worker emitted non-JSON on stdout: {exc} — fail-closed"
            ) from exc
        if not isinstance(obj, dict):
            raise SandboxJobError("worker result was not a JSON object — fail-closed")
        rendered_bytes: Optional[bytes] = None
        rb64 = obj.get("rendered_b64")
        if rb64:
            import base64
            try:
                rendered_bytes = base64.b64decode(str(rb64).encode("ascii"))
            except (ValueError, TypeError) as exc:
                raise SandboxJobError(
                    f"worker rendered_b64 undecodable: {exc} — fail-closed"
                ) from exc
        return cls(
            ok=bool(obj.get("ok", False)),
            reason=str(obj.get("reason", "")),
            segments=list(obj.get("segments", [])),
            extraction_complete=bool(obj.get("extraction_complete", False)),
            detected_format=str(obj.get("detected_format", "")),
            rendered_bytes=rendered_bytes,
            output_segments=list(obj.get("output_segments", [])),
            output_extraction_complete=bool(obj.get("output_extraction_complete", False)),
        )


# ---------------------------------------------------------------------------
# The runner
# ---------------------------------------------------------------------------

class SandboxedExtractorRunner:
    """Dispatches one parse/re-render job into a per-job ephemeral container.

    Reuses the Pool Manager ``ContainerBackend`` (Docker/Podman SDK) — the same
    isolation primitive the rest of the gateway uses (plan §6: "reusing our
    existing container-per-identity Pool Manager").  K8s parity: the same
    hardened spec is expressed as a Job/Pod (helm template) — see
    ``helm/yashigani/templates/extractor-job-template.yaml`` (Captain).

    The runner is the only place that knows HOW to spawn the hardened container;
    the worker (docker/extractor/worker.py, Tom's parsers) is the only place
    that knows HOW to parse.  Clean separation.
    """

    def __init__(
        self,
        backend=None,
        config: Optional[SandboxConfig] = None,
    ) -> None:
        # Lazy backend resolution: we only need a backend when a job actually
        # runs, so the module imports cleanly without a daemon (tests, dark flag).
        self._backend = backend
        self._backend_resolved = backend is not None
        self._config = config or SandboxConfig.from_env()

    @property
    def config(self) -> SandboxConfig:
        return self._config

    def _resolve_backend(self):
        if not self._backend_resolved:
            # Use the EXTRACTOR-specific backend selector — NOT the per-identity
            # Pool Manager create_backend(). Prefers HttpExtractorBackend (Design A,
            # LAURA-30-001 fix) when YASHIGANI_EXTRACTOR_WORKER_URL is set, then CLI
            # (Docker/Podman), then K8s. Fail-closed if none.
            from yashigani.pool.backend import create_extractor_backend
            self._backend = create_extractor_backend()
            # Only cache a positive result — if backend is None (unavailable right
            # now), stay unresolved so the next call retries. This allows the
            # pre-spawned extractor-svc (Design A) to become available after
            # backoffice startup without requiring a container restart.
            if self._backend is not None:
                self._backend_resolved = True
        if self._backend is None:
            raise SandboxUnavailableError(
                "no container backend (Docker/Podman/K8s/HTTP) available — refusing "
                "to run an untrusted parser in-process (fail-closed BLOCK)"
            )
        return self._backend

    def run_job(
        self,
        data: bytes,
        *,
        job: str,
        fmt: str,
        declared_mime: str,
        plan_b64: str = "",
    ) -> SandboxJobResult:
        """Run one sandboxed job and return its structured result.

        Parameters
        ----------
        data:
            Raw document bytes — passed to the worker on **stdin** (no host
            mount; the container has no path to traverse).
        job:
            ``"extract"`` | ``"redact"`` | ``"pseudonymize"`` — the re-render jobs
            run in the SAME sandbox as extraction (red-team F6).
        fmt:
            Detected format hint (``docx``/``xlsx``/``pptx``/``pdf``/``txt``/``csv``).
        declared_mime:
            The declared MIME (for the worker's own cross-check).
        plan_b64:
            For ``redact``/``pseudonymize`` only — the base64'd JSON RenderPlan
            (per-span transforms; NO replacer map — F5).  Passed on argv; the
            document bytes stay on stdin.

        Raises
        ------
        SandboxUnavailableError, SandboxJobError
            Both fail-closed → caller maps to BLOCK.
        """
        backend = self._resolve_backend()
        cfg = self._config
        name = f"ysg-extract-{uuid.uuid4().hex[:10]}"
        argv = [
            "--job", job,
            "--format", fmt,
            "--declared-mime", declared_mime or "",
        ]
        if job in ("redact", "pseudonymize"):
            # The plan is required for a re-render job; an empty plan fails closed
            # in the worker. We never log the plan (it carries originals — F5).
            argv += ["--plan", plan_b64]

        run_kwargs = self._hardened_run_kwargs(name, argv, cfg)

        logger.info(
            "sandbox: dispatching job=%s fmt=%s into %s (egress=none, ro-rootfs, "
            "caps=drop-all, seccomp, mem=%s, cpus=%s, pids=%d, timeout=%ds)",
            job, fmt, name, cfg.mem_limit, cfg.cpus, cfg.pids_limit, cfg.timeout_s,
        )

        try:
            stdout, exit_code, killed = backend.run_extractor_job(
                stdin=data,
                timeout_s=cfg.timeout_s,
                **run_kwargs,
            )
        except SandboxUnavailableError:
            raise
        except Exception as exc:  # defensive: any backend error → fail-closed
            raise SandboxJobError(
                f"sandbox dispatch failed: {exc!r} — fail-closed"
            ) from exc

        if killed:
            raise SandboxJobError(
                f"job killed (timeout/limit breach) after {cfg.timeout_s}s "
                f"— containment held, fail-closed BLOCK",
                killed=True,
            )
        if exit_code != 0:
            raise SandboxJobError(
                f"worker exited {exit_code} (parser crash/guard-abort) "
                f"— fail-closed BLOCK",
                killed=False,
            )

        return SandboxJobResult.from_stdout(stdout, cfg.max_output_bytes)

    @staticmethod
    def _hardened_run_kwargs(name: str, argv: list[str], cfg: SandboxConfig) -> dict:
        """The full hardening spec for the per-job container (plan §6).

        Kept in one place so the security boundary is auditable at a glance and
        Su's seccomp review has a single source of truth for the runtime flags.
        """
        security_opt = [
            "no-new-privileges:true",
            # seccomp profile is read + passed as JSON by the backend (so the
            # same string works across Docker & Podman SDKs).
        ]
        return {
            "image": cfg.image,
            "name": name,
            "command": argv,
            # --- ISOLATION ---
            "network_disabled": True,        # egress = NONE (SSRF/exfil killed)
            "read_only": True,               # read-only rootfs
            "cap_drop": ["ALL"],             # drop every capability
            "cap_add": [],                   # add none
            "user": "65532:65532",           # non-root (nonroot numeric UID)
            "security_opt": security_opt,
            "seccomp_path": cfg.seccomp_path,
            "apparmor_profile": cfg.apparmor_profile,
            # No host mounts.  Worker needs a writable scratch for temp files
            # the parser libs may create — give it a SMALL tmpfs, not a host bind.
            "tmpfs": {"/tmp": "rw,noexec,nosuid,nodev,size=64m"},
            # --- RESOURCE LIMITS ---
            "mem_limit": cfg.mem_limit,
            "memswap_limit": cfg.mem_limit,  # disable swap (= mem_limit)
            # CPU quota only where the cpu cgroup controller is available. On
            # rootless Podman cgroup-v2 the cpu controller is frequently NOT
            # delegated (only memory+pids) and setting nano_cpus makes the OCI
            # runtime error. CPU abuse stays contained by the wall-clock timeout
            # (runner-enforced) + the memory cap, so we degrade the quota, never
            # the isolation. nano_cpus=0 means "no quota" to both SDKs.
            "nano_cpus": int(cfg.cpus * 1_000_000_000) if _cpu_controller_available() else 0,
            "pids_limit": cfg.pids_limit,
            # --- LIFECYCLE ---
            "labels": {
                "yashigani.managed": "true",
                "yashigani.role": "extractor-sandbox",
                "yashigani.ephemeral": "true",
            },
            "auto_remove": False,  # runner removes explicitly after reading logs
        }
