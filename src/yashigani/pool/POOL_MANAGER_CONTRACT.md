# Pool Manager API Contract — v2.25.0 P1 Extension

Plan reference: `p1-universal-ringfence-implementation-plan-20260528.md` §2.D L11/L12.

**Owner split:** Captain owns this contract document + the Python type stubs in `manager.py` / `backend.py`. Tom owns the Python implementation against this contract.

## Summary of changes

The existing `PoolManager` and `ContainerBackend` are **backwards-compatible extended** with keyword-only parameters. No existing call site breaks. New ring-fence parameters are keyword-only with sane defaults that reproduce the current behaviour.

## 1. `ContainerInfo` — new fields

```python
@dataclass
class ContainerInfo:
    # --- existing fields (unchanged) ---
    container_id: str
    container_name: str
    identity_id: str
    service_slug: str
    image: str
    endpoint: str
    status: str
    created_at: float
    last_active: float
    health_failures: int = 0

    # --- NEW fields (P1 W2, plan L11) ---
    networks: list[str] = field(default_factory=list)
    """
    All network names the container is connected to.
    For ring-fenced agents: [ringfence_<agent>, caddy_internal].
    For legacy pool containers: [docker_internal] (unchanged behaviour).
    """

    mode: str = "on-demand"
    """
    Container lifecycle mode.
    "on-demand"  — cleaned up by cleanup_idle() after idle_timeout_seconds.
    "persistent" — cleanup_idle() skips; only torn down by explicit teardown().
    Constraint: v1 onboarded agents MUST be "persistent" (Nico N2: onboard-time
    cert issuance; runtime cert re-issuance is v2.24.0-blocked).
    """

    spiffe_identity: str = ""
    """
    SPIFFE URI for this container instance.
    Format: spiffe://yashigani.internal/agents/{tenant_id}/{agent_name}
    Empty string for non-agent pool containers (legacy behaviour).
    Populated by PoolManager._create_container() when provided via CertMount.
    """

    ringfence_init_ready: bool = False
    """
    True after the ringfence-init sidecar has written /run/ringfence/ready
    AND PoolManager._wait_for_ringfence_init() confirmed it.
    False for containers without a ringfence-init sidecar (legacy behaviour).
    """
```

## 2. `CertMount` — new dataclass

```python
@dataclass
class CertMount:
    """
    SPIFFE TLS certificate mount specification for a ring-fenced agent.

    plan L11: PM._create_container() receives a list of CertMount instances and
    connects them to the container's bind-mount spec. Tom implements the
    actual Docker/Podman/K8s binding.
    """
    host_cert_path: str
    """
    Absolute path on the host (or PVC mount path in K8s) to the certificate
    file. Issued at onboard time by install.sh _pki_run_issuer (Su-002).
    Example: /opt/yashigani/docker/secrets/goose_client.crt
    """

    host_key_path: str
    """
    Absolute path to the private key file.
    Example: /opt/yashigani/docker/secrets/goose_client.key
    Permissions: 0640 root:2002 (ysg-secrets GID).
    """

    host_ca_path: str
    """
    Absolute path to the CA certificate bundle (ca_root.crt).
    """

    container_cert_path: str = "/run/secrets/client.crt"
    """Path inside the container where cert is mounted (read-only)."""

    container_key_path: str = "/run/secrets/client.key"
    """Path inside the container where key is mounted (read-only)."""

    container_ca_path: str = "/run/secrets/ca.crt"
    """Path inside the container where CA cert is mounted (read-only)."""

    spiffe_identity: str = ""
    """SPIFFE URI embedded in the cert. Used to populate ContainerInfo.spiffe_identity."""
```

## 3. `PoolManager.get_or_create()` — extended signature

```python
def get_or_create(
    self,
    identity_id: str,
    service_slug: str,
    image: str,
    env: dict[str, str] | None = None,
    port: int = 8080,
    # --- NEW keyword-only parameters (P1 W2) ---
    *,
    networks: list[str] | None = None,
    cert_mount: CertMount | None = None,
    mode: str = "on-demand",
    ringfence_init_network: str | None = None,
) -> ContainerInfo:
    """
    Get an existing container or create a new one for (identity, service).

    [existing behaviour unchanged for callers that don't pass new kwargs]

    New parameters:
        networks: list[str]
            Additional networks to connect the container to after creation.
            First element is the primary network (replaces self._network for
            ring-fenced agents). Remaining elements connected via network.connect().
            Docker/Podman: `ContainerBackend.run()` uses networks[0] as the primary,
            then calls `network.connect()` for networks[1:].
            K8s: ignored (K8s uses NetworkPolicy for isolation, not multi-network).
            None → use self._network (existing single-network behaviour).

        cert_mount: CertMount | None
            SPIFFE certificate bind-mount specification. If provided:
            - Compose/Podman: bind-mounts host_*_path → container_*_path (ro, mode 0444/0400).
            - K8s: projected volume from Secret carrying the leaf cert (issued at onboard time).
            None → no cert mounts (existing behaviour).

        mode: str ("on-demand" | "persistent")
            Container lifecycle mode. "persistent" containers are skipped by
            cleanup_idle(). v1 ring-fenced agents MUST be "persistent".

        ringfence_init_network: str | None
            Network name shared between the ringfence-init sidecar and this container.
            When set, PoolManager._create_container() calls
            _wait_for_ringfence_init(ringfence_init_network) before returning
            ContainerInfo. None → skip the wait (existing behaviour).
    """
```

## 4. `PoolManager._create_container()` — extended signature

```python
def _create_container(
    self,
    identity_id: str,
    service_slug: str,
    image: str,
    env: dict,
    port: int,
    # --- NEW keyword-only parameters (P1 W2) ---
    *,
    networks: list[str] | None = None,
    cert_mount: CertMount | None = None,
    mode: str = "on-demand",
    ringfence_init_network: str | None = None,
) -> ContainerInfo:
    """
    Internal container creation. Tom implements.

    Multi-network connect semantics:
        Docker backend:
            1. run() with network=networks[0] (primary).
            2. For each n in networks[1:]: backend._client.networks.get(n).connect(container)
        Podman backend:
            1. run() with no network (Podman: connect after creation pattern already in backend.py).
            2. networks.get(networks[0]).connect(container)  # primary
            3. For each n in networks[1:]: networks.get(n).connect(container)
        K8s backend:
            Ignore networks parameter — K8s networking handled by NetworkPolicy.

    Cert mount semantics (Docker/Podman):
        Bind-mount each path with read-only, uid/gid matching the agent's
        supplementalGroups ([2002] per plan S7):
            host_cert_path → container_cert_path: ro, mode 0444
            host_key_path  → container_key_path:  ro, mode 0400
            host_ca_path   → container_ca_path:   ro, mode 0444
        Podman rootless: requires :U flag (or explicit UID mapping).

    Cert mount semantics (K8s):
        Projected volume from the agent's Secret (created by install.sh or
        the onboarding hook). Mounted at /run/secrets/ in the pod spec.

    Persistent mode:
        Set ContainerInfo.mode = "persistent".
        The cleanup_idle() method must check info.mode and skip "persistent" containers.
    """
```

## 5. `PoolManager._wait_for_ringfence_init()` — new method

```python
def _wait_for_ringfence_init(
    self,
    ringfence_network: str,
    timeout_seconds: int = 30,
    poll_interval_seconds: float = 0.5,
) -> None:
    """
    Wait until the ringfence-init sidecar writes /run/ringfence/ready on the
    shared tmpfs volume mounted at ringfence_network's shared namespace.

    Compose path:
        The shared tmpfs is a named volume or tmpfs mount shared between the
        ringfence-init container and the agent container. PoolManager probes
        the volume indirectly by inspecting the init container's exit code:
        exit 0 = rules applied, /run/ringfence/ready written.
        Actually, for Compose: the service_completed_successfully condition
        IS the gate. This method is only needed for the programmatic PM path
        where PM creates containers directly (not via docker-compose up).

    Direct-API path (PM creates containers without compose):
        1. Find the init container by label: yashigani.ringfence-init=<network>.
        2. Poll for its exit code == 0 or presence of /run/ringfence/ready file
           via `docker exec <init-ctr> cat /run/ringfence/ready`.
        3. On timeout: raise RingfenceInitTimeout.

    K8s path:
        initContainers exit code is the sequencing gate — no explicit wait needed.
        This method is a no-op on K8s.

    Raises:
        RingfenceInitTimeout: if the ringfence-init sidecar does not complete
        within timeout_seconds. Caller should treat as a hard failure and abort
        container creation (do not create the agent container un-ring-fenced).

    Fail-closed contract:
        If this method raises for any reason, _create_container() MUST NOT
        return a ContainerInfo. The caller's fallback is to emit 503 Service
        Unavailable (same as PodStartupTimeout for K8s pods).
        This enforces plan L12: "PM must create the agent container ONLY AFTER
        the init-sidecar applied iptables rules."
    """
```

### §5 addendum — podman-rootless behaviour (Laura + Iris gate, P1 W2)

On `YSG_RUNTIME_4WAY=podman-rootless` the ringfence-init sidecar **cannot** apply
iptables rules (iptables inside a rootless user-namespace requires SYS_ADMIN, which
is not granted — see `docker/ringfence-init/Dockerfile` rootless-podman-gap comment).
The init script therefore exits **non-zero** and writes only
`/run/ringfence/l1-gap` (NOT `/run/ringfence/ready`).

Tom's implementation of `_wait_for_ringfence_init()` MUST handle this as follows:

**Binding contract (option A — honest L1-absent path):**

1. Detect `YSG_RUNTIME_4WAY=podman-rootless` via `os.environ.get("YSG_RUNTIME_4WAY")`.
2. When runtime is `podman-rootless`:
   - Poll for `/run/ringfence/l1-gap` instead of `/run/ringfence/ready`.
   - On finding `l1-gap`: return normally (do not raise `RingfenceInitTimeout`).
   - Set `ContainerInfo.ringfence_init_ready = False` (NOT True — the full ready marker
     was never written; the agent starts but L1 is NOT enforced).
   - Emit a `logger.warning` at init time:
     `"ringfence-init: L1 iptables not enforced (podman-rootless); l1-gap marker detected. L2+L3 active. Audit event emitted."`
   - Emit an audit event (Su audit chain hook, implementation details deferred to Tom)
     recording the L1-absent state so it is visible to the operator.
3. When runtime is NOT `podman-rootless`:
   - Poll for `/run/ringfence/ready` as specified above.
   - `l1-gap` alone is NOT an acceptable substitute — raise `RingfenceInitTimeout`.

**Rationale (why option A, not option B "skip the poll entirely"):**

Option B (skip the ready-poll for podman-rootless entirely) would silently allow the
agent container to start even if the init sidecar crashed for an unrelated reason.
Option A keeps the fail-closed contract for non-L1 failures (e.g. DNS resolution
failure, unexpected sidecar crash) while honestly acknowledging the known L1 gap.
The l1-gap marker is only written by the init script on the explicit iptables-fail
path — any other exit condition means no marker and the poll will timeout, which is
the correct fail-closed behaviour.

**ContainerInfo.ringfence_init_ready semantics on podman-rootless:**

| State | ringfence_init_ready | Meaning |
|---|---|---|
| `/run/ringfence/ready` present | `True` | L1 enforced, L2+L3 enforced |
| `/run/ringfence/l1-gap` present (podman-rootless) | `False` | L1 absent (documented gap), L2+L3 enforced |
| Neither — timeout | raises `RingfenceInitTimeout` | Hard failure, agent must not start |

The PM MUST NOT silently hang waiting for `ready` that never comes on
podman-rootless — that would be an indefinite startup stall for every agent
container on the most common developer runtime.

## 6. `PoolManager.cleanup_idle()` — persistent-mode skip

```python
def cleanup_idle(self) -> int:
    """
    Tear down containers that have been idle longer than the timeout.

    EXISTING behaviour: tears down all containers over the idle threshold.
    MODIFIED behaviour (P1 W2): skip containers where info.mode == "persistent".

    Persistent containers are only torn down by:
        - teardown(identity_id, service_slug) called explicitly
        - teardown_all_for_identity(identity_id) called on identity deactivation
        - yashigani offboard <agent> (Su S5 / Lu G4 — calls teardown_all_for_identity)
    """
```

## 7. `PoolManager.replace()` — network/cert forwarding

```python
def replace(
    self,
    identity_id: str,
    service_slug: str,
    reason: str,
) -> Optional[ContainerInfo]:
    """
    Replace an unhealthy container.

    EXISTING behaviour: calls _create_container() with image/port from the old info.
    MODIFIED behaviour (P1 W2): also forwards networks, cert_mount hints, and mode
    from the old ContainerInfo to _create_container() so the replacement
    container is ring-fenced identically to the original.

    ContainerInfo.networks and ContainerInfo.mode are the persistence mechanism:
    replacement reads them from the old ContainerInfo and passes them to the new
    _create_container() call.

    cert_mount reconstruction: cert paths are derived from the old container's
    spiffe_identity (or looked up from the running service_identities.yaml)
    by calling a to-be-defined _resolve_cert_mount(spiffe_identity) helper.
    TODO(tom): implement _resolve_cert_mount() as part of the PM Python impl.
    """
```

## 8. New exception class

```python
class RingfenceInitTimeout(Exception):
    """
    Raised when PoolManager._wait_for_ringfence_init() does not observe the
    ringfence-init sidecar completing within the timeout window.

    Callers must NOT create the agent container after this exception. Treat
    as a hard failure; emit 503 Service Unavailable to the downstream caller.
    """
    pass
```

## 9. `ContainerBackend.run()` — multi-network extension

```python
def run(
    self,
    image: str,
    name: str,
    environment: dict,
    network: str,          # primary network (unchanged)
    labels: dict,
    detach: bool = True,
    # --- NEW keyword-only parameter (P1 W2) ---
    *,
    additional_networks: list[str] | None = None,
    mounts: list[CertMount] | None = None,
) -> ContainerHandle:
    """
    Create and start a container.

    additional_networks: list[str] | None
        Networks to connect after creation (beyond the primary `network`).
        Implementation: after container is created and started, call
        self._client.networks.get(n).connect(container) for each n.
        Docker path: network.connect() is synchronous; container is already
        in the primary network from containers.run().
        Podman path: the existing post-creation network.connect() pattern
        (already in backend.py) is extended for additional_networks.
        K8s path: ignored (K8s uses NetworkPolicy).

    mounts: list[CertMount] | None
        SPIFFE cert bind-mounts. See CertMount docstring.
        Docker/Podman: passed to containers.run() as volumes= dict.
        K8s: ignored (K8s uses projected volumes; handled at pod-spec level).
    """
```

## 10. `KubernetesBackend.run()` — cert mount via projected volume

```python
# K8s extension: when cert_mount is provided to PoolManager._create_container(),
# the K8s pod spec gets a projected volume instead of bind-mounts.
# The cert Secret name is derived from the agent_name (e.g. yashigani-goose-tls).
# Tom implements the pod-spec projection; Captain documents the mount contract here.
#
# Pod spec snippet (generated by Tom's K8s impl):
#
#   volumes:
#     - name: agent-tls
#       projected:
#         sources:
#           - secret:
#               name: yashigani-<agent>-tls
#               items:
#                 - key: tls.crt
#                   path: client.crt
#                 - key: tls.key
#                   path: client.key
#                   mode: 0400
#                 - key: ca.crt
#                   path: ca.crt
#   containers:
#     - name: agent
#       volumeMounts:
#         - name: agent-tls
#           mountPath: /run/secrets
#           readOnly: true
#
# The Secret is created by install.sh / the onboarding hook at onboard time
# (Su S2). K8s Secret name convention: yashigani-<agent_name>-tls.
```

## 11. Interaction with compose codegen (TODO-pending-W1)

The following bindings in the compose codegen template are DEFERRED pending Tom's W1 manifest schema:

```python
# TODO-pending-W1: these variable names will be supplied by the W1 manifest schema.
# Captain's contract is the PM API above; codegen wires these at W3.

# From manifest spec.identity.spiffe (W1 field):
#
# IMPORTANT — spec.identity.spiffe is a DICT, not a string.
# Schema (agent-manifest-v1alpha1.schema.json):
#   spec.identity.spiffe = { "override_id": "<string>" }
#
# The W3 codegen author MUST call Tom's resolve_spiffe_uri(parsed) helper
# (yashigani.manifest package, added in W1) to obtain the resolved URI string.
# Direct dict access (manifest.spec.identity.spiffe) returns the dict and will
# produce a TypeError at CertMount.__post_init__ enforcement time.
#
# Correct wiring (W3):
#   from yashigani.manifest import resolve_spiffe_uri   # Tom adds this in W1
#   spiffe_uri = resolve_spiffe_uri(parsed)             # returns str
#   cert_mount = CertMount(
#       host_cert_path=f"{secrets_dir}/{agent_name}_client.crt",
#       host_key_path=f"{secrets_dir}/{agent_name}_client.key",
#       host_ca_path=f"{secrets_dir}/ca_root.crt",
#       spiffe_identity=spiffe_uri,                     # str, not dict
#   )
#
# resolve_spiffe_uri(parsed) semantics (Tom to document in W1):
#   - If spec.identity.spiffe.override_id is set and passes N1 linting,
#     return override_id verbatim.
#   - Otherwise, derive canonical form:
#     "spiffe://yashigani.internal/agents/{tenant_id}/{name}"
#     where tenant_id = parsed["metadata"]["tenant_id"]
#     and   name      = parsed["metadata"]["name"]
#
# Cross-reference: yashigani.manifest.resolve_spiffe_uri (W1, Tom)
#                  src/yashigani/manifest/linter.py _lint_spiffe_prefix (N1 rule)
#
# From manifest spec.network (W1 field):
#   networks = [f"ringfence_{agent_name}", "caddy_internal"]
#
# From manifest spec.lifecycle.mode (W1 field, always "persistent" in v1 per Nico N2):
#   mode = "persistent"
#
# From codegen runtime detection (L4):
#   ringfence_init_network = f"ringfence_{agent_name}"
```

## 12. Backward-compatibility guarantee

All new parameters are keyword-only with defaults that reproduce the existing single-network, no-cert, on-demand behaviour:

```python
# Existing callers (no new kwargs):
pm.get_or_create("id1", "goose", "goose:latest", env={}, port=8080)
# => ContainerInfo.networks=[], mode="on-demand", spiffe_identity=""
# => identical to current behaviour

# New ring-fenced callers:
pm.get_or_create(
    "id1", "goose", "goose:latest",
    env={"OPENAI_API_BASE": "https://caddy/v1"},
    port=8080,
    networks=["ringfence_goose", "caddy_internal"],
    cert_mount=CertMount(host_cert_path="/opt/yashigani/docker/secrets/goose_client.crt", ...),
    mode="persistent",
    ringfence_init_network="ringfence_goose",
)
```

## 13. Test contract (Captain's perspective — tests/contracts/)

Tom writes the implementation tests; Captain specifies the contract assertions:

1. **`test_pool_manager_ringfence_contract.py`**:
   - `get_or_create(..., networks=[...])` → `ContainerInfo.networks == [...]`
   - `get_or_create(..., mode="persistent")` → `cleanup_idle()` does NOT tear it down
   - `get_or_create(..., mode="on-demand")` → `cleanup_idle()` tears it down after idle_timeout
   - `replace()` → new container has same `.networks` and `.mode` as old
   - `get_or_create(..., ringfence_init_network="test-net")` → raises `RingfenceInitTimeout` after timeout if init never completes
   - `get_or_create(..., cert_mount=CertMount(...))` → `ContainerInfo.spiffe_identity == cert_mount.spiffe_identity`

2. **`test_container_backend_multi_network.py`**:
   - `ContainerBackend.run(..., additional_networks=["net2"])` → container connected to primary + net2
   - Docker path: `docker inspect <container> --format '{{.NetworkSettings.Networks}}'` shows both networks
   - Podman path: same via `podman inspect`
   - K8s path: `additional_networks` ignored; no error

3. **`test_ringfence_init_timeout.py`**:
   - `_wait_for_ringfence_init("ring-net", timeout_seconds=1)` raises `RingfenceInitTimeout` if init container never exits
   - On K8s backend: `_wait_for_ringfence_init()` is a no-op (returns immediately)
