#!/usr/bin/env python3
"""
licgen — the unified Yashigani v2 licence/build tool (§7).

Ref: AgnosticSecurity/Products/Yashigani/licence-hardening-v2-design-20260713.md
     §7 (Demo vs Production channel) + §6 (Revocation — kill-list) + §9
     (Convergence + implementation split — "Su: ... licgen wrapper").

    licgen new-leaf   --channel {demo|prod} --version 4.1.1      # master certifies leaf-N
    licgen sign-build --channel {demo|prod} --version 4.1.1      # leaf signs hash-bundle
    licgen issue      --channel {demo|prod} --domain <d> --tier <t>   # leaf signs a v5 .ysg
    licgen release    --channel {demo|prod} --version 4.1.1      # new-leaf + sign-build
    licgen revoke     --leaf|--licence|--client <id>              # kill-list entry (§6)
    licgen anchor-set emit                                        # emit MASTER_ANCHOR_SET_JSON

Channel selects DEFAULT paths only — never a different code path (§7: "Same
4.1.1 source, same signing pipeline, only the keys differ"):
  demo  -> defaults to testing_runs/yashigani/demo-license-system/{keys,registry.json}
           (§7: "Lives in testing_runs/yashigani/demo-license-system/. No custody.")
  prod  -> NO default path — --keys-dir/--registry/--kill-list are REQUIRED for
           --channel prod, so a prod invocation can never silently fall back to
           the demo/testing_runs location (fail-closed on missing prod config,
           not a silent demo-path fallback).

This script is a thin orchestration layer over:
  - scripts/keygen.py       (master/leaf minting — imported, not subprocessed,
                              so passphrase env vars are read exactly once)
  - yashigani.licensing.chain.registry (durable key/anchor records)
  - yashigani.licensing.chain.kill_list (revocation entries)
  - scripts/sign_license.py (v5 licence signing — Tom's SEAM, §9: "Tom:
                              sign_license.py -> v5 ... wire into licgen issue")
  - scripts/inject_hashes.sh (build-embed — sign-build shells out to it)

Requires: cryptography>=42, yashigani.licensing.chain importable.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

# CLAUDE.md: all install/build/deploy scratch state lives under
# `~/Documents/Claude/testing_runs/<product>/`, never inside a repo. This
# repo lives at `~/Documents/Claude/YSG/<repo-name>/` (canonical `YSG/yashigani/`
# or a worktree such as `YSG/yashigani-licence-v2/`) — i.e. TWO levels under
# the `Claude/` workspace root. From scripts/licgen.py that's FOUR `.parent`
# hops: scripts/ -> <repo-name>/ -> YSG/ -> Claude/. A prior version used
# THREE hops, resolving one directory short to `YSG/testing_runs/...`
# instead of `Claude/testing_runs/...` — every `licgen` call this session
# needed an explicit --keys-dir/--registry to work around it (Ava's finding,
# 2026-07-15). A stray `YSG/testing_runs/...` tree, if one ever existed,
# would silently sign against the wrong keys with no error — fixed here.
DEMO_DEFAULT_DIR = (
    Path(__file__).resolve().parent.parent.parent.parent
    / "testing_runs"
    / "yashigani"
    / "demo-license-system"
)


def _repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


def _ensure_src_on_path() -> None:
    src = _repo_root() / "src"
    if str(src) not in sys.path:
        sys.path.insert(0, str(src))
    scripts = _repo_root() / "scripts"
    if str(scripts) not in sys.path:
        sys.path.insert(0, str(scripts))


_ensure_src_on_path()


def _resolve_channel_dirs(args: argparse.Namespace) -> tuple[Path, Path]:
    """Returns (keys_dir, registry_path). demo defaults to testing_runs/...;
    prod REQUIRES --keys-dir + --registry explicitly (fail-closed — §7's
    'only the keys differ' means the PROD keys must never be the demo
    directory by accident)."""
    if args.channel == "demo":
        keys_dir = Path(args.keys_dir) if args.keys_dir else DEMO_DEFAULT_DIR / "keys"
        registry = Path(args.registry) if args.registry else DEMO_DEFAULT_DIR / "registry.json"
        return keys_dir, registry

    # channel == prod
    if not args.keys_dir or not args.registry:
        print(
            "ERROR: --channel prod requires --keys-dir AND --registry explicitly "
            "(no default — refusing to silently fall back to the demo/testing_runs "
            "path for production key material).",
            file=sys.stderr,
        )
        sys.exit(1)
    return Path(args.keys_dir), Path(args.registry)


# ---------------------------------------------------------------------------
# new-leaf
# ---------------------------------------------------------------------------

def _cmd_new_leaf(args: argparse.Namespace) -> None:
    import keygen  # scripts/keygen.py

    keys_dir, registry_path = _resolve_channel_dirs(args)
    keys_dir.mkdir(parents=True, exist_ok=True)

    from yashigani.licensing.chain.leaf_cert import SHARED_CLIENT_ID, Role
    from yashigani.licensing.chain.registry import KeyRecord, KeyRegistry

    role = Role(args.role)
    if role == Role.CODE:
        if not args.version:
            print("ERROR: --version is required for --role code", file=sys.stderr)
            sys.exit(1)
        client_id = SHARED_CLIENT_ID
        release = args.version
    elif role == Role.LICENCE:
        if not args.client_id:
            print("ERROR: --client-id is required for --role licence", file=sys.stderr)
            sys.exit(1)
        client_id = args.client_id
        release = None
    else:
        print(f"ERROR: licgen new-leaf does not mint role={role.value} (Phase C)", file=sys.stderr)
        sys.exit(1)

    registry = KeyRegistry(registry_path)
    anchor = registry.get_anchor(args.master_anchor_id)
    if not anchor.backend_ref.startswith("pem:"):
        print("ERROR: master anchor backend is not PEM — no live PIV/KMS session in this environment", file=sys.stderr)
        sys.exit(1)

    master_passphrase = keygen._resolve_master_passphrase()
    master_key_path = Path(args.master_key) if args.master_key else Path(anchor.backend_ref[len("pem:"):])
    master_private_key = keygen._load_private_key_encrypted(master_key_path, master_passphrase)

    leaf_passphrase = keygen._resolve_leaf_passphrase()
    serial = args.serial or f"{role.value}-{release or client_id}-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"

    leaf_private_key, leaf_cert, leaf_cert_sig = keygen.mint_leaf(
        role=role,
        client_id=client_id,
        release=release,
        serial=serial,
        window_days=args.window_days,
        master_backend="pem",
        master_private_key=master_private_key,
        org_domain=args.org_domain,
    )

    name_prefix = f"{role.value}-{release or client_id}-{serial}".replace("/", "_")
    priv_path = keys_dir / f"{name_prefix}_private.pem"
    cert_path = keys_dir / f"{name_prefix}_leaf_cert.json"
    sig_path = keys_dir / f"{name_prefix}_leaf_cert.sig.b64"
    if priv_path.exists() and not args.force:
        print(f"ERROR: {priv_path} already exists. Use --force to overwrite.", file=sys.stderr)
        sys.exit(1)

    keygen._write_private_key_encrypted(priv_path, leaf_private_key, leaf_passphrase)
    cert_path.write_text(json.dumps(leaf_cert.to_canonical_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(cert_path, 0o644)
    import base64

    sig_b64 = base64.b64encode(leaf_cert_sig).decode("ascii")
    sig_path.write_text(sig_b64 + "\n", encoding="utf-8")
    os.chmod(sig_path, 0o644)

    key_id = f"{role.value}:{release or client_id}:{serial}"
    registry.add_key(
        KeyRecord(
            key_id=key_id,
            role=role,
            client_id=client_id,
            release=release,
            public_key_pem=leaf_cert.leaf_pubkey_pem,
            leaf_cert=leaf_cert,
            leaf_cert_sig_b64=sig_b64,
            not_before=leaf_cert.not_before,
            not_after=leaf_cert.not_after,
            serial=serial,
            private_key_backend_ref=f"pem:{priv_path}",
            org_domain=args.org_domain,
        )
    )
    print(f"LEAF MINTED  role={role.value} client_id={client_id} release={release} serial={serial}  key_id={key_id}")
    print(f"  private key : {priv_path}")
    print(f"  leaf_cert   : {cert_path}")
    print(f"  leaf_cert_sig: {sig_path}")


# ---------------------------------------------------------------------------
# anchor-set emit
# ---------------------------------------------------------------------------

def _cmd_anchor_set_emit(args: argparse.Namespace) -> None:
    from yashigani.licensing.chain.registry import KeyRegistry

    _keys_dir, registry_path = _resolve_channel_dirs(args)
    registry = KeyRegistry(registry_path)
    out = registry.emit_current_anchor_set_json()
    if args.out:
        Path(args.out).write_text(out, encoding="utf-8")
        print(f"Anchor set ({len(registry.emit_current_anchor_set())} active/retiring) written to {args.out}")
    else:
        print(out)


def _cmd_anchor_new(args: argparse.Namespace) -> None:
    import keygen

    keys_dir, registry_path = _resolve_channel_dirs(args)
    keys_dir.mkdir(parents=True, exist_ok=True)

    from yashigani.licensing.chain.algorithms import Alg
    from yashigani.licensing.chain.anchors import AnchorStatus
    from yashigani.licensing.chain.registry import KeyRegistry, MasterAnchorRecord

    registry = KeyRegistry(registry_path)
    passphrase = keygen._resolve_master_passphrase()
    priv_path = keys_dir / "master_private.pem"
    pub_path = keys_dir / "master_public.pem"
    if priv_path.exists() and not args.force:
        print(f"ERROR: {priv_path} already exists. Use --force to overwrite.", file=sys.stderr)
        sys.exit(1)
    master_key = keygen._generate_p384_keypair()
    keygen._write_private_key_encrypted(priv_path, master_key, passphrase)
    pub_pem = keygen._pubkey_pem(master_key)
    pub_path.write_text(pub_pem, encoding="utf-8")
    os.chmod(pub_path, 0o644)

    registry.add_anchor(
        MasterAnchorRecord(
            anchor_id=args.anchor_id,
            pubkey_pem=pub_pem,
            alg=Alg.ECDSA_P384_SHA384,
            status=AnchorStatus.ACTIVE,
            added=datetime.now(timezone.utc),
            backend_ref=f"pem:{priv_path}",
            note=args.note,
        )
    )
    print(f"MASTER ANCHOR {args.anchor_id} REGISTERED — {priv_path}")


def _cmd_anchor_mark(args: argparse.Namespace) -> None:
    from yashigani.licensing.chain.registry import KeyRegistry

    _keys_dir, registry_path = _resolve_channel_dirs(args)
    registry = KeyRegistry(registry_path)
    if args.mark == "retiring":
        registry.mark_anchor_retiring(args.anchor_id)
    elif args.mark == "retired":
        registry.mark_anchor_retired(args.anchor_id)
    print(f"Anchor {args.anchor_id} marked {args.mark}")


# ---------------------------------------------------------------------------
# sign-build
# ---------------------------------------------------------------------------

def _cmd_sign_build(args: argparse.Namespace) -> None:
    from yashigani.licensing.chain.registry import KeyRegistry

    keys_dir, registry_path = _resolve_channel_dirs(args)
    registry = KeyRegistry(registry_path)

    code_key = registry.active_code_leaf_for_release(args.version)
    if code_key is None:
        print(
            f"ERROR: no active CODE leaf registered for release {args.version!r}. "
            f"Run `licgen new-leaf --role code --version {args.version}` first "
            f"(or `licgen release`).",
            file=sys.stderr,
        )
        sys.exit(1)
    if not code_key.private_key_backend_ref.startswith("pem:"):
        print("ERROR: code leaf backend is not PEM — no live PIV/KMS session in this environment", file=sys.stderr)
        sys.exit(1)
    code_leaf_key_path = Path(code_key.private_key_backend_ref[len("pem:"):])

    # Locate the cert/sig files written alongside the private key by new-leaf.
    name_prefix = code_leaf_key_path.name[: -len("_private.pem")]
    cert_path = keys_dir / f"{name_prefix}_leaf_cert.json"
    sig_path = keys_dir / f"{name_prefix}_leaf_cert.sig.b64"
    for p in (code_leaf_key_path, cert_path, sig_path):
        if not p.exists():
            print(f"ERROR: expected build-embed artefact not found: {p}", file=sys.stderr)
            sys.exit(1)

    anchor_set_path = keys_dir / "anchor_set.json"
    anchor_set_path.write_text(registry.emit_current_anchor_set_json(), encoding="utf-8")

    env = dict(os.environ)
    env["CODE_LEAF_KEY_PATH"] = str(code_leaf_key_path)
    env["CODE_LEAF_CERT_PATH"] = str(cert_path)
    env["CODE_LEAF_CERT_SIG_PATH"] = str(sig_path)
    env["MASTER_ANCHOR_SET_PATH"] = str(anchor_set_path)
    if args.src_root:
        env["SRC_ROOT"] = args.src_root
    if args.kill_list:
        env["KILL_LIST_PATH"] = args.kill_list
    if args.client_domain_registry:
        env["CLIENT_DOMAIN_REGISTRY_PATH"] = args.client_domain_registry

    inject_script = _repo_root() / "scripts" / "inject_hashes.sh"
    print(f"Running {inject_script} for release {args.version}...")
    result = subprocess.run(["bash", str(inject_script)], env=env)
    if result.returncode != 0:
        print("ERROR: inject_hashes.sh failed", file=sys.stderr)
        sys.exit(result.returncode)
    print(f"sign-build complete for release {args.version} (leaf key_id={code_key.key_id})")


# ---------------------------------------------------------------------------
# issue
# ---------------------------------------------------------------------------

def _cmd_issue(args: argparse.Namespace) -> None:
    from yashigani.licensing.chain.registry import KeyRegistry

    keys_dir, registry_path = _resolve_channel_dirs(args)
    registry = KeyRegistry(registry_path)

    licence_key = registry.active_licence_leaf_for_client(args.client_id)
    if licence_key is None:
        print(
            f"ERROR: no active LICENCE leaf registered for client_id={args.client_id!r}. "
            f"Run `licgen new-leaf --role licence --client-id {args.client_id} "
            f"--org-domain <domain>` first (client onboarding).",
            file=sys.stderr,
        )
        sys.exit(1)
    if not licence_key.private_key_backend_ref.startswith("pem:"):
        print("ERROR: licence leaf backend is not PEM — no live PIV/KMS session in this environment", file=sys.stderr)
        sys.exit(1)
    licence_key_path = Path(licence_key.private_key_backend_ref[len("pem:"):])
    name_prefix = licence_key_path.name[: -len("_private.pem")]
    cert_path = keys_dir / f"{name_prefix}_leaf_cert.json"
    sig_path = keys_dir / f"{name_prefix}_leaf_cert.sig.b64"
    for p in (licence_key_path, cert_path, sig_path):
        if not p.exists():
            print(f"ERROR: expected licence-leaf artefact not found: {p}", file=sys.stderr)
            sys.exit(1)

    # SEAM: Tom's scripts/sign_license.py — imported directly (§9: "Tom:
    # sign_license.py -> v5 (leaf-sign + carry leaf_cert); wire into licgen
    # issue"). build_payload_v5()/sign_licence_file() are the exact
    # functions confirmed present in that file.
    import sign_license  # scripts/sign_license.py

    expires_at = args.expires_at
    if not expires_at:
        days = args.expires_days if args.expires_days is not None else 365
        expires_at = (datetime.now(timezone.utc) + timedelta(days=days)).isoformat()

    licence_serial = args.licence_serial or f"lic-{args.client_id}-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"

    payload = sign_license.build_payload_v5(
        tier=args.tier,
        org_domain=args.domain,
        client_id=args.client_id,
        licence_serial=licence_serial,
        expires_at=expires_at,
        max_agents=args.max_agents,
        max_end_users=args.max_end_users,
        max_admin_seats=args.max_admin_seats,
        max_orgs=args.max_orgs,
        features=args.features,
    )

    passphrase = os.environ.get("YASHIGANI_LICENCE_KEY_PASSPHRASE")
    passphrase_bytes = passphrase.rstrip("\n").encode("utf-8") if passphrase else None

    wire = sign_license.sign_licence_file(
        payload=payload,
        licence_key_pem_path=str(licence_key_path),
        leaf_cert_json_path=str(cert_path),
        leaf_cert_sig_b64=sig_path.read_text(encoding="utf-8").strip(),
        licence_key_passphrase=passphrase_bytes,
    )

    out_path = Path(args.out) if args.out else Path(f"{args.client_id}-{licence_serial}.ysg")
    out_path.write_text(wire, encoding="utf-8")
    print(f"Issued v5 licence: {out_path}")
    print(f"  tier={args.tier} org_domain={args.domain} client_id={args.client_id} "
          f"licence_serial={licence_serial} expires_at={expires_at}")


# ---------------------------------------------------------------------------
# release (new-leaf role=code + sign-build)
# ---------------------------------------------------------------------------

def _cmd_release(args: argparse.Namespace) -> None:
    new_leaf_args = argparse.Namespace(**vars(args))
    new_leaf_args.role = "code"
    new_leaf_args.client_id = None
    new_leaf_args.org_domain = None
    new_leaf_args.serial = args.serial
    _cmd_new_leaf(new_leaf_args)

    sign_build_args = argparse.Namespace(**vars(args))
    _cmd_sign_build(sign_build_args)


# ---------------------------------------------------------------------------
# revoke (§6 — semantics-aware kill-list writes)
# ---------------------------------------------------------------------------

def _load_kill_list_entries(path: Path) -> list[dict]:
    if not path.exists():
        return []
    raw = path.read_text(encoding="utf-8").strip()
    if not raw:
        return []
    return json.loads(raw)


def _save_kill_list_entries(path: Path, entries: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(entries, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _cmd_revoke(args: argparse.Namespace) -> None:
    from yashigani.licensing.chain.kill_list import KillListEntry, KillListSemantics
    from yashigani.licensing.chain.registry import KeyRegistry

    _keys_dir, registry_path = _resolve_channel_dirs(args)
    kill_list_path = Path(args.kill_list) if args.kill_list else _keys_dir.parent / "kill_list.json"

    provided = [x for x in (args.leaf, args.licence, args.client) if x]
    if len(provided) != 1:
        print("ERROR: exactly one of --leaf / --licence / --client must be given", file=sys.stderr)
        sys.exit(1)

    now = datetime.now(timezone.utc)
    entries = _load_kill_list_entries(kill_list_path)
    new_entries: list[KillListEntry] = []

    if args.leaf:
        new_entries.append(
            KillListEntry(namespace="leaf", identifier=args.leaf, revoked_at=now,
                          semantics=KillListSemantics.IMMEDIATE, reason=args.reason)
        )
    elif args.licence:
        new_entries.append(
            KillListEntry(namespace="licence", identifier=args.licence, revoked_at=now,
                          semantics=KillListSemantics.IMMEDIATE, reason=args.reason)
        )
    else:  # args.client
        # §6.1: revoking a client kills BOTH its leaves in one kill-list
        # write, but with DIFFERENT semantics per leaf type (Laura R5-F3) —
        # the licence-leaf entry is IMMEDIATE (feature access stops now);
        # the audit-leaf entry is FORWARD_ONLY (past compliance evidence
        # must keep verifying forever, even though role=audit leaves are
        # Phase C / not minted yet in this codebase — the kill-list schema
        # already supports it per Tom's kill_list.py docstring, so this
        # entry is inert-but-correct today and needs no future format
        # change when §3.4.1 lands).
        new_entries.append(
            KillListEntry(namespace="client", identifier=args.client, revoked_at=now,
                          semantics=KillListSemantics.IMMEDIATE, reason=args.reason)
        )
        new_entries.append(
            KillListEntry(namespace="client", identifier=args.client, revoked_at=now,
                          semantics=KillListSemantics.FORWARD_ONLY, reason=args.reason)
        )

        # Registry bookkeeping — mark every key for this client_id revoked
        # (registry.py docstring: this is bookkeeping only, independent of
        # the kill-list write above, which is what builds actually embed).
        try:
            registry = KeyRegistry(registry_path)
            for k in registry.list_keys(client_id=args.client):
                registry.mark_key_revoked(k.key_id, reason=args.reason)
        except Exception as exc:  # pragma: no cover - registry may not exist yet
            print(f"WARNING: could not update registry bookkeeping for client {args.client}: {exc}", file=sys.stderr)

    entries.extend(e.to_canonical_dict() for e in new_entries)
    _save_kill_list_entries(kill_list_path, entries)

    for e in new_entries:
        print(f"REVOKED: namespace={e.namespace} identifier={e.identifier} semantics={e.semantics.value} revoked_at={e.revoked_at.isoformat()}")
    print(f"Kill-list written to {kill_list_path} ({len(entries)} total entries)")


# ---------------------------------------------------------------------------
# argparse wiring
# ---------------------------------------------------------------------------

def _add_channel_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--channel", choices=["demo", "prod"], default="demo")
    p.add_argument("--keys-dir", default=None)
    p.add_argument("--registry", default=None)


def main() -> None:
    parser = argparse.ArgumentParser(description="licgen — Yashigani v2 unified licence/build tool (§7)")
    sub = parser.add_subparsers(dest="command", required=True)

    p_new_leaf = sub.add_parser("new-leaf", help="Mint + master-certify a new leaf (code or licence)")
    _add_channel_args(p_new_leaf)
    p_new_leaf.add_argument("--role", choices=["code", "licence"], required=True)
    p_new_leaf.add_argument("--version", default=None, help="Required for --role code")
    p_new_leaf.add_argument("--client-id", default=None, help="Required for --role licence")
    p_new_leaf.add_argument("--org-domain", default=None)
    p_new_leaf.add_argument("--serial", default=None)
    p_new_leaf.add_argument("--window-days", type=int, default=30)
    p_new_leaf.add_argument("--master-anchor-id", required=True)
    p_new_leaf.add_argument("--master-key", default=None)
    p_new_leaf.add_argument("--force", action="store_true")
    p_new_leaf.set_defaults(func=_cmd_new_leaf)

    p_sign_build = sub.add_parser("sign-build", help="Sign the hash-bundle + embed the chain into _integrity.py")
    _add_channel_args(p_sign_build)
    p_sign_build.add_argument("--version", required=True)
    p_sign_build.add_argument("--src-root", default=None)
    p_sign_build.add_argument("--kill-list", default=None)
    p_sign_build.add_argument("--client-domain-registry", default=None)
    p_sign_build.set_defaults(func=_cmd_sign_build)

    p_issue = sub.add_parser("issue", help="Sign a v5 licence for an onboarded client")
    _add_channel_args(p_issue)
    p_issue.add_argument("--domain", required=True)
    p_issue.add_argument("--tier", required=True)
    p_issue.add_argument("--client-id", required=True)
    p_issue.add_argument("--licence-serial", default=None)
    p_issue.add_argument("--expires-at", default=None, help="ISO-8601; default: now + --expires-days")
    p_issue.add_argument("--expires-days", type=int, default=None, help="Default 365 (demo: pass 14-30, §7)")
    p_issue.add_argument("--max-agents", type=int, default=None)
    p_issue.add_argument("--max-end-users", type=int, default=None)
    p_issue.add_argument("--max-admin-seats", type=int, default=None)
    p_issue.add_argument("--max-orgs", type=int, default=None)
    p_issue.add_argument("--features", nargs="*", default=None)
    p_issue.add_argument("--out", default=None)
    p_issue.set_defaults(func=_cmd_issue)

    p_release = sub.add_parser("release", help="new-leaf(role=code) + sign-build, per-release convenience")
    _add_channel_args(p_release)
    p_release.add_argument("--version", required=True)
    p_release.add_argument("--window-days", type=int, default=30)
    p_release.add_argument("--master-anchor-id", required=True)
    p_release.add_argument("--master-key", default=None)
    p_release.add_argument("--serial", default=None)
    p_release.add_argument("--force", action="store_true")
    p_release.add_argument("--src-root", default=None)
    p_release.add_argument("--kill-list", default=None)
    p_release.add_argument("--client-domain-registry", default=None)
    p_release.set_defaults(func=_cmd_release)

    p_revoke = sub.add_parser("revoke", help="Write a semantics-aware kill-list entry (§6)")
    _add_channel_args(p_revoke)
    grp = p_revoke.add_mutually_exclusive_group(required=True)
    grp.add_argument("--leaf", metavar="SERIAL")
    grp.add_argument("--licence", metavar="LICENCE_SERIAL")
    grp.add_argument("--client", metavar="CLIENT_ID")
    p_revoke.add_argument("--reason", default=None)
    p_revoke.add_argument("--kill-list", dest="kill_list", default=None)
    p_revoke.set_defaults(func=_cmd_revoke)

    p_anchor = sub.add_parser("anchor-set", help="Master trust-anchor SET operations")
    sub_anchor = p_anchor.add_subparsers(dest="anchor_command", required=True)

    p_anchor_new = sub_anchor.add_parser("new", help="Mint a new master anchor")
    _add_channel_args(p_anchor_new)
    p_anchor_new.add_argument("--anchor-id", required=True)
    p_anchor_new.add_argument("--force", action="store_true")
    p_anchor_new.add_argument("--note", default=None)
    p_anchor_new.set_defaults(func=_cmd_anchor_new)

    p_anchor_mark = sub_anchor.add_parser("mark", help="Mark an anchor retiring/retired")
    _add_channel_args(p_anchor_mark)
    p_anchor_mark.add_argument("--anchor-id", required=True)
    p_anchor_mark.add_argument("--mark", choices=["retiring", "retired"], required=True)
    p_anchor_mark.set_defaults(func=_cmd_anchor_mark)

    p_anchor_emit = sub_anchor.add_parser("emit", help="Emit the current anchor SET as JSON")
    _add_channel_args(p_anchor_emit)
    p_anchor_emit.add_argument("--out", default=None)
    p_anchor_emit.set_defaults(func=_cmd_anchor_set_emit)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
