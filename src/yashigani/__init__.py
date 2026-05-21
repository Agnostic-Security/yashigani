"""
Yashigani — Security enforcement gateway for MCP servers and agentic AI systems.

Modules:
  yashigani.gateway     — Reverse proxy with inspection and OPA policy enforcement
  yashigani.backoffice  — Admin control plane (local auth, port 8443)
  yashigani.inspection  — Prompt injection classifier and sanitization pipeline
  yashigani.chs         — Credential Handle Service (opaque UUID handles)
  yashigani.kms         — KSM provider abstraction (Keeper, AWS, Azure, GCP, Docker)
  yashigani.audit       — Hybrid audit log (volume + multi-SIEM forwarding)
  yashigani.auth        — Local auth: Argon2id passwords, TOTP, session store
  yashigani.sso         — SAMLv2 and OIDC identity provider integration
"""
# Last updated: 2026-05-16T00:00:00+01:00 (v2.23.4: align __version__ with pyproject.toml — pre-existing drift from be38110)

__version__ = "2.23.4"
