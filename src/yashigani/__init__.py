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
# Last updated: 2026-06-26T00:00:00+01:00 (v3.0.1: post-GA hardening bump — SSRF/installer/risk-register)

__version__ = "3.1.2"
