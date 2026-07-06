"""
Yashigani Manifest — Universal Ring-fence Onboarding (v2.25.0 P1 W1+W3+P3).

Package layout:
  parser.py     — M1/M2/M3 safe YAML parser + sandboxed subprocess
  schema.py     — M8 JSON-Schema validator (external $ref disabled)
  linter.py     — M5/M6/M7/N1/N2/C1/C3/P2/FS1 semantic lint rules + resolve_spiffe_uri
  signatures.py — M7 signature verification (cosign + RSA-PSS FIPS split)
  cli.py        — yashigani validate CLI entrypoint (K3 human-quality errors)
  codegen.py    — W3 Shape A + P3 Shape C artifact generators
  schemas/      — bundled JSON-Schema bundle (agent-manifest-v1alpha1.schema.json)
  keys/         — bundled cosign public key (manifest-signing.pub)

Entry points:
  parse_manifest(source)               — M1/M2/M3 parse
  validate_manifest(parsed, ...)       — M5/M6/M7/M8/N1/N2/C1/C3/P2/FS1 lint
  verify_manifest_signature(...)       — M7 crypto verification
  assert_schema_valid(parsed)          — M8 schema validation only
  resolve_spiffe_uri(parsed)           — canonical SPIFFE URI resolver (P1-F-01)
  CodegenEngine(parsed, runtime)       — W3 Shape A artifact generator
  CodegenEngineShapeC(parsed, runtime) — P3 Shape C (stdio MCP-server) artifact generator
  CodegenError                         — codegen failure type
  reset_codegen_registry()             — C3 duplicate-pair registry reset
  seed_mesh_ports_from_descriptors(d)  — C1 mesh-port registry seed from durable state
  resolve_egress_forwarder_port(p)     — C2 fixed egress-forwarder port (9400, overridable)
  MCP_EGRESS_FORWARDER_PORT            — C2 forwarder port constant (outside 9500-9899)
  is_shape_c(parsed)                   — detect if manifest is Shape-C

Last updated: 2026-07-06T00:00:00+00:00
"""
from yashigani.manifest.parser import parse_manifest, ManifestParseError
from yashigani.manifest.schema import validate_schema, assert_schema_valid, ManifestSchemaError
from yashigani.manifest.linter import validate_manifest, LintResult, LintError, resolve_spiffe_uri
from yashigani.manifest.signatures import verify_manifest_signature, ManifestSignatureError
from yashigani.manifest.codegen import (
    MCP_EGRESS_FORWARDER_PORT,
    CodegenEngine,
    CodegenEngineShapeC,
    CodegenError,
    reset_codegen_registry,
    resolve_egress_forwarder_port,
    seed_mesh_ports_from_descriptors,
    _is_shape_c as is_shape_c,
)

__all__ = [
    "parse_manifest",
    "ManifestParseError",
    "validate_schema",
    "assert_schema_valid",
    "ManifestSchemaError",
    "validate_manifest",
    "LintResult",
    "LintError",
    "verify_manifest_signature",
    "ManifestSignatureError",
    "resolve_spiffe_uri",
    "CodegenEngine",
    "CodegenEngineShapeC",
    "CodegenError",
    "reset_codegen_registry",
    "seed_mesh_ports_from_descriptors",
    "resolve_egress_forwarder_port",
    "MCP_EGRESS_FORWARDER_PORT",
    "is_shape_c",
]
