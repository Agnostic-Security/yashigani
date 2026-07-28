# Last updated: 2026-06-15T00:00:00+00:00 (feat/licence-hardening: MC-02 counter-key rotation gate)
# Yashigani — top-level Makefile
#
# Targets:
#
#   sync-service-identities       — re-create symlink docker/ → helm/files/ (idempotent)
#   check-service-identities      — verify the two copies have identical SHA-256 (CI gate)
#   check-counter-key-rotation    — MC-02: fail if COUNTER_PUBLIC_KEY_PEM in _integrity.py
#                                   is identical to the previous release tag's value (treadmill gate)
#
# YSG-RISK-026 (2026-05-16): helm/yashigani/files/service_identities.yaml is now a
# symlink to ../../docker/service_identities.yaml.  Helm follows the symlink at
# template time (verified: `helm template` includes the content; see YSG-RISK-026 close
# notes).  sync-service-identities re-creates the symlink if it is ever replaced with
# a regular file (e.g. by git checkout on a host that doesn't support symlinks).
# The canonical source is docker/service_identities.yaml — edit only that file.
#
# See docs/development/service_identities.md for the full workflow.

.PHONY: sync-service-identities check-service-identities check-counter-key-rotation

CANONICAL := docker/service_identities.yaml
HELM_COPY  := helm/yashigani/files/service_identities.yaml

## sync-service-identities: (re-)create the symlink from helm/files/ to docker/ canonical.
## Idempotent — safe to run even if the symlink already exists.
## Fall back to a plain copy if the filesystem does not support symlinks.
sync-service-identities:
	@echo "[sync] Ensuring $(HELM_COPY) → $(CANONICAL) (symlink)"
	@if [ -L "$(HELM_COPY)" ] && [ -e "$(HELM_COPY)" ]; then \
	   echo "[sync] Symlink already correct — nothing to do."; \
	 elif ln -sf "../../../$(CANONICAL)" "$(HELM_COPY)" 2>/dev/null; then \
	   echo "[sync] Symlink created: $(HELM_COPY) → $(CANONICAL)"; \
	 else \
	   echo "[sync] Symlink not supported on this filesystem — falling back to copy."; \
	   cp -f "$(CANONICAL)" "$(HELM_COPY)"; \
	   echo "[sync] Copy done. Verify with: make check-service-identities"; \
	 fi

## check-service-identities: fail if canonical and helm copy have diverged.
## This is the same assertion run by tests/contracts/test_service_identities_sha.py.
check-service-identities:
	@CANONICAL_SHA=$$(shasum -a 256 "$(CANONICAL)"  | awk '{print $$1}'); \
	 HELM_SHA=$$(shasum -a 256 "$(HELM_COPY)" | awk '{print $$1}'); \
	 if [ "$$CANONICAL_SHA" != "$$HELM_SHA" ]; then \
	   echo "DRIFT DETECTED — service_identities.yaml copies have diverged."; \
	   echo "  Canonical ($(CANONICAL)):  $$CANONICAL_SHA"; \
	   echo "  Helm copy  ($(HELM_COPY)): $$HELM_SHA"; \
	   echo "  Fix: edit $(CANONICAL), then run: make sync-service-identities"; \
	   exit 1; \
	 fi
	@echo "OK — service_identities.yaml copies are identical."

# ---------------------------------------------------------------------------
# MC-02 (Laura / 2026-06-15): Counter key rotation gate (treadmill enforcement)
#
# Fails the build if COUNTER_PUBLIC_KEY_PEM in _integrity.py is identical to
# the value embedded in the previous release tag.  This enforces per-release
# counter key rotation and prevents the treadmill from silently stalling.
#
# Usage (run before tagging a release):
#   make check-counter-key-rotation
#
# Override the reference tag (default: most recent vX.Y.Z annotated tag):
#   make check-counter-key-rotation PREV_RELEASE_TAG=v2.25.4
#
# How it works:
#   1. Determines the previous release tag (or uses PREV_RELEASE_TAG env/arg).
#   2. Extracts COUNTER_PUBLIC_KEY_PEM from that tag's _integrity.py.
#   3. Extracts COUNTER_PUBLIC_KEY_PEM from the current working tree.
#   4. Fails if the two values are byte-identical.
#
# A placeholder value ("PLACEHOLDER_YASHIGANI_INTEGRITY") in either side
# is also treated as a failure — a placeholder means the build pipeline has
# not run, which is a separate error that would mask a real rotation check.
# ---------------------------------------------------------------------------

INTEGRITY_PY_RELPATH := src/yashigani/licensing/_integrity.py
PREV_RELEASE_TAG ?= $(shell git tag --sort=-version:refname | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$$' | head -1)

## check-counter-key-rotation: MC-02 treadmill gate — fail if counter key unchanged since last release.
## Run before every release tag. Override reference tag: make check-counter-key-rotation PREV_RELEASE_TAG=v2.25.4
check-counter-key-rotation:
	@python3 scripts/check_counter_key_rotation.py "$(PREV_RELEASE_TAG)" "$(INTEGRITY_PY_RELPATH)"
