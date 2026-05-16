# Last updated: 2026-05-16T00:00:00+00:00 (v2.23.4: ACS-RISK-026 — service_identities.yaml is now a symlink)
# Yashigani — top-level Makefile
#
# Primary target relevant to service identity manifest management:
#
#   sync-service-identities  — re-create symlink docker/ → helm/files/ (idempotent)
#   check-service-identities — verify the two copies have identical SHA-256 (CI gate)
#
# ACS-RISK-026 (2026-05-16): helm/yashigani/files/service_identities.yaml is now a
# symlink to ../../docker/service_identities.yaml.  Helm follows the symlink at
# template time (verified: `helm template` includes the content; see ACS-RISK-026 close
# notes).  sync-service-identities re-creates the symlink if it is ever replaced with
# a regular file (e.g. by git checkout on a host that doesn't support symlinks).
# The canonical source is docker/service_identities.yaml — edit only that file.
#
# See docs/development/service_identities.md for the full workflow.

.PHONY: sync-service-identities check-service-identities

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
