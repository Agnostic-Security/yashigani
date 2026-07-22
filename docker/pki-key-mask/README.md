# PKI key mask (FINDING-V412-F1)

`denied.mask` is a git-tracked, permanently-empty (0 byte) placeholder file. It is
**not** a secret — it never contains key material and is never written to at
install/runtime.

It exists solely to be bind-mounted, read-only, OVER the CA private-key paths
(`/run/secrets/ca_root.key`, `/run/secrets/ca_intermediate.key`) for every
compose service that does not need to read those keys. Docker/Podman apply a
more-specific single-file bind mount after a broader directory mount for the
same target path, so a service that lists both

```yaml
- ./secrets:/run/secrets:ro
- ./docker/pki-key-mask/denied.mask:/run/secrets/ca_root.key:ro
```

sees an empty file at `/run/secrets/ca_root.key`, never the real private key
underneath (the real key still lives at `docker/secrets/ca_root.key` on the
host — unchanged — for `install.sh` bootstrap/rotate flows and for the one
service that legitimately signs, `backoffice`, which keeps the real
`ca_intermediate.key`).

See `FINDING-V412-DOCKER-CLEANROUND-BATCH.md` F1 and the mount-site comments in
`docker/docker-compose.yml` for the full rationale.
