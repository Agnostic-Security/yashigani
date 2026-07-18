<!-- Last-Updated: 2026-07-18 -->

# NOTICE — podman-compose-ysg

Per Petra's GPL-2.0 memo (`AgnosticSecurity/Legal/yashigani-podman-compose-
fork-gpl-memo-20260718.md`), §4.2, this notice covers the seven required
elements for the customer-facing third-party notice of this component.

1. **Component and fork identity.** `podman-compose-ysg`, version
   `1.5.0+ysg.1` — a first-party-patched fork of upstream `podman-compose`
   1.5.0 (https://github.com/containers/podman-compose), maintained by
   Agnostic Security Ltd.

2. **License.** Licensed entirely under **GPL-2.0-only** (GNU General Public
   License, Version 2, June 1991 — no "or later" clause). Full license text:
   [`LICENSE`](./LICENSE) in this directory.

3. **Upstream copyright preserved.** All upstream copyright notices and the
   "no warranty" disclaimer (GPL-2.0 §11–12) are preserved unmodified in
   [`podman_compose.py`](./podman_compose.py) and [`LICENSE`](./LICENSE).

4. **Agnostic Security Ltd modifications.** AS Ltd modified this work. Every
   modified file carries a "Modified by Agnostic Security Ltd, 2026-07-18"
   header at the point of change. The full change log, with dates and
   rationale for each of the 3 fixes, is [`CHANGES.agnostic.md`](./
   CHANGES.agnostic.md).

5. **Corresponding source.** The complete modified source is shipped
   **in this directory**, in the Yashigani distribution bundle (GPL-2.0
   §3(a) — the primary compliance mechanism for this fork; podman-compose is
   pure Python, so source and executable are the same text). A public git
   repository, as belt-and-braces corroboration of §3(a) (not itself the
   compliance mechanism), is pending a separate Tiago/Maxine publish-timing
   decision (Petra memo §5) — **not yet published** as of this build.

6. **The Yashigani proprietary EULA does NOT govern this component.** This
   fork is licensed solely under GPL-2.0-only. Agnostic Security Ltd's
   commercial/proprietary license terms for Yashigani apply only to
   Yashigani's own proprietary components and do not purport to add any
   restriction to this fork (GPL-2.0 §6).

7. **Not affiliated with, and not endorsed by, the Podman / `containers`
   project or Red Hat.** "Podman" and related marks belong to their
   respective owners; this fork's name (`podman-compose-ysg`) and version
   suffix (`+ysg.1`) are chosen specifically to avoid implying it is the
   official upstream project.

---

## Boundary note (GPL-2.0 §2 "mere aggregation")

This component is invoked by Yashigani's `install.sh` as a **standalone CLI**
via subprocess only (argv + compose file + exit code) — never imported,
never linked. Yashigani's proprietary code does not import
`podman_compose` and must never do so (Petra memo §2.3 — a hard "do not do
this" line). This fork lives in its own directory (`vendor/podman-compose-
ysg/`), never intermingled with proprietary source.
