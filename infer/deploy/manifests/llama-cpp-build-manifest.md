# llama.cpp pinned-tag build manifest — per-backend

**Status:** TEMPLATE — tag/commit/digest are placeholders. OFFLINE AUTHORING ONLY per this
dispatch; no image was built, no tag was resolved against a live registry (Verification
Protocol #7 forbids guessing a version — there is no live network/registry access in this
authoring session). `scripts/resolve-and-pin-digests.sh` is the exact command sequence to run
**before the first live build**, on a rig, with Maxine/Tiago sign-off per the runtime
workaround / infra-gate rule.

## Pinned source

| Field | Value |
|---|---|
| Upstream repo | `https://github.com/ggml-org/llama.cpp` |
| Pinned ref | `${LLAMA_CPP_TAG}` — **PLACEHOLDER, must be resolved to a real tag/commit SHA before build.** Never build against `master`/`HEAD`. |
| Pinned commit SHA | `${LLAMA_CPP_COMMIT_SHA}` — filled by `resolve-and-pin-digests.sh`; the tag alone is not immutable (tags can move upstream — same reasoning as digest-pin vs tag-pin for base images below). |
| License | MIT — see `infer/NOTICE` / `infer/LICENSE`; vendored source lives under a `third_party/llama.cpp/` build context, never merged into `kuroshio`'s own source tree (Petra F1 boundary). |
| Reproducible build | `cmake -B build -DGGML_BACKEND_DL=OFF -DGGML_NATIVE=OFF <backend flags below> && cmake --build build --config Release -j$(nproc)` — `GGML_NATIVE=OFF` so the build is portable across the CI builder's CPU and the deploy target's CPU (a native-tuned build baked with `-march=native` on the CI box can crash with `SIGILL` on a deploy host with a narrower instruction set). |
| sha256 manifest | Generated at build time by `scripts/resolve-and-pin-digests.sh --emit-manifest`; committed alongside the signed git release tag (platform doc §3), never as a side-channel file. **Not generated this session — no build ran.** |

## Standing CVE gate (Captain finding #2 / Red Council C1)

Every re-pin of `LLAMA_CPP_COMMIT_SHA` MUST re-check the new commit against disclosed
GGUF-loader advisories (the CVE-2024-21836 heap-overflow/integer-overflow cluster and any
successor Huntr-reported bugs in `gguf.cpp` / `gguf_init_from_file`) **before** the pin lands.
This is a release-gate script requirement (`scripts/resolve-and-pin-digests.sh --cve-check`),
not a one-off note — the gate must run on every re-pin, not just the first.

## Per-backend build flags

| Backend | CMake flags | Base image role |
|---|---|---|
| `kuroshio-cuda` | `-DGGML_CUDA=ON -DCMAKE_CUDA_ARCHITECTURES=native-or-explicit-list` (explicit arch list recommended for reproducible multi-GPU-generation support, e.g. `75;80;86;89;90`) | build: CUDA devel image; runtime: CUDA runtime-only image (no devel/compiler toolchain shipped) |
| `kuroshio-rocm` | `-DGGML_HIP=ON -DAMDGPU_TARGETS=<explicit gfx list, e.g. gfx1030;gfx1100;gfx1101>` | build: ROCm dev image; runtime: same ROCm userspace runtime libs only (ROCm does not publish a slim runtime-only image the way CUDA does — rocBLAS/Tensile kernel blobs are inherently large; "lean" here means *lean relative to the fat multi-backend image*, not sub-1GB) |
| `kuroshio-vulkan` | `-DGGML_VULKAN=ON` (+ `glslc`/shaderc at build time to compile the Vulkan compute shaders) | build: Debian + Vulkan SDK headers/glslc; runtime: `libvulkan1` + loader only — the actual ICD (GPU driver) is host-mounted, never baked into the image |
| `kuroshio-cpu` | `-DGGML_BLAS=OFF -DGGML_NATIVE=OFF` + explicit `-DGGML_AVX2=ON -DGGML_FMA=ON` baseline (portable baseline; runtime CPU-feature dispatch via `GGML_CPU_ALL_VARIANTS=ON` is preferred if the pinned tag supports it, avoiding a `SIGILL` on older CPUs while still using AVX2/AVX512 where available) | universal fallback; also the Mac-in-VM / M-k8s dev-cell image |

## Multi-arch

`kuroshio-vulkan` and `kuroshio-cpu` are built as OCI image indexes (`docker buildx build --platform
linux/amd64,linux/arm64`) so the same tag resolves per node arch (platform doc §3). `kuroshio-cuda`
and `kuroshio-rocm` are `linux/amd64` only for v1 (arm64+CUDA/Jetson deferred per platform doc §15).

## Deferred to a live build (explicit — nothing here is guessed)

1. Resolving `LLAMA_CPP_TAG` → `LLAMA_CPP_COMMIT_SHA` against the real upstream repo.
2. Resolving every base-image tag → digest (`docker manifest inspect` / `skopeo inspect`) —
   see `scripts/resolve-and-pin-digests.sh`. Placeholders below are NOT verified digests.
3. Generating the sha256 build-flag manifest and committing it into the signed release tag.
4. Running the standing CVE gate against the resolved commit.
5. Confirming CUDA_ARCHITECTURES / AMDGPU_TARGETS against the actual target fleet's GPU
   generations (the lists above are representative, not confirmed against a real deploy target).
