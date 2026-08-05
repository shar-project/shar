# Rendering calibration

`npm run bench:render:browser` measures the protocol default through the CPU,
WebGPU, WebGL2, and real CSS executors in Chromium. Its default mode explicitly
selects SwiftShader for reproducible software-renderer conformance evidence.
Run with `SHAR_BENCH_GPU_MODE=physical` on each reference device for GA
evidence. `npm run bench:render:llvmpipe` instead runs headed Chromium under
virtual X in the digest-pinned Playwright container, forces Mesa llvmpipe, and
fails if the GPU process silently substitutes SwiftShader or hardware.

The benchmark includes executor/device setup in every sample, rejects relevant
browser console errors, requires byte-identical digests, requires at least one
million predicates per round, confirms CSS completion, and enforces a 10× local
accelerated/CSS separation. A privileged benchmark-only CDP query records the
actual Chromium GPU process and driver; the widget never collects those fields.
Physical mode disables software rasterization and fails unless hardware is
observed. SwiftShader and llvmpipe modes require that exact software renderer,
not merely any non-hardware backend. The structured result is retained even
when a gate fails. A software result can never set a physical-device
`ga_scope_pass`.

The same runner can coordinate a browser on another device without installing
Node or Playwright there. Set `SHAR_BENCH_CDP_ENDPOINT` to a loopback-forwarded
CDP endpoint, `SHAR_BENCH_PORT` to the fixed local harness port,
`SHAR_BENCH_PAGE_BASE` to the origin visible to the browser, and
`SHAR_BENCH_EXECUTION_ENVIRONMENT` to a bounded JSON description of the actual
execution host. `SHAR_BENCH_PAGE_TRANSPORT` records whether the page arrived
through an SSH reverse tunnel, ADB reverse forwarding, or another isolated
transport. Remote mode refuses to run without explicit execution-host metadata
so the coordinator's CPU and OS cannot be mislabeled as the measured device.
Keep both the CDP and harness endpoints on loopback or an authenticated tunnel;
never expose a debugging port publicly.

Retained local evidence:

- `results/local-browser-calibration.json`: explicitly forced and observed
  SwiftShader software rendering.
- `results/local-intel-iris-xe-calibration.json`: observed Intel Iris Xe ADL
  GT2 through Mesa/ANGLE Vulkan with software rasterization disabled.
- `results/local-llvmpipe-calibration.json`: observed Mesa llvmpipe through
  ANGLE OpenGL in the digest-pinned Playwright 1.62.1 container.
- `results/local-amd-steam-deck-calibration.json`: observed physical AMD Van
  Gogh through the Steam Deck's Flatpak Chromium and RADV/ANGLE Vulkan, driven
  over loopback-only SSH tunnels.
- `results/local-android-mali-g710-calibration.json`: observed physical Arm
  Mali-G710 through Chrome on a Pixel 7 Pro, driven through temporary ADB CDP
  and reverse-loopback forwards.

These artifacts cover multiple local and remote hosts but only a small device
and browser sample. They do not substitute for the remaining vendor, mobile,
operating-system, energy, or shipping-version matrix.

On a Linux host with a DRM render node, run the full Chromium suite with
software fallback disabled using `npm run test:browser:physical`. This project
is opt-in so portable CI and machines without a GPU do not silently replace or
skip required hardware evidence.
