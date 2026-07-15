# Copilot Instructions for Meshtastic Firmware (JF-Pieper)

## Orientation
- Fork of meshtastic/firmware focused on Heltec Mesh Node T114 (`HELTEC_MESH_NODE_T114` guard); keep upstream merges intact via workflows under `.github/workflows`.
- PlatformIO project with shared `platformio.ini` that pulls in `arch/*/*.ini` and `variants/*/platformio.ini`; default env `tbeam`, T114 env extends `nrf52840_base`.
- Core directories: `src/` (firmware), `arch/` (MCU glue), `variants/` (board pinouts + build flags), `boards/*.json` (board meta), `mesh/` (routing/services), `modules/` (feature threads).

## Architecture & Patterns
- `src/main.cpp` boots hardware, runs detection helpers in `detect/`, and calls `setupModules()` (`src/modules/Modules.cpp`) to spawn `concurrency::OSThread`-derived modules with a `runOnce()` loop.
- Mesh messaging flows through `MeshService` → `Router`/`MeshRadio`; packets are `meshtastic_MeshPacket` protobufs generated in `src/mesh/generated`.
- Configuration lives in nanopb structs (`config`, `moduleConfig`); default timings come from `mesh/Default.*` helpers like `Default::getConfiguredOrDefaultMs`.
- Board/UI special cases must stay under the Heltec macro; e.g. `graphics/Screen.cpp`, `platform/nrf52/main-nrf52.cpp`, and module code that checks the `HELTEC_MESH_NODE_T114` guard.

## Build & Flash Workflow
- Primary build: `pio run --environment heltec-mesh-node-t114`; artifacts (`firmware.uf2`, `.hex`, `.elf`) land in `.pio/build/heltec-mesh-node-t114/`.
- Clean rebuild: `pio run --target fullclean --environment heltec-mesh-node-t114`; use `pio device monitor -b 115200` for logs.
- Post-build UF2 packaging is driven by `bin/platformio-custom.py`, which also injects version info from `version.properties` and user flags from `userPrefs.jsonc`.
- CI mirrors these steps (`.github/workflows/auto-build-t114.yml`); keep command compatibility when modifying scripts.

## Testing & Validation
- Hardware E2E tests live in `meshtestic/`; run `pnpm i` then `pnpm run test` with devices connected.
- Static analysis via `pio check --environment heltec-mesh-node-t114` (configured for `cppcheck`).
- Protobuf changes require regenerating generated sources with `bin/regen-protos.sh` (or `.bat` on Windows) followed by rebuilding.

## Extending the Firmware
- Add board features by editing `boards/<board>.json`, `variants/<board>/` sources, and optional `src/platform/extra_variants/` hooks (`lateInitVariant()`).
- Shared utilities: `Throttle::isWithinTimespanMs` for rate limiting, `LOG_*` macros for diagnostics, and `Default::*` for adapting broadcast cadences to network congestion.
- When touching display or power logic, review Heltec-specific constraints in `README.md` and `CHANGES.md` to avoid reintroducing removed screens or GPS assumptions.
