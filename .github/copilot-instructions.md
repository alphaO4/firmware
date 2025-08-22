# Copilot Instructions for Meshtastic Firmware

## Project Overview
- This repository contains the device firmware for the Meshtastic project, supporting multiple hardware platforms (ESP32, nRF52, STM32, RP2040, etc.).
- Major directories:
  - `src/` — Main firmware source code (C++/Arduino style)
  - `arch/` — Platform-specific code for each supported MCU family
  - `boards/` — Board configuration files (JSON)
  - `protobufs/` — Protobuf message definitions for device/app communication
  - `bin/` — Build scripts, utilities, and helper tools (Python, shell, batch)
  - `extra_scripts/` — PlatformIO environment modification scripts
  - `meshtestic/` — End-to-end test suite (Node.js, Python, PlatformIO)

## Build & Test Workflows
- **Build firmware:** Use PlatformIO (`pio run`) or VS Code PlatformIO tasks. Example: `pio run --environment heltec-mesh-node-t114`.
- **Full clean:** `pio run --target fullclean --environment <env>`
- **End-to-end tests:**
  - Install Node.js, pnpm, Python (with pip), and PlatformIO.
  - Connect supported devices via USB.
  - In `meshtestic/`, run `pnpm i` then `pnpm run test`.
- **Protobufs:** Regenerate with `bin/regen-protos.sh` (Linux/macOS) or `bin/regen-protos.bat` (Windows).

## Key Patterns & Conventions
- **Board Variants:**
  - Board-specific code lives in `variants/` and `src/platform/extra_variants/`.
  - Use `lateInitVariant()` for board-specific initialization (see `src/platform/extra_variants/README.md`).
  - Board macros: Define `_VARIANT_boardname` in `variant.h` for conditional compilation.
- **Protobuf Communication:**
  - All device/app communication uses protobufs defined in `protobufs/`.
  - Regenerate code after editing `.proto` files.
- **Scripts:**
  - Use scripts in `bin/` for build, versioning, and device management tasks.
  - Many scripts have both `.sh` (Unix) and `.bat` (Windows) versions.
- **Testing:**
  - End-to-end tests in `meshtestic/` simulate real device usage and require hardware.
  - See `meshtestic/README.md` for setup and execution details.

## Integration & External Dependencies
- **PlatformIO** is the primary build system (see `platformio.ini`).
- **Protobufs** are shared with apps and tools; keep definitions in sync.
- **Node.js** and **Python** are required for test automation and some build scripts.

## Examples
- Add a new board: Create a JSON in `boards/`, add variant code in `variants/` and/or `src/platform/extra_variants/`.
- Add a new protobuf message: Edit `.proto` in `protobufs/`, then run the regen script.
- Run all tests: `pnpm run test` in `meshtestic/` (after setup).

## References
- See `README.md` (root), `protobufs/README.md`, `meshtestic/README.md`, and `src/platform/extra_variants/README.md` for more details.

---
If any section is unclear or missing important project-specific knowledge, please provide feedback for further refinement.
