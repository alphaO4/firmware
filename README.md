# Meshtastic Firmware (JF-Pieper Modified)

![GitHub release downloads](https://img.shields.io/github/downloads/meshtastic/firmware/total)
[![CI](https://img.shields.io/github/actions/workflow/status/meshtastic/firmware/main_matrix.yml?branch=master&label=actions&logo=github&color=yellow)](https://github.com/meshtastic/firmware/actions/workflows/ci.yml)
[![CLA assistant](https://cla-assistant.io/readme/badge/meshtastic/firmware)](https://cla-assistant.io/meshtastic/firmware)
[![Fiscal Contributors](https://opencollective.com/meshtastic/tiers/badge.svg?label=Fiscal%20Contributors&color=deeppink)](https://opencollective.com/meshtastic/)
[![Vercel](https://img.shields.io/static/v1?label=Powered%20by&message=Vercel&style=flat&logo=vercel&color=000000)](https://vercel.com?utm_source=meshtastic&utm_campaign=oss)

## Overview

This repository contains the device firmware for the Meshtastic project with specific modifications for Heltec T114 devices.

## JF-Pieper Modifications

This fork includes specialized modifications for the **Heltec Mesh Node T114** device:

### Display Simplification
- **Simplified UI**: Shows only essential screens (messages + settings)
- **Removed pages**: Clock, nodes list, WiFi info, debug log
- **GPS indication**: Debug screen shows "No GPS present" when applicable
- **Conditional compilation**: Protected by `HELTEC_MESH_NODE_T114` macro

### Automated Workflows
- **Auto-merge**: Automatically merges upstream changes while preserving modifications
- **Auto-build**: Builds T114 firmware on every commit with compliance documentation

## GPL-3.0 Compliance

**License & Notices:** This distribution contains modified Meshtastic firmware (GPL-3.0). Modified by JF-Pieper on 2025-08-22. Original source: https://github.com/meshtastic/firmware. See LICENSE file for full GPL-3.0 terms.

**Corresponding Source:** All source code modifications are available in this repository on the `JF-Pieper-Modifications` branch. Build configuration included (`platformio.ini`, `.github/workflows/`). To rebuild: `pip install platformio && pio run --environment heltec-mesh-node-t114`.

**Installation Information (GPLv3 §6):** For Heltec T114 devices: Enter bootloader mode (double-tap reset), drag `.uf2` file to mounted drive, or use programming tools with `.hex` file. No cryptographic signatures prevent user installation of modified firmware. Device owners can install their own builds using standard nRF52840 programming methods.

**No Additional Restrictions:** No patent claims, technical protection measures, or license terms beyond GPL-3.0 are imposed on this distribution.

**Trademarks:** This modified firmware is based on Meshtastic but is not affiliated with or endorsed by Meshtastic LLC. "Meshtastic" is a trademark of Meshtastic LLC. Use of Meshtastic trademark follows fair use for compatibility description only.

## Building

This project uses the [PlatformIO](https://platformio.org) development environment.

### Prerequisites

* [Python 3](https://www.python.org/downloads/)
* [PlatformIO](https://platformio.org)

### Build for Heltec T114

```bash
pip install platformio
pio run --environment heltec-mesh-node-t114
```

### Firmware Files

After building, firmware files are located in `.pio/build/heltec-mesh-node-t114/`:
- `firmware.hex` - Intel HEX format for programming tools
- `firmware.uf2` - UF2 format for drag-and-drop flashing
- `firmware.elf` - ELF format with debug symbols

## Installation

### Heltec T114 Installation
1. Connect T114 device via USB
2. Double-tap the reset button to enter bootloader mode
3. Device appears as USB drive
4. Drag `firmware.uf2` file to the drive
5. Device automatically reboots with new firmware

## Documentation

* [Official Meshtastic Documentation](https://meshtastic.org)
* [Building Instructions](https://meshtastic.org/docs/development/firmware/build)
* [Flashing Instructions](https://meshtastic.org/docs/getting-started/flashing-firmware/)
* [JF-Pieper Workflow Documentation](.github/workflows/README.md)
* [Changes Log](CHANGES.md)

## Stats

![Alt](https://repobeats.axiom.co/api/embed/a92f097d9197ae853e780ec53d7d126e545629ab.svg "Repobeats analytics image")


# testing after enabling actions for github apps

