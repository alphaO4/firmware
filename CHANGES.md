# CHANGES

## 2025-08-22, JF-Pieper-Modifications, 004f46acf

### Build/CI
- `.github/workflows/auto-merge-master.yml` → Added automated merge workflow from master to JF-Pieper-Modifications with intelligent `Screen.cpp` conflict resolution; preserves `HELTEC_MESH_NODE_T114` conditional blocks via Python merge script
- `.github/workflows/auto-build-t114.yml` → Added automated Heltec T114 firmware build workflow; triggers on JF-Pieper-Modifications pushes; uses PlatformIO with caching; verifies `HELTEC_MESH_NODE_T114` guards; produces `.hex`, `.uf2`, `.elf`, `.zip` artifacts
- `.github/workflows/README.md` → Added comprehensive workflow documentation covering auto-merge and auto-build integration

### Device UX
- **T114 Display preserved**: Simplified display (messages + settings only); removed: clock/nodes/WiFi/debug log; debug shows "No GPS present" when applicable; protected by `HELTEC_MESH_NODE_T114` conditional compilation

### Docs  
- `README.md` → Added testing comment for GitHub Apps actions enablement
