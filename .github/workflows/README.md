# Auto-merge Workflow Documentation

## Overview
This GitHub Action automatically merges changes from the `master` branch into the `JF-Pieper-Modifications` branch while preserving specific modifications to `Screen.cpp`.

## JF-Pieper Screen.cpp Modifications
The workflow preserves the following modifications in `src/graphics/Screen.cpp`:

### HELTEC_MESH_NODE_T114 Conditional Block
The workflow specifically protects this conditional compilation block that simplifies the display for the T114 device:

```cpp
#ifdef HELTEC_MESH_NODE_T114
    // For T114: Only show text messages and debug info (which shows "No GPS present")
    
    // If we have a critical fault, show it first
    fsi.positions.fault = numframes;
    if (error_code) {
        normalFrames[numframes++] = drawCriticalFaultFrame;
        focus = FOCUS_FAULT;
    }

    // If we have a text message - show it next
    if (devicestate.has_rx_text_message && shouldDrawMessage(&devicestate.rx_text_message)) {
        fsi.positions.textMessage = numframes;
        normalFrames[numframes++] = drawTextMessageFrame;
    }

    // Only show the debug info settings screen (which includes "No GPS present" message)
    fsi.positions.settings = numframes;
    normalFrames[numframes++] = &Screen::drawDebugInfoSettingsTrampoline;

#else
    // For all other devices: show all frames as before
    // ... (rest of the original code)
#endif
```

### Key Features of This Modification:
- **Removes unnecessary pages** for the T114 device (clock, nodes, debug log, WiFi)
- **Shows only critical content**: fault messages, text messages, and debug info settings
- **Preserves "No GPS present" message** through the debug info settings screen

## Workflow Behavior

### Automatic Execution
- Runs automatically on every push/merge to the `master` branch
- Can be manually triggered from the GitHub Actions tab

### Merge Strategy
1. **Simple merge**: If no conflicts, automatically merges master into JF-Pieper-Modifications
2. **Intelligent conflict resolution**: For Screen.cpp conflicts:
   - Preserves the entire HELTEC_MESH_NODE_T114 conditional block
   - Integrates other master branch changes around the protected code
   - Uses Python script for smart text processing
3. **Standard resolution**: For other file conflicts, uses master branch version

### Verification
- Confirms JF-Pieper modifications are still present after merge
- Fails the workflow if critical modifications are lost

### Failure Handling
- Creates GitHub issues when automatic merge fails
- Provides detailed instructions for manual resolution
- Avoids duplicate issue creation

## Manual Override
If the automatic merge fails, you can:

1. **Check the created issue** for specific failure details
2. **Manually merge**:
   ```bash
   git checkout JF-Pieper-Modifications
   git merge master
   # Resolve conflicts manually, ensuring Screen.cpp modifications are preserved
   git push origin JF-Pieper-Modifications
   ```

## Files Protected
- `src/graphics/Screen.cpp` - JF-Pieper T114 modifications preserved
- All other files accept master branch changes during conflicts

## Workflow Files
- `.github/workflows/auto-merge-master.yml` - Main workflow
- `.github/workflows/README.md` - This documentation
