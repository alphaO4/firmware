# Pager Single-Message Screen Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the 2.7 multi-message thread view with a full-screen single-message frame on the FF Kladow T114 pager, showing only the newest received (non-`T100E:`) message in FONT_MEDIUM with autoscroll.

**Architecture:** New fork-owned renderer `src/graphics/draw/PagerMessageRenderer.{h,cpp}` registered as the textMessage frame inside the existing `#ifdef HELTEC_MESH_NODE_T114` path of `Screen::setFrames()`. Upstream `MessageRenderer.cpp` stays untouched (its `handleNewMessage()` banner/wake logic keeps running). Merge protection via `.gitattributes` + auto-merge workflow markers.

**Tech Stack:** Meshtastic firmware 2.7.x, C++ (PlatformIO, nRF52840), OLEDDisplay UI library (ST7789 TFT 240x135).

**Spec:** `docs/superpowers/specs/2026-07-15-pager-single-message-screen-design.md`

## Global Constraints

- Target/build env: `heltec-mesh-node-t114`. Build command (pio NOT on PATH; PowerShell):
  `& "$env:USERPROFILE\.platformio\penv\Scripts\pio.exe" run --environment heltec-mesh-node-t114`
  Full build ≈ 7.5 min warm. Expect `SUCCESS`; flash was 90.4% before this change — must stay under 100%.
- No display test harness exists in this repo; per-task verification = successful T114 compile + code checklist. On-device verification happens after flashing (out of scope for this plan's steps).
- Marker string `FF Kladow pager: single-message frame` must appear verbatim in BOTH `src/graphics/Screen.cpp` and `src/graphics/draw/PagerMessageRenderer.cpp` (the auto-merge workflow greps for it — Task 3).
- Fonts on T114 (USE_ST7789 → big-font branch of `ScreenFonts.h`): FONT_SMALL height 19, FONT_MEDIUM height 28. Screen 240x135.
- `messageStore.getLiveMessages()` returns `std::deque<StoredMessage>`, newest at back (`push_back`).
- Commit style: Conventional Commits, subject ≤50 chars.

---

### Task 1: PagerMessageRenderer (new files)

**Files:**
- Create: `src/graphics/draw/PagerMessageRenderer.h`
- Create: `src/graphics/draw/PagerMessageRenderer.cpp`

**Interfaces:**
- Consumes: `messageStore` (global, `src/MessageStore.h`), `MessageStore::getText(const StoredMessage&)`, `nodeDB->getNodeNum()` / `nodeDB->getMeshNode(uint32_t)` (`NodeDB.h`), `graphics::MessageRenderer::generateLines(display, "", text, width)` (`draw/MessageRenderer.h`), `graphics::drawCommonHeader(...)` / `graphics::getTextPositions(display)` / `graphics::hasUnreadMessage` (`graphics/SharedUIDisplay.h`), `getValidTime(RTCQuality::RTCQualityDevice, true)` (`gps/RTC.h`).
- Produces: `graphics::PagerMessageRenderer::drawPagerMessageFrame(OLEDDisplay*, OLEDDisplayUiState*, int16_t, int16_t)` — exact signature required by `normalFrames[]` in Screen.cpp (Task 2).

- [ ] **Step 1: Write `src/graphics/draw/PagerMessageRenderer.h`**

```cpp
#pragma once
#include "configuration.h"
#if HAS_SCREEN
#include <OLEDDisplay.h>
#include <OLEDDisplayUi.h>

namespace graphics
{
namespace PagerMessageRenderer
{

/// FF Kladow pager: full-screen single-message frame (2.5-style).
/// Shows only the newest received message; T100E:* tracker traffic and our
/// own sent messages are never displayed.
void drawPagerMessageFrame(OLEDDisplay *display, OLEDDisplayUiState *state, int16_t x, int16_t y);

} // namespace PagerMessageRenderer
} // namespace graphics
#endif
```

- [ ] **Step 2: Write `src/graphics/draw/PagerMessageRenderer.cpp`**

Layout: common 2.7 header (battery/clock) → small sender line + 1px underline → body in FONT_MEDIUM, wrapped, autoscrolling (2 s start delay, 5 px/s, 3 s end pause, jump to top). Body drawn first, then a black mask rect + header/sender line on top so scrolled text never bleeds into the header area. Plain `drawString` (no emote rendering — dispatch texts are plain text).

```cpp
// FF Kladow pager: single-message frame. Shows only the newest received
// message full screen (old 2.5 behavior); tracker command traffic (T100E:*)
// never replaces the displayed alert. See
// docs/superpowers/specs/2026-07-15-pager-single-message-screen-design.md
#include "configuration.h"
#if HAS_SCREEN
#include "PagerMessageRenderer.h"

#include "MessageRenderer.h" // generateLines() word-wrap
#include "MessageStore.h"
#include "NodeDB.h"
#include "UIRenderer.h"
#include "gps/RTC.h"
#include "graphics/ScreenFonts.h"
#include "graphics/SharedUIDisplay.h"
#include <algorithm>
#include <string>
#include <vector>

namespace graphics
{
namespace PagerMessageRenderer
{

// Tracker command/ACK chatter that must never replace an alert on screen
static constexpr char IGNORED_PREFIX[] = "T100E:";

// Autoscroll state (same feel as the upstream thread view)
static float scrollY = 0.0f;
static uint32_t lastTime = 0;
static uint32_t scrollStartDelay = 0;
static uint32_t pauseStart = 0;
static bool waitingToReset = false;
static bool scrollStarted = false;

// Identity of the message the cached lines/scroll state belong to
static uint32_t shownSender = 0;
static uint32_t shownTimestamp = 0;
static uint16_t shownTextOffset = 0xffff;
static uint16_t shownTextLength = 0xffff;
static std::vector<std::string> lines;

static void resetScroll()
{
    scrollY = 0.0f;
    scrollStarted = false;
    waitingToReset = false;
    scrollStartDelay = millis();
    lastTime = millis();
}

static const StoredMessage *pickNewestReceived()
{
    const auto &msgs = messageStore.getLiveMessages();
    const uint32_t ourNode = nodeDB->getNodeNum();
    for (auto it = msgs.rbegin(); it != msgs.rend(); ++it) {
        if (it->sender == ourNode)
            continue;
        const char *text = MessageStore::getText(*it);
        if (!text || !text[0])
            continue;
        if (strncmp(text, IGNORED_PREFIX, sizeof(IGNORED_PREFIX) - 1) == 0)
            continue;
        return &*it;
    }
    return nullptr;
}

// Relative age like the thread view: 42s / 5m / 3h / 2d, "???" if unknown
static void formatAge(const StoredMessage &m, char *out, size_t outSize)
{
    uint32_t nowSecs = getValidTime(RTCQuality::RTCQualityDevice, true);
    uint32_t seconds = 0;
    bool invalidTime = true;

    if (m.timestamp > 0 && nowSecs > 0) {
        if (nowSecs >= m.timestamp) {
            seconds = nowSecs - m.timestamp;
            invalidTime = (seconds > 315360000); // >10 years
        } else if (m.timestamp - nowSecs <= 600) { // allow small clock skew
            seconds = 0;
            invalidTime = false;
        }
    } else if (m.timestamp > 0 && nowSecs == 0) {
        // RTC not valid: only trust boot-relative timestamps from this boot
        uint32_t bootNow = millis() / 1000;
        if (m.isBootRelative && m.timestamp <= bootNow) {
            seconds = bootNow - m.timestamp;
            invalidTime = false;
        }
    }

    if (invalidTime)
        snprintf(out, outSize, "???");
    else if (seconds < 60)
        snprintf(out, outSize, "%us", seconds);
    else if (seconds < 3600)
        snprintf(out, outSize, "%um", seconds / 60);
    else if (seconds < 86400)
        snprintf(out, outSize, "%uh", seconds / 3600);
    else
        snprintf(out, outSize, "%ud", seconds / 86400);
}

void drawPagerMessageFrame(OLEDDisplay *display, OLEDDisplayUiState *state, int16_t x, int16_t y)
{
    messageStore.upgradeBootRelativeTimestamps();

    // Viewing the frame clears the unread indicator (mail icon)
    hasUnreadMessage = false;

    display->clear();
    display->setTextAlignment(TEXT_ALIGN_LEFT);

    const StoredMessage *m = pickNewestReceived();

    if (!m) {
        display->setFont(FONT_SMALL);
        graphics::drawCommonHeader(display, x, y, "Messages");
        const char *placeholder = "No messages";
        int cx = (SCREEN_WIDTH / 2) - (display->getStringWidth(placeholder) / 2);
        display->drawString(cx, getTextPositions(display)[2], placeholder);
        return;
    }

    // Rebuild wrapped lines + reset scroll when a different message is newest.
    // (upgradeBootRelativeTimestamps may rewrite the timestamp once when the
    // RTC becomes valid; the resulting single spurious reset is harmless.)
    constexpr int LEFT_MARGIN = 2;
    constexpr int RIGHT_MARGIN = 4; // room for the 1px scrollbar
    const int wrapWidth = SCREEN_WIDTH - LEFT_MARGIN - RIGHT_MARGIN;
    if (m->sender != shownSender || m->timestamp != shownTimestamp || m->textOffset != shownTextOffset ||
        m->textLength != shownTextLength) {
        shownSender = m->sender;
        shownTimestamp = m->timestamp;
        shownTextOffset = m->textOffset;
        shownTextLength = m->textLength;
        display->setFont(FONT_MEDIUM); // generateLines measures with the current font
        lines = MessageRenderer::generateLines(display, "", MessageStore::getText(*m), wrapWidth);
        resetScroll();
    }

    // Geometry
    const int headerLineY = getTextPositions(display)[1];
    const int bodyTop = headerLineY + FONT_HEIGHT_SMALL + 3; // sender line + underline + gap
    const int usable = SCREEN_HEIGHT - bodyTop;
    const int totalHeight = (int)lines.size() * FONT_HEIGHT_MEDIUM;
    const int scrollStop = std::max(0, totalHeight - usable);

    // Autoscroll: wait 2s, scroll down, pause 3s at end, jump back to top
    uint32_t now = millis();
    float delta = (now - lastTime) / 400.0f;
    lastTime = now;
    const float scrollSpeed = 2.0f;

    if (scrollStartDelay == 0)
        scrollStartDelay = now;
    if (!scrollStarted && now - scrollStartDelay > 2000)
        scrollStarted = true;

    if (totalHeight > usable) {
        if (scrollStarted) {
            if (!waitingToReset) {
                scrollY += delta * scrollSpeed;
                if (scrollY >= scrollStop) {
                    scrollY = scrollStop;
                    waitingToReset = true;
                    pauseStart = now;
                }
            } else if (now - pauseStart > 3000) {
                scrollY = 0;
                waitingToReset = false;
                scrollStarted = false;
                scrollStartDelay = now;
            }
        }
    } else {
        scrollY = 0;
    }

    // Body (drawn first; header area is masked afterwards)
    display->setFont(FONT_MEDIUM);
    display->setColor(WHITE);
    int lineY = bodyTop - (int)scrollY;
    for (const auto &line : lines) {
        if (lineY > -FONT_HEIGHT_MEDIUM && lineY < SCREEN_HEIGHT) {
            display->drawString(x + LEFT_MARGIN, lineY, line.c_str());
        }
        lineY += FONT_HEIGHT_MEDIUM;
    }

    // Mask everything above the body so scrolled text never collides with
    // the common header or the sender line
    display->setColor(BLACK);
    display->fillRect(0, 0, SCREEN_WIDTH, bodyTop);
    display->setColor(WHITE);

    // Common 2.7 header (battery/clock/mail)
    display->setFont(FONT_SMALL);
    graphics::drawCommonHeader(display, x, y, "");

    // Sender line: "2m ago from LSTELLE" (or "from LSTELLE" if age unknown)
    char senderName[64];
    const meshtastic_NodeInfoLite *node = nodeDB->getMeshNode(m->sender);
    if (node && node->has_user && node->user.long_name[0]) {
        snprintf(senderName, sizeof(senderName), "%s", node->user.long_name);
    } else if (node && node->has_user && node->user.short_name[0]) {
        snprintf(senderName, sizeof(senderName), "%s", node->user.short_name);
    } else {
        snprintf(senderName, sizeof(senderName), "(%08x)", (unsigned)m->sender);
    }

    char age[16];
    formatAge(*m, age, sizeof(age));

    char headerLine[96];
    if (strcmp(age, "???") == 0) {
        snprintf(headerLine, sizeof(headerLine), "from %s", senderName);
    } else {
        snprintf(headerLine, sizeof(headerLine), "%s ago from %s", age, senderName);
    }

    char truncated[96];
    graphics::UIRenderer::truncateStringWithEmotes(display, headerLine, truncated, sizeof(truncated), wrapWidth);
    display->drawString(x + LEFT_MARGIN, headerLineY, truncated);

    // 1px underline below the sender line
    int underlineW = graphics::UIRenderer::measureStringWithEmotes(display, truncated);
    if (underlineW > wrapWidth)
        underlineW = wrapWidth;
    display->drawHorizontalLine(x + LEFT_MARGIN, headerLineY + FONT_HEIGHT_SMALL, underlineW);

    // Scrollbar (right edge) when the body overflows
    if (totalHeight > usable) {
        int sbX = SCREEN_WIDTH - 2;
        int thumbH = std::max(6, usable * usable / totalHeight);
        int thumbY = bodyTop + (usable - thumbH) * (int)scrollY / std::max(1, scrollStop);
        for (int i = 0; i < thumbH; i++) {
            display->setPixel(sbX, thumbY + i);
        }
    }
}

} // namespace PagerMessageRenderer
} // namespace graphics
#endif
```

- [ ] **Step 3: Compile for T114**

Run (PowerShell):
```powershell
& "$env:USERPROFILE\.platformio\penv\Scripts\pio.exe" run --environment heltec-mesh-node-t114
```
Expected: `SUCCESS`. New file compiles standalone (it is not referenced by anything yet — that's Task 2). Watch for: missing include errors, namespace mismatches. Flash usage unchanged ±0.5% (linker may drop unreferenced code).

- [ ] **Step 4: Commit**

```bash
git add src/graphics/draw/PagerMessageRenderer.h src/graphics/draw/PagerMessageRenderer.cpp
git commit -m "feat(screen): add pager single-message renderer"
```

---

### Task 2: Register frame in Screen.cpp (T114 only)

**Files:**
- Modify: `src/graphics/Screen.cpp` (include block near line 35-41; frame registration at lines 1193-1195)

**Interfaces:**
- Consumes: `graphics::PagerMessageRenderer::drawPagerMessageFrame` from Task 1.
- Produces: T114 builds show the pager frame at the textMessage position; all other targets keep `MessageRenderer::drawTextMessageFrame`. Frame position bookkeeping (`fsi.positions.textMessage`, `indicatorIcons`) unchanged, so focus-jump on new message, mail icon, and menu handling keep working.

- [ ] **Step 1: Add include**

In `src/graphics/Screen.cpp`, the include block currently reads (lines 35-41):

```cpp
#include "draw/ClockRenderer.h"
#include "draw/DebugRenderer.h"
#include "draw/MenuHandler.h"
#include "draw/MessageRenderer.h"
#include "draw/NodeListRenderer.h"
#include "draw/NotificationRenderer.h"
#include "draw/UIRenderer.h"
```

Insert after `#include "draw/NotificationRenderer.h"`:

```cpp
#ifdef HELTEC_MESH_NODE_T114
#include "draw/PagerMessageRenderer.h"
#endif
```

- [ ] **Step 2: Swap the frame pointer under the T114 ifdef**

In `Screen::setFrames()`, replace (currently lines 1193-1195):

```cpp
    fsi.positions.textMessage = numframes;
    normalFrames[numframes++] = graphics::MessageRenderer::drawTextMessageFrame;
    indicatorIcons.push_back(icon_mail);
```

with:

```cpp
    fsi.positions.textMessage = numframes;
#ifdef HELTEC_MESH_NODE_T114
    // FF Kladow pager: single-message frame (newest received alert, full screen)
    normalFrames[numframes++] = graphics::PagerMessageRenderer::drawPagerMessageFrame;
#else
    normalFrames[numframes++] = graphics::MessageRenderer::drawTextMessageFrame;
#endif
    indicatorIcons.push_back(icon_mail);
```

The comment text must contain the exact marker `FF Kladow pager: single-message frame` (workflow grep, Task 3).

- [ ] **Step 3: Compile for T114**

Run (PowerShell):
```powershell
& "$env:USERPROFILE\.platformio\penv\Scripts\pio.exe" run --environment heltec-mesh-node-t114
```
Expected: `SUCCESS`, flash under 100% (was 90.4%; this adds well under 1%).

- [ ] **Step 4: Code checklist (no test harness — verify by reading the diff)**

- [ ] `MessageRenderer::handleNewMessage` still referenced by its callers (banner/wake untouched) — `grep -n "handleNewMessage" src/graphics/Screen.cpp src/modules/TextMessageModule.cpp` style check; no call sites were edited.
- [ ] Non-T114 path byte-identical behavior (else-branch keeps upstream line).
- [ ] `fsi.positions.textMessage` still set unconditionally before the ifdef.

- [ ] **Step 5: Commit**

```bash
git add src/graphics/Screen.cpp
git commit -m "feat(screen): use single-message frame on T114 pager"
```

---

### Task 3: Merge protection + final verification

**Files:**
- Modify: `.gitattributes` (fork-owned block, lines 7-16)
- Modify: `.github/workflows/auto-merge-master.yml` (OURS list ~line 56-61; verify step ~line 106-114; failure-issue bullet list ~line 157-162)

**Interfaces:**
- Consumes: marker `FF Kladow pager: single-message frame` placed in Task 1 (PagerMessageRenderer.cpp) and Task 2 (Screen.cpp).
- Produces: upstream merges can never silently drop or clobber the pager screen files.

- [ ] **Step 1: Extend `.gitattributes`**

Append to the JF-Pieper block (after the `variants/...` line):

```
src/graphics/draw/PagerMessageRenderer.h merge=ours
src/graphics/draw/PagerMessageRenderer.cpp merge=ours
```

- [ ] **Step 2: Extend the workflow OURS list**

In `.github/workflows/auto-merge-master.yml`, change:

```yaml
        OURS="src/modules/AlertRingtones.h
        src/mesh/generated/meshtastic/rtttl.pb.h
        variants/nrf52840/heltec_mesh_node_t114/variant.h
        README.md
        .github/copilot-instructions.md
        .gitattributes"
```

to:

```yaml
        OURS="src/modules/AlertRingtones.h
        src/mesh/generated/meshtastic/rtttl.pb.h
        src/graphics/draw/PagerMessageRenderer.h
        src/graphics/draw/PagerMessageRenderer.cpp
        variants/nrf52840/heltec_mesh_node_t114/variant.h
        README.md
        .github/copilot-instructions.md
        .gitattributes"
```

- [ ] **Step 3: Extend the verify step**

After the existing line `check src/graphics/Screen.cpp "HELTEC_MESH_NODE_T114"`, add:

```bash
        check src/graphics/Screen.cpp "FF Kladow pager: single-message frame"
        check src/graphics/draw/PagerMessageRenderer.cpp "FF Kladow pager: single-message frame"
```

- [ ] **Step 4: Extend the failure-issue modification list**

In the `notify-on-failure` job body, after the line
`- HELTEC_MESH_NODE_T114 screen restriction via hiddenFrames in Screen.cpp setFrames()`, add:

```
          - Pager single-message frame (src/graphics/draw/PagerMessageRenderer.{h,cpp} + frame swap in Screen.cpp setFrames())
```

- [ ] **Step 5: Verify the markers actually match (run the greps locally)**

```bash
grep -F "FF Kladow pager: single-message frame" src/graphics/Screen.cpp src/graphics/draw/PagerMessageRenderer.cpp
```
Expected: one hit in each file. Zero hits in either = the workflow would fail every future merge — fix the comment text.

- [ ] **Step 6: Commit**

```bash
git add .gitattributes .github/workflows/auto-merge-master.yml
git commit -m "fix(ci): protect pager screen files during auto-merge"
```

---

### Post-plan (manual, on device)

Flash `.pio/build/heltec-mesh-node-t114/firmware-heltec-mesh-node-t114-<version>.uf2` and confirm: long message autoscrolls; `T100E:ACK` arrival keeps the alert on screen; own sent message not displayed; empty store shows "No messages"; banner + ringtone behavior unchanged.
