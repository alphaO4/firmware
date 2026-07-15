# Pager Single-Message Screen — Design

**Date:** 2026-07-15
**Branch:** JF-Pieper-Modifications
**Scope:** Heltec Mesh Node T114 (FF Kladow fire-department pager) only

## Problem

Upstream 2.7 replaced the single-message text frame with a threaded multi-message
view (`src/graphics/draw/MessageRenderer.cpp`): per-message headers, underlines,
optional bubbles, FONT_SMALL everywhere. On the pager the incoming alert gets a
small slice of the 240x135 screen and is hard to read at a glance.

Old 2.5 behavior (wanted back): the frame showed only the newest received
message — one small header line, rest of the screen for the message body.

## Decisions (user-confirmed)

1. **History:** newest received message only. No paging into history on device.
2. **Font:** body in FONT_MEDIUM with vertical autoscroll for overflow; header
   line stays small.
3. **Filter:** messages starting with `T100E:` are never displayed (tracker
   command/ACK chatter must not replace the alert on screen). Own sent messages
   are never displayed. Everything else displays.

## Approach

New fork-owned renderer + one-line hook in `Screen.cpp` (option B of A/B/C):

- `src/graphics/draw/PagerMessageRenderer.h`
- `src/graphics/draw/PagerMessageRenderer.cpp`
- Hook: inside the existing `#ifdef HELTEC_MESH_NODE_T114` FF Kladow block in
  `Screen::setFrames()`, register `PagerMessageRenderer::drawPagerMessageFrame`
  as the textMessage frame instead of
  `MessageRenderer::drawTextMessageFrame`.

Rejected alternatives: ifdef branch inside shared `MessageRenderer.cpp`
(recurring upstream-merge conflicts in a file not on the MANUAL list); upstream
config option (protobuf plumbing, overkill for the fork).

## Frame behavior

```
+------------------------------------+
| [common 2.7 header: battery/clock] |
| 2m ago from LSTELLE       (small)  |
| ------------------------------     |
| EINSATZ: B2 Wohnungsbrand          |
| Musterstr. 12              (MEDIUM,|
| 14:32 OT Kladow            wraps,  |
| ...                        scrolls)|
+------------------------------------+
```

1. **Message pick:** iterate `messageStore.getLiveMessages()` newest-first;
   take the first entry with `sender != nodeDB->getNodeNum()` and text not
   starting with `T100E:`. None found → centered "No messages" placeholder
   (header still drawn).
2. **Header line:** relative age (`5s/3m/2h/1d` style) + `from <name>`
   (long name preferred, short name fallback, `(%08x)` last resort), FONT_SMALL,
   1px underline.
3. **Body:** FONT_MEDIUM, word-wrapped to full usable width (reuse
   `MessageRenderer::generateLines()` with the display font set to
   FONT_MEDIUM before the call).
4. **Autoscroll:** if body height exceeds usable area: wait 2 s, scroll down
   continuously, pause 3 s at end, jump back to top, repeat. Simplified copy of
   the 2.7 scroll pattern, self-contained in the new file. New message arrival
   resets scroll to top.
5. **Unread flag:** frame clears `hasUnreadMessage` when drawn (same as 2.7
   renderer).

## Untouched

- Banner popup ("Alert Received from…"), screen wake, buzzer/RTTTL prefixes,
  message storage/persistence, `MessageRenderer.cpp` itself (still compiled,
  its `handleNewMessage()` keeps running — only the frame pointer differs on
  T114).
- Menu/button handling for the textMessage frame position stays as upstream.

## Merge protection

- `.gitattributes`: `merge=ours` for both new files.
- `auto-merge-master.yml` verify step: add marker grep
  `"FF Kladow pager: single-message frame"` (comment placed in
  `PagerMessageRenderer.cpp` and at the Screen.cpp hook).
- `Screen.cpp` already MANUAL-listed; hook lives inside the existing FF Kladow
  ifdef block.

## Verification

- Build: `pio run -e heltec_mesh_node_t114` succeeds, flash usage sane.
- Behavior (on-device or code review): long message autoscrolls; `T100E:ACK`
  arrival does not replace displayed alert; own sent message not displayed;
  empty store shows placeholder.
