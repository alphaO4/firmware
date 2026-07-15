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
#include <cstdio>
#include <cstring>
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
