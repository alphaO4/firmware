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
