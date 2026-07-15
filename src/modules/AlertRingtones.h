#pragma once

/**
 * @file AlertRingtones.h
 * @brief Alert type definitions and default RTTTL ringtones for prefix-based notifications.
 *
 * This module provides prefix detection and ringtone selection for the FF Kladow
 * Meshtastic Pager project. Different message prefixes trigger different alert tones.
 *
 * Supported prefixes (from Tech-Specs.md):
 * - ALARM:       Urgent fire department alarm (highest priority)
 * - EINSATZ:     Standard fire department deployment
 * - LSP_ALARM:   Youth group (Lösch-Schnupper-Programm) alerts
 * - T100E:ALARM: SenseCAP T1000E specific high-priority
 * - T100E:EINSATZ: SenseCAP T1000E standard deployment
 * - T100E:TEST:  SenseCAP T1000E test notification
 */

#include <cstdint>
#include <cstring>

/**
 * @brief Enumeration of supported alert types based on message prefix.
 */
enum class AlertType : uint8_t {
    DEFAULT = 0,      // No prefix match, use default ringtone
    ALARM,            // ALARM: prefix - highest priority
    EINSATZ,          // EINSATZ: prefix - standard deployment
    LSP_ALARM,        // LSP_ALARM: prefix - youth group
    T100E_ALARM,      // T100E:ALARM: prefix
    T100E_EINSATZ,    // T100E:EINSATZ: prefix
    T100E_TEST,       // T100E:TEST: prefix
    T100E_ACK,        // T100E:ACK: prefix - no sound
    COUNT             // Number of alert types
};

/**
 * @brief Prefix strings for alert type detection.
 * Order must match AlertType enum (excluding DEFAULT and COUNT).
 */
static const char *const ALERT_PREFIXES[] = {
    "ALARM:",         // AlertType::ALARM
    "EINSATZ:",       // AlertType::EINSATZ
    "LSP_ALARM:",     // AlertType::LSP_ALARM
    "T100E:ALARM:",   // AlertType::T100E_ALARM
    "T100E:EINSATZ:", // AlertType::T100E_EINSATZ
    "T100E:TEST:",    // AlertType::T100E_TEST
    "T100E:ACK:",     // AlertType::T100E_ACK
};

// Number of prefixes to check
static const uint8_t ALERT_PREFIX_COUNT = sizeof(ALERT_PREFIXES) / sizeof(ALERT_PREFIXES[0]);

/**
 * Default RTTTL Ringtones for each alert type.
 * These are used when no custom ringtone is configured.
 *
 * RTTTL Format: name:d=duration,o=octave,b=bpm:notes
 *
 * All tones are optimized for a buzzer with 2700Hz resonant frequency.
 * Primary notes: E7 (2637Hz) and F7 (2794Hz) bracket the resonant peak
 * for maximum acoustic output. D7 (2349Hz) through G7 (3136Hz) remain
 * within the effective bandwidth (~±20%) of a 2700Hz piezo buzzer.
 */

// Default fallback ringtone - optimized for 2700Hz resonant buzzer
// Two-phase pattern: short E7/F7 bursts then sustained E7 tail
#define DEFAULT_RTTTL_RINGTONE "Default:d=32,o=7,b=565:e,p,e,4p,p,e,p,e,2p,p,f,p,f,p,f,p,f,p,e,p,e,p,e,p,e,p,e,p,e,p,e,p,e,1p.,2p.,p"

// ALARM: Aggressive rapid siren - 16th notes at 280 BPM, near-continuous E7/F7 warble
// Designed to be impossible to ignore; minimal gaps between siren bursts
#define ALARM_RTTTL_RINGTONE "Alarm:d=16,o=7,b=280:e,f,e,f,e,f,e,f,e,f,e,f,e,f,e,f,8p,e,f,e,f,e,f,e,f,e,f,e,f,e,f,e,f"

// EINSATZ: Urgent rapid staccato - 16th notes at 240 BPM, fast beep bursts
// 5-beep groups with short gaps; clearly urgent, distinct from ALARM's continuous siren
#define EINSATZ_RTTTL_RINGTONE "Einsatz:d=16,o=7,b=240:e,p,e,p,e,p,e,p,e,8p,e,p,e,p,e,p,e,p,e,8p,e,p,e,p,e,p,e,p,e"

// LSP_ALARM: Youth group alert - ascending melodic pattern near resonance
// D7(2349Hz)->E7(2637Hz)->F7(2794Hz) keeps friendly character at full volume
#define LSP_ALARM_RTTTL_RINGTONE "LSP:d=8,o=7,b=160:d,e,f,4e,p,d,e,f,4e,p,d,e,f,4e"

// T100E:ALARM: High priority for SenseCAP T1000E
// F7 (2794Hz) - single closest note to 2700Hz for max output on small buzzer
#define T100E_ALARM_RTTTL_RINGTONE "T100Alarm:d=4,o=7,b=220:f,p,f,p,f,2p,f,p,f,p,f,2p,f,p,f,p,f"

// T100E:EINSATZ: Standard for SenseCAP T1000E
// E7 (2637Hz) beeps with pauses, optimized for small piezo buzzer
#define T100E_EINSATZ_RTTTL_RINGTONE "T100Ein:d=8,o=7,b=180:e,p,e,p,e,4p,e,p,e,p,e,4p"

// T100E:TEST: Test notification - short, non-intrusive
// Two quick F7 beeps at peak resonance for clear confirmation
#define T100E_TEST_RTTTL_RINGTONE "T100Test:d=16,o=7,b=200:f,p,f"

/**
 * @brief Detect alert type from message payload based on prefix.
 *
 * @param payload Pointer to message payload bytes
 * @param payloadSize Size of the payload in bytes
 * @return AlertType The detected alert type, or DEFAULT if no prefix matches
 */
inline AlertType detectAlertType(const uint8_t *payload, size_t payloadSize)
{
    if (payload == nullptr || payloadSize == 0) {
        return AlertType::DEFAULT;
    }

    // Check each prefix in order (longer prefixes like T100E:ALARM: checked before shorter ones)
    // Order in ALERT_PREFIXES matters - T100E variants should be checked before generic ALARM/EINSATZ
    // We check T100E prefixes first (indices 3-6), then generic ones (0-2)
    static const uint8_t checkOrder[] = {3, 4, 5, 6, 0, 1, 2}; // T100E variants first

    for (uint8_t i = 0; i < sizeof(checkOrder); i++) {
        uint8_t idx = checkOrder[i];
        if (idx >= ALERT_PREFIX_COUNT)
            continue;

        const char *prefix = ALERT_PREFIXES[idx];
        size_t prefixLen = strlen(prefix);

        if (payloadSize >= prefixLen && memcmp(payload, prefix, prefixLen) == 0) {
            // Map array index to AlertType enum (offset by 1 because DEFAULT=0)
            return static_cast<AlertType>(idx + 1);
        }
    }

    return AlertType::DEFAULT;
}

/**
 * @brief Check if an alert type should produce sound.
 *
 * @param type The alert type to check
 * @return true if the alert should produce sound, false otherwise
 */
inline bool alertTypeHasSound(AlertType type)
{
    // T100E:ACK messages are protocol acknowledgments, no sound
    return type != AlertType::T100E_ACK;
}

/**
 * @brief Get the name of an alert type for logging.
 *
 * @param type The alert type
 * @return const char* Name string for the alert type
 */
inline const char *getAlertTypeName(AlertType type)
{
    switch (type) {
    case AlertType::DEFAULT:
        return "DEFAULT";
    case AlertType::ALARM:
        return "ALARM";
    case AlertType::EINSATZ:
        return "EINSATZ";
    case AlertType::LSP_ALARM:
        return "LSP_ALARM";
    case AlertType::T100E_ALARM:
        return "T100E_ALARM";
    case AlertType::T100E_EINSATZ:
        return "T100E_EINSATZ";
    case AlertType::T100E_TEST:
        return "T100E_TEST";
    case AlertType::T100E_ACK:
        return "T100E_ACK";
    default:
        return "UNKNOWN";
    }
}
