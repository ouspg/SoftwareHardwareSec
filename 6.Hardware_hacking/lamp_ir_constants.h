#pragma once
#include <infrared.h>

// Led lamp protocol constants
// See lamp.ir

// Protocol: NECext
// NOTE: Flipper expects 32-bit address in little-endian format (low byte first) (different from .ir)
// All commands use the same address: 0xEF00 (from IR file: 00 EF 00 00)
// Common protocol and address for all led lamp's commands
#define LAMP_IR_PROTOCOL InfraredProtocolNECext
#define LAMP_IR_ADDRESS  0xEF00 // From IR file: 00 EF 00 00 -> 0xEF00

// LAMP IR Command Codes (converted from IR file format)
typedef enum {
    LAMP_CMD_ON = 0xFC03, // From IR file: 03 FC 00 00 -> 0xFC03
    LAMP_CMD_OFF = 0xFD02, // From IR file: 02 FD 00 00 -> 0xFD02
    LAMP_CMD_RED = 0xFB04, // From IR file: 04 FB 00 00 -> 0xFB04
    LAMP_CMD_WHITE = 0xF807, // From IR file: 07 F8 00 00 -> 0xF807
    LAMP_CMD_YELLOW = 0xEB14, // From IR file: 14 EB 00 00 -> 0xEB14
    LAMP_CMD_BLUE = 0xF906, // From IR file: 06 F9 00 00 -> 0xF906
    LAMP_CMD_INC = 0xFF00, // From IR file: 00 FF 00 00 -> 0xFF00
    LAMP_CMD_DEC = 0xFE01, // From IR file: 01 FE 00 00 -> 0xFE01
} LAMPCommand;

// Button name strings for debugging/logging
typedef struct {
    LAMPCommand command;
    const char* name;
} LAMPButtonInfo;

static const LAMPButtonInfo LAMP_buttons[] = {
    {LAMP_CMD_ON, "On"},
    {LAMP_CMD_OFF, "Off"},
    {LAMP_CMD_RED, "Red"},
    {LAMP_CMD_WHITE, "White"},
    {LAMP_CMD_YELLOW, "Yellow"},
    {LAMP_CMD_BLUE, "Blue"},
    {LAMP_CMD_INC, "Inc"},
    {LAMP_CMD_DEC, "Dec"},
};

#define LAMP_BUTTON_COUNT (sizeof(LAMP_buttons) / sizeof(LAMP_buttons[0]))

// Helper function to get button name from command
static inline const char* lamp_get_button_name(LAMPCommand command) {
    for(size_t i = 0; i < LAMP_BUTTON_COUNT; i++) {
        if(LAMP_buttons[i].command == command) {
            return LAMP_buttons[i].name;
        }
    }
    return "Unknown";
}

// Helper function to create an InfraredMessage for the led lamp commands
static inline InfraredMessage lamp_create_message(LAMPCommand command, bool repeat) {
    InfraredMessage message = {
        .protocol = LAMP_IR_PROTOCOL,
        .address = LAMP_IR_ADDRESS,
        .command = command,
        .repeat = repeat};
    return message;
}
