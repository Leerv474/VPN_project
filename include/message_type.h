#pragma once
#include <cstdint>

enum class MessageType : uint8_t {
    CLIENT_CHALLENGE   = 0x01,
    SERVER_RESPONSE    = 0x02,
    SERVER_CHALLENGE   = 0x03,
    CLIENT_RESPONSE    = 0x04,
    VPN_PACKET         = 0x05,
    ACCESS_DECLINED    = 0x06
};

