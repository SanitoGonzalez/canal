#pragma once

#include <stdint.h>

#define CANAL_VERSION 1

/*
* SYN: Initiate an RUDP connection between two hosts.
* ACK: Reply the correct sequential message.
* EAK: Reply the incorrect or unsequenced message.
* RST: Reset a RUDP connection
* NUL: Keep connection between two hosts.
* (5): Not used yet.
* (6~7): VER NO. Used to indicated the version of RUDP 
*/
enum CanalHeaderControlFlag {
    CANAL_HEADER_CONTROL_SYN = 1 << 0,
    CANAL_HEADER_CONTROL_ACK = 1 << 1,
    CANAL_HEADER_CONTROL_EAK = 1 << 2,
    CANAL_HEADER_CONTROL_RST = 1 << 3,
    CANAL_HEADER_CONTROL_NUL = 1 << 4,
};

enum CanalPacketFlag {
    CANAL_PACKET_ORDERED =  1 << 0,
    CANAL_PACKET_UNORDERED = 1 << 1,
    CANAL_PACKET_RELIABLE = 1 << 2,
    CANAL_PACKET_UNRELIABLE = 1 << 3,
};

struct CanalHeader {
    uint8_t control;
    uint8_t header_length;
    uint16_t sequence;
    uint16_t checksum;
    uint16_t custom;
};

static void canal_write_header_control(struct CanalHeader* header, const CanalHeaderControlFlag control) {
    header->control = 0;
    header->control |= (control & 0b0011'1111);
    header->control |= (CANAL_VERSION & 0b0000'0011) << 6;
}