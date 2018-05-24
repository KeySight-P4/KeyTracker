
#ifndef DPDK_PCAP_FLOW_H
#define DPDK_PCAP_FLOW_H

#include <stdint.h>
#include "protocol.h"

#define SWAP16(v) \
	(uint16_t) ((((uint16_t)(v) & UINT16_C(0x00ff)) << 8) | \
	 (((uint16_t)(v) & UINT16_C(0xff00)) >> 8))

#define SWAP32(v) \
	((((uint32_t)(v) & UINT32_C(0x000000ff)) << 24) | \
	 (((uint32_t)(v) & UINT32_C(0x0000ff00)) <<  8) | \
	 (((uint32_t)(v) & UINT32_C(0x00ff0000)) >>  8) | \
	 (((uint32_t)(v) & UINT32_C(0xff000000)) >> 24))

#define SWAP64(v) \
	((((uint64_t)(v) & UINT64_C(0x00000000000000ff)) << 56) | \
	 (((uint64_t)(v) & UINT64_C(0x000000000000ff00)) << 40) | \
	 (((uint64_t)(v) & UINT64_C(0x0000000000ff0000)) << 24) | \
	 (((uint64_t)(v) & UINT64_C(0x00000000ff000000)) <<  8) | \
	 (((uint64_t)(v) & UINT64_C(0x000000ff00000000)) >>  8) | \
	 (((uint64_t)(v) & UINT64_C(0x0000ff0000000000)) >> 24) | \
	 (((uint64_t)(v) & UINT64_C(0x00ff000000000000)) >> 40) | \
	 (((uint64_t)(v) & UINT64_C(0xff00000000000000)) >> 56))


typedef struct packet_t {
    uint32_t packet_length;
    ethernet_t eth;
    vlan_t vlan;
    ipv4_t ipv4;
    tcp_t tcp;
    udp_t udp;
    uint8_t eth_valid;
    uint8_t tcp_valid;
    uint8_t udp_valid;
    uint8_t ipv4_valid;
    uint8_t vlan_valid;
} packet_t;

/**
 *
 * @param length
 */
void extract_packet(packet_t * , const uint8_t *, uint32_t length);

/**
 *
 * @param dst
 * @param src
 */
static inline void
copy_eth_addr(uint8_t* dst, const uint8_t* src)
{
	((uint32_t*) dst)[0] = ((const uint32_t*) src)[0];
	((uint32_t*) (dst + 2))[0] = ((const uint32_t*) (src + 2))[0];
}

#endif //DPDK_PCAP_FLOW_H
