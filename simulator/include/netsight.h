#ifndef DPDK_PCAP_NETSIGHT_H
#define DPDK_PCAP_NETSIGHT_H

#include "packet.h"

typedef struct netsight_t {
    uint32_t postcard_count;
    uint32_t tcp_packet_count;
    uint32_t udp_packet_count;

    int enable;
} netsight_t;

/**
 *
 * @param ns
 * @param packet
 */
static inline void
netsight_count(netsight_t * ns, packet_t * packet)
{
    ns->postcard_count ++;
    if (packet->udp_valid) {
        ns->udp_packet_count ++;
    }
    if (packet->tcp_valid) {
        ns->tcp_packet_count ++;
    }
}

#endif //DPDK_PCAP_NETSIGHT_H
