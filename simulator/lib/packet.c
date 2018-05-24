#include <memory.h>
#include <stdlib.h>
#include <stdio.h>
#include "packet.h"
#include "hash.h"

void
extract_packet(packet_t * p, const uint8_t * buf, uint32_t length)
{
    if (unlikely(p == NULL))
    {
        printf("The packet should not be null!");
        exit(1);
    }
    // Clear the packet structure
    p->vlan_valid = 0;
    p->udp_valid = 0;
    p->tcp_valid = 0;
    p->ipv4_valid = 0;
    p->eth_valid = 0;

    p->packet_length = length;
    int offset = 0;
    if (buf[0] == 0x45)
    {
        const ipv4_t * ipv4 = (const ipv4_t *) (buf + offset);
        p->ipv4 = * ipv4;
        p->ipv4_valid = 1;
        p->eth_valid = 0;
        offset = 20;
    }
    else if (buf[0] == 0x60)
    {
        p->ipv4_valid = 0;
        p->eth_valid = 0;
    }
    else
    {
        const ethernet_t * eth = (const ethernet_t*) buf;
        p->eth = *eth;
        p->eth_valid = 1;
        offset += sizeof(ethernet_t);
        uint16_t eth_type = SWAP16(eth->eth_type);

        if (eth_type == ETHER_TYPE_VLAN)
        {
            const vlan_t * vlan = (const vlan_t *) (buf + offset);
            p->vlan = *vlan;
            p->vlan_valid = 1;
            offset += 4;
            eth_type = SWAP16(vlan->eth_type);
        }
        if (eth_type == ETHER_TYPE_IPv4)
        {
            const ipv4_t * ipv4 = (const ipv4_t *) (buf + offset);
            p->ipv4 = * ipv4;
            p->ipv4_valid = 1;
            offset += 20;
        }
    }
    if (p->ipv4_valid == 1)
    {
        if (p->ipv4.proto == IPPROTO_TCP)
        {
            const tcp_t * tcp = (const tcp_t *)(buf + offset);
            p->tcp = *tcp;
            p->tcp_valid = 1;
        }
        else if (p->ipv4.proto == IPPROTO_UDP)
        {
            const udp_t * udp = (const udp_t *)(buf + offset);
            p->udp = *udp;
            p->udp_valid = 1;
        }
    }
}