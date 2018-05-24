#ifndef DPDK_PCAP_PROTOCOL_H
#define DPDK_PCAP_PROTOCOL_H

#define ETHER_TYPE_IPv4 0x0800 /**< IPv4 Protocol. */
#define ETHER_TYPE_IPv6 0x86DD /**< IPv6 Protocol. */
#define ETHER_TYPE_ARP  0x0806 /**< Arp Protocol. */
#define ETHER_TYPE_RARP 0x8035 /**< Reverse Arp Protocol. */
#define ETHER_TYPE_VLAN 0x8100 /**< IEEE 802.1Q VLAN tagging. */
#define ETHER_TYPE_QINQ 0x88A8 /**< IEEE 802.1ad QinQ tagging. */
#define ETHER_TYPE_1588 0x88F7 /**< IEEE 802.1AS 1588 Precise Time Protocol. */
#define ETHER_TYPE_SLOW 0x8809 /**< Slow protocols (LACP and Marker). */
#define ETHER_TYPE_TEB  0x6558 /**< Transparent Ethernet Bridging. */
#define ETHER_TYPE_LLDP 0x88CC /**< LLDP Protocol. */

typedef struct ethernet_t {
    uint8_t dst_mac[6];
    uint8_t src_mac[6];
    uint16_t eth_type;
} ethernet_t;

#define IPPROTO_ICMP 1
#define IPPROTO_UDP 17
#define IPPROTO_TCP 6

typedef struct ipv4_t {
    uint8_t ver_ihl;
    uint8_t tos;
    uint16_t tot_en;
    uint16_t ipid;
    uint16_t frag;
    uint8_t ttl;
    uint8_t proto;
    uint16_t checksum;
    uint32_t src_ip;
    uint32_t dst_ip;
} ipv4_t;

typedef struct vlan_t {
    uint16_t value;
    uint16_t eth_type;
} vlan_t;


typedef struct tcp_t {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t  ack;
    uint8_t flag;
    uint8_t ctrl;
    uint16_t rwnd;
    uint16_t checksum;
    uint16_t ptr;
} tcp_t;

typedef struct udp_t {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;
} udp_t;
#endif //DPDK_PCAP_PROTOCOL_H
