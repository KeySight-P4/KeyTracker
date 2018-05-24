#ifndef PCAP_KEY_H
#define PCAP_KEY_H

typedef struct switch_key_t {
    uint8_t eth_src_mac[6];
    uint8_t eth_dst_mac[6];
} switch_key_t;

#define SWITCH_KEY_SIZE sizeof(switch_key_t)

typedef struct router_key_t {

    // ethertype
    uint8_t dst_mac[6];
    uint8_t src_mac[6];

    uint16_t eth_type;
    // ipv4
    uint32_t dst_addr;

} router_key_t;

#define ROUTER_KEY_SIZE sizeof(router_key_t)

typedef struct nat_key {
    uint32_t src_addr;
    uint32_t dst_addr;
    uint8_t  proto;
    uint16_t src_port;
    uint16_t dst_port;
} nat_key_t;

#define NAT_KEY_SIZE sizeof(nat_key_t)

typedef struct stateful_firewall_key {
    // ipv4
    uint32_t src_addr;
    uint32_t dst_addr;
    uint8_t  proto;
    uint8_t  tcp_ctrl;
    uint16_t src_port;
    uint16_t dst_port;
    // dependency here

} stateful_firewall_key_t;

#define STATEFUL_FIREWALL_KEY_SIZE sizeof(stateful_firewall_key_t)

enum keysight_functions {
    SWITCH,
    ROUTER,
    NAT,
    STATEFUL_FW,
    FUNCTION_NUM
};

#endif //PCAP_KEY_H
