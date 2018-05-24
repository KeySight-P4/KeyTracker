#ifndef PCAP_SAMPLE_H
#define PCAP_SAMPLE_H



#include <stdint.h>
#include "packet.h"
#include "key.h"

#define ROUTER_PREFIX 0xFFFFFFFF
#define DEFAULT_SAMPLE_PERIOD 10

// For L2 Switch

// For Router
//typedef struct sample_router_key_t {
//    uint32_t dst_addr;
//} sample_router_key_t;

typedef struct sample_router_key_container_t {
    router_key_t key;
    uint32_t packet_count;
    uint32_t sampled;
    struct sample_router_key_container_t * next;
} sample_router_key_container_t;


// For NAT
//typedef struct sample_nat_key_t {
//    uint32_t src_addr;
//    uint32_t dst_addr;
//    uint8_t  proto;
//    uint16_t src_port;
//    uint16_t dst_port;
//} sample_nat_key_t;

typedef struct sample_nat_key_container_t {
    nat_key_t key;
    uint32_t packet_count;
    uint32_t sampled;
    struct sample_nat_key_container_t* next;
} sample_nat_key_container_t;


// For Stateful TCP FW
//typedef struct {
//    uint32_t src_addr;
//    uint32_t dst_addr;
//    uint8_t  proto;
//    uint8_t  tcp_ctrl;
//    uint16_t src_port;
//    uint16_t dst_port;
//} sample_tcp_fw_key_t;

typedef struct sample_tcp_fw_key_container_t{
    stateful_firewall_key_t key;
    uint32_t packet_count;
    uint32_t sampled;
    struct sample_tcp_fw_key_container_t * next;
} sample_tcp_fw_key_container_t;


#define SAMPLE_ROUTER_KEY_SIZE sizeof(router_key_t)
#define SAMPLE_NAT_KEY_SIZE sizeof(nat_key_t)
#define SAMPLE_TCP_FW_KEY_SIZE sizeof(stateful_firewall_key_t)

#define SAMPLE_CONTAINER_SIZE 65536

typedef struct sample_t {
    uint64_t packet_count;
    sample_router_key_container_t router_key_container[SAMPLE_CONTAINER_SIZE];
    sample_nat_key_container_t nat_key_container[SAMPLE_CONTAINER_SIZE];
    sample_tcp_fw_key_container_t tcp_fw_key_container[SAMPLE_CONTAINER_SIZE];
    uint32_t router_behavior_count;
    uint32_t nat_behavior_count;
    uint32_t tcp_fw_behavior_count;
    uint32_t enable;
    uint32_t sample_period;
    uint32_t router_sample_count;
    uint32_t nat_sample_count;
    uint32_t tcp_fw_sample_count;
} sample_t;

void sample_count(sample_t * sample, packet_t * packet);

#define SAMPLE_EXTRACT(key) \
    sample_extract_##key(&(key), packet)




#endif //PCAP_SAMPLE_H
