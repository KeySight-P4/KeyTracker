#ifndef DPDK_PCAP_EVERFLOW_H
#define DPDK_PCAP_EVERFLOW_H

#include "packet.h"

#define FLOW_CONTAINER_SIZE 1000000
#define FLOW_POOL_SIZE 10000000

typedef struct flow_key_t {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t proto;
    uint16_t src_port;
    uint16_t dst_port;
} flow_key_t;

typedef struct everflow_flow_container_t {
    bf_key_t key;
    int packet_count;
    uint32_t p4db_packet_stamp;
    int count_enable;
    struct everflow_flow_container_t * next;
} everflow_flow_container_t;

typedef struct everflow_t {
    uint32_t packet_count;
    uint32_t distinct_flow_count;
    uint32_t count_behavior;
    everflow_flow_container_t flow_container[FLOW_CONTAINER_SIZE];
    uint32_t enable;
    uint32_t everflow_90_count;
    uint32_t p4db_90_count;

} everflow_t;

#define FLOW_KEY_SIZE sizeof(flow_key_t)

/**
 *
 * @param ks
 * @param packet
 */
void everflow_count(everflow_t* ks, packet_t* packet);

/**
 *
 * @param file_name
 */
void everflow_print(everflow_t * ef);

#endif //DPDK_PCAP_EVERFLOW_H
