#ifndef DPDK_PCAP_MOTIVATION_H
#define DPDK_PCAP_MOTIVATION_H

#include <stdint.h>
#include "packet.h"
#include "key.h"

#define ROUTER_PREFIX 0xFFFFFFFF

#define MOTIVATION_FLOW_PRINT 1


typedef struct switch_key_container_t {
    switch_key_t key;
    uint32_t packet_count;
    struct switch_key_container_t * next;
} switch_key_container_t;

typedef struct router_key_container_t {
    router_key_t key;
    uint32_t packet_count;
    struct router_key_container_t * next;
} router_key_container_t;

typedef struct nat_key_container_t {
    nat_key_t key;
    uint32_t packet_count;
    struct nat_key_container_t* next;
} nat_key_container_t;

typedef struct tcp_fw_key_container_t{
    stateful_firewall_key_t key;
    uint32_t packet_count;
    struct tcp_fw_key_container_t * next;
} tcp_fw_key_container_t;

#define MOTIVATION_CONTAINER_SIZE 65536

typedef struct motivation_t {
    uint32_t packet_count;
    switch_key_container_t switch_key_container[MOTIVATION_CONTAINER_SIZE];
    router_key_container_t router_key_container[MOTIVATION_CONTAINER_SIZE];
    nat_key_container_t nat_key_container[MOTIVATION_CONTAINER_SIZE];
    tcp_fw_key_container_t tcp_fw_key_container[MOTIVATION_CONTAINER_SIZE];
    uint32_t switch_behavior_count;
    uint32_t router_behavior_count;
    uint32_t nat_behavior_count;
    uint32_t tcp_fw_behavior_count;
    uint32_t enable;
} motivation_t;

/**
 *
 * @param motivation
 * @param packet
 */
void motivation_count(motivation_t * motivation, packet_t * packet);

/**
 * Print flow information based on
 * @param motivation
 */
void motivation_flow_print(motivation_t * motivation);

/**
 * Motivation extraction key wrapper
 */
#define MOTIVATION_EXTRACT(key) \
    motivation_extract_##key(&(key), packet)




#endif //DPDK_PCAP_MOTIVATION_H
