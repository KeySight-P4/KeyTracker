#include <memory.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include "motivation.h"
#include "hash.h"

#define MOTIVATION_POOL_SIZE (65536*256)

switch_key_container_t switch_key_pool[MOTIVATION_POOL_SIZE];
uint32_t switch_key_pool_ptr = 0;

router_key_container_t router_key_pool[MOTIVATION_POOL_SIZE];
uint32_t router_key_pool_ptr = 0;

nat_key_container_t nat_key_pool[MOTIVATION_POOL_SIZE];
uint32_t nat_key_pool_ptr = 0;

tcp_fw_key_container_t tcp_fw_key_pool[MOTIVATION_POOL_SIZE];
uint32_t tcp_fw_key_pool_ptr = 0;


/**
 *
 * @param key
 * @param packet
 */
static inline void
motivation_extract_switch_key(switch_key_t* key,
                              packet_t* packet)
{
    if (key == NULL)
    {
        printf("Key should not be NULL.\n");
        exit(1);
    }
    memset(key, 0, sizeof(switch_key_t));
    if (packet->eth_valid)
    {
        memcpy(key->eth_dst_mac, packet->eth.dst_mac, 6);
        memcpy(key->eth_src_mac, packet->eth.src_mac, 6);
    }
}

/**
 *
 * @param key
 * @param packet
 */
static inline void
motivation_extract_router_key(router_key_t* key,
                              packet_t* packet)
{
    assert(key != NULL);

    memset(key, 0, sizeof(router_key_t));
    if (packet->ipv4_valid)
    {
        key->dst_addr = SWAP32(packet->ipv4.dst_ip) & ROUTER_PREFIX;
    }
}

/**
 *
 * @param key
 * @param packet
 */
static inline void
motivation_extract_tcp_fw_key(stateful_firewall_key_t* key,
                              packet_t* packet)
{
    assert (key != NULL);

    memset(key, 0, sizeof(stateful_firewall_key_t));

    if (packet->ipv4_valid)
    {
        key->dst_addr = SWAP32(packet->ipv4.dst_ip);
        key->src_addr = SWAP32(packet->ipv4.src_ip);
        key->proto = packet->ipv4.proto;
    }

    if (packet->tcp_valid) {
        key->src_port = SWAP16(packet->tcp.src_port);
        key->dst_port = SWAP16(packet->tcp.dst_port);
        key->tcp_ctrl = packet->tcp.ctrl;
    }
}

/**
 *
 * @param key
 * @param packet
 */
static inline void
motivation_extract_nat_key(nat_key_t* key,
                           packet_t* packet) {
    assert (key != NULL);

    memset(key, 0, NAT_KEY_SIZE);

    if (packet->ipv4_valid)
    {
        key->dst_addr = SWAP32(packet->ipv4.dst_ip);
        key->src_addr = SWAP32(packet->ipv4.src_ip);
        key->proto = packet->ipv4.proto;
    }

    if (packet->tcp_valid)
    {
        key->src_port = SWAP16(packet->tcp.src_port);
        key->dst_port = SWAP16(packet->tcp.dst_port);
    }
    else if (packet->udp_valid)
    {
        key->src_port = SWAP16(packet->udp.src_port);
        key->dst_port = SWAP16(packet->udp.dst_port);
    }
}


static void
motivation_switch_count(motivation_t * motivation,
                        switch_key_t* key)
{
    int idx = hash_crc32(key, sizeof(switch_key_t), CRC32)
              % MOTIVATION_CONTAINER_SIZE;
    switch_key_container_t * kc =
            &motivation->switch_key_container[idx];
    while(kc->next != NULL) {
        kc = kc->next;
        if (key_compare(&kc->key, key, SWITCH_KEY_SIZE) == 0)
        {
            kc->packet_count ++;
            return;
        }
    }

    if (kc->next == NULL) {
        kc->next = &switch_key_pool[switch_key_pool_ptr++];
        kc = kc->next;
        kc->key = *key;
        kc->packet_count = 1;
        kc->next = NULL;
        motivation->switch_behavior_count ++;
    }
}

/**
 *
 * @param motivation
 * @param key
 */
static void
motivation_router_count(motivation_t * motivation,
                        router_key_t* key)
{
    int idx = hash_crc32(key, ROUTER_KEY_SIZE, CRC32)
              % MOTIVATION_CONTAINER_SIZE;
    router_key_container_t * kc =
            &motivation->router_key_container[idx];
    while(kc->next != NULL) {
        kc = kc->next;
        if (key_compare(&kc->key, key, ROUTER_KEY_SIZE) == 0)
        {
            kc->packet_count ++;
            return;
        }
    }

    if (kc->next == NULL)
    {
        kc->next = &router_key_pool[router_key_pool_ptr++];
        kc = kc->next;
        kc->key = *key;
        kc->packet_count = 1;
        kc->next = NULL;
        motivation->router_behavior_count ++;
    }
}

/**
 *
 * @param motivation
 * @param key
 */
static void
motivation_nat_count(motivation_t * motivation,
                     nat_key_t* key)
{
    int idx = hash_crc32(key, NAT_KEY_SIZE, CRC32)
              % MOTIVATION_CONTAINER_SIZE;
    nat_key_container_t * kc =
            &motivation->nat_key_container[idx];
    while(kc->next != NULL)
    {
        kc = kc->next;
        if (key_compare(&kc->key, key, NAT_KEY_SIZE) == 0)
        {
            kc->packet_count ++;
            return;
        }
    }

    if (kc->next == NULL)
    {
        kc->next = &nat_key_pool[nat_key_pool_ptr++];
        kc = kc->next;
        kc->key = *key;
        kc->packet_count = 1;
        kc->next = NULL;
        motivation->nat_behavior_count ++;
    }
}

/**
 *
 * @param motivation
 * @param key
 */
static void
motivation_tcp_fw_count(motivation_t * motivation,
                        stateful_firewall_key_t* key)
{
    int idx = hash_crc32(key, STATEFUL_FIREWALL_KEY_SIZE, CRC32)
              % MOTIVATION_CONTAINER_SIZE;
    tcp_fw_key_container_t * kc =
            &motivation->tcp_fw_key_container[idx];
    while(kc->next != NULL)
    {
        kc = kc->next;
        if (key_compare(&kc->key, key, STATEFUL_FIREWALL_KEY_SIZE) == 0)
        {
            kc->packet_count ++;
            return;
        }
    }

    if (kc->next == NULL)
    {
        kc->next = &tcp_fw_key_pool[tcp_fw_key_pool_ptr++];
        kc = kc->next;
        kc->key = *key;
        kc->packet_count = 1;
        kc->next = NULL;
        motivation->tcp_fw_behavior_count ++;
    }
}

/**
 *
 * @param motivation
 * @param packet
 */
void
motivation_count(motivation_t * motivation,
                 packet_t* packet)
{
    switch_key_t switch_key;
    router_key_t router_key;
    nat_key_t nat_key;
    stateful_firewall_key_t tcp_fw_key;
    motivation->packet_count++;
    MOTIVATION_EXTRACT(tcp_fw_key);
    MOTIVATION_EXTRACT(switch_key);
    MOTIVATION_EXTRACT(router_key);
    MOTIVATION_EXTRACT(nat_key);

    motivation_switch_count(motivation, &switch_key);
    motivation_router_count(motivation, &router_key);
    motivation_nat_count(motivation, &nat_key);
    motivation_tcp_fw_count(motivation, &tcp_fw_key);
}

/**
 *
 * @param x
 * @param y
 * @param z
 * @return
 */
static inline uint32_t 
min(uint32_t x, uint32_t y, uint32_t z)
{
    if (x > y) {
        return y > z ? z : y;
    } else {
        return x > z ? z : x;
    }
}

/**
 *
 * @param x
 * @param y
 * @param z
 * @return
 */
static inline uint32_t 
max(uint32_t x, uint32_t y, uint32_t z)
{
    if (x < y)
    {
        return y < z ? z : y;
    }
    else
    {
        return x < z ? z : x;
    }
}

/**
 *
 * @param buf
 * @param i
 * @param j
 * @param size
 */
static inline void
sort(uint32_t* buf, int i, int j, int size)
{
    int tmp1 = min(buf[i], buf[j], buf[size - 1 - i]);
    int tmp2 = max(buf[i], buf[j], buf[size - 1 - i]);
    buf[j] = buf[i] + buf[j] + buf[size - 1 - i] - tmp1 - tmp2;
    buf[i] = (uint32_t) tmp2;
    buf[size - 1 - i] = (uint32_t) tmp1;
}

/**
 *
 */
#define LAZY_TEMPLATE(X) \
    best_sum = worst_sum = 0; \
    cur = 0;                \
    packet_gap = X##_key_pool_ptr / 100; \
    fp = fopen("motivation_"#X".txt", "w"); \
    for (i = 0; i < X##_key_pool_ptr; i ++) \
        packet_count[i] = X##_key_pool[i].packet_count; \
    for (i = 0; i < X##_key_pool_ptr; i ++) { \
        uint32_t max = i, min = X##_key_pool_ptr - 1 - i;              \
        for (j = i + 1; j < X##_key_pool_ptr - 1 - i; j ++)  {              \
            min = packet_count[j] > packet_count[min] ? min : j;        \
            max = packet_count[j] < packet_count[max] ? max : j;        \
        }                                                               \
        if (i % 100000 == 0) {                                               \
            printf("LAZY: %d\n", i);                                    \
        }                                                               \
        if (max != i)                                                    \
            sort(packet_count, i, max, X##_key_pool_ptr);                   \
        if (min != X##_key_pool_ptr - 1 - i)                            \
            sort(packet_count, i, min, X##_key_pool_ptr);                   \
    }                           \
    for (i = 0; i < X##_key_pool_ptr; i ++) {                                 \
        best_sum += packet_count[X##_key_pool_ptr - 1 - i]; \
        worst_sum += packet_count[i];                           \
        if (best_sum > cur)    {                                   \
            cur += gap;                 \
            fprintf(fp, "%lf\t%lf\t%lf\t%lf\t%lf\n", (i + 1)*1.0/X##_key_pool_ptr, best_sum*1.0/motivation->packet_count, worst_sum*1.0/motivation->packet_count, (i + 1)*1.0/X##_key_pool_ptr, X##_key_pool_ptr*1.0/motivation->packet_count);\
        }                                                                               \
        else if (i % packet_gap == 0) { \
            fprintf(fp, "%lf\t%lf\t%lf\t%lf\t%lf\n", (i + 1)*1.0/X##_key_pool_ptr, best_sum*1.0/motivation->packet_count, worst_sum*1.0/motivation->packet_count, (i + 1)*1.0/X##_key_pool_ptr, X##_key_pool_ptr*1.0/motivation->packet_count);\
        }                       \
    }           \
    fclose(fp);                                                                      \

#define FAST_TEMPLATE(X) \
    fp = fopen("motivation_"#X".txt", "w"); \
    for (i = 0; i < X##_key_pool_ptr; i ++) { \
        fprintf(fp, "%lf\t%lf\t%d\n", (i + 1)*1.0/X##_key_pool_ptr, X##_key_pool_ptr*1.0/motivation->packet_count, X##_key_pool[i].packet_count);\
    }                           \
    fclose(fp);                     \

uint32_t packet_count[10000000];

void 
motivation_flow_print(motivation_t * motivation)
{
    FILE* fp = NULL;
    int i, j;
    uint32_t best_sum, worst_sum;
    uint32_t cur, gap = motivation->packet_count / 100, packet_gap;
    FAST_TEMPLATE(switch);
    FAST_TEMPLATE(router);
    FAST_TEMPLATE(nat);
    FAST_TEMPLATE(tcp_fw);
}
