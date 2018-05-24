#ifndef PCAP_KEYTRACKER_H
#define PCAP_KEYTRACKER_H

#include <stdint.h>
#include "packet.h"
#include "key.h"

#define MAX_BF_NUM 3
#define MAX_BF_SIZE 16*1024*1024
#define DEFAULT_BF_MAX 1
#define BF_KEY_CONTAINER_SIZE 1000000
#define BF_KEY_POOL_SIZE  10000000

#define DEFAULT_PACKET_PER_WINDOW 100000
#define DEFAULT_WINDOW_NUM 4
#define DEFAULT_BUCKET_NUM 4



#define P4_ID 2

#if P4_ID == 0
#define KEYSIGHT_KEY switch_key_t
#define KEYSIGHT_KEY_EXTRACTOR keysight_extract_switch_key
#elif P4_ID == 1
#define KEYSIGHT_KEY router_key_t
#define KEYSIGHT_KEY_EXTRACTOR keysight_extract_router_key
#elif P4_ID == 2
#define KEYSIGHT_KEY nat_key_t
#define KEYSIGHT_KEY_EXTRACTOR keysight_extract_nat_key
#else
#define KEYSIGHT_KEY stateful_firewall_key_t
#define KEYSIGHT_KEY_EXTRACTOR keysight_extract_stateful_firewall_key
#endif

enum update_alg {
    BSBF = 0,
    BSBFSD,
    RLBSBF,
    STABLE_BF,
    BFQ,
    SBF,
    /** Deprecated Algorithms **/
    KEYSIGHT_BSBF,
    KEYSIGHT_BSBFSD,
    KEYSIGHT_RLBSBF,
    KEYSIGHT_NEG_BSBF,
    KEYSIGHT_NEG_BSBFSD,
    KEYSIGHT_NEG_RLBSBF,
    /** Deprecated Algorithms **/
    UPDATE_ALG_NUM
};

extern char* BF_ALG_NAMES[];

/**
 * Wrapper for different keys
 * */
typedef struct bf_key_t {
    KEYSIGHT_KEY key;
} bf_key_t;

/**
 * Contain a key, the packet count, and recored packet stamp
 */
typedef struct keysight_key_container_t {
    bf_key_t key;
    uint32_t packet_count; // How many packets hit this key
    uint32_t packet_stamp; // The last hitted packet counter
    struct keysight_key_container_t * next; // The next container (in the same bucket)
} keysight_key_container_t;

#define BF_KEY_SIZE sizeof(struct bf_key_t)
/**
 * KeySight struct
 */
typedef struct keysight_t {
    uint32_t packet_count; // All packet count
    uint32_t postcard_count;
    uint32_t false_positive;
    uint32_t false_negative;
    uint32_t recent_false_negative;
    uint32_t recent_false_positive;
    uint32_t distinct_behavior_count;
    uint32_t random_seed;
    uint64_t bf[MAX_BF_NUM][MAX_BF_SIZE];
    uint32_t bf_len[MAX_BF_NUM];
    keysight_key_container_t key_container[BF_KEY_CONTAINER_SIZE];

    int enable;
    uint32_t bf_size;
    uint32_t bf_alg;
    uint32_t bf_num;
    uint32_t packet_per_window;
    uint32_t window_num;
    uint32_t bucket_num;
    uint32_t bf_max;
} keysight_t;

void keysight_extract_router_key(packet_t* packet, router_key_t* key);
void keysight_extract_stateful_firewall_key(packet_t* packet, stateful_firewall_key_t* key);
void keysight_extract_nat_key(packet_t* packet, nat_key_t* key);

void keysight_count(keysight_t* ks, packet_t * packet);

#endif //DPDK_PCAP_KEYSIGHT_H
