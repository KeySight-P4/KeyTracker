#include <memory.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <time.h>
#include "keytracker.h"
#include "hash.h"

char* BF_ALG_NAMES[UPDATE_ALG_NUM] =  {
        [BSBF] = "BSBF",
        [BSBFSD] = "BSBFSD",
        [RLBSBF] = "RLBSBF",
        [STABLE_BF] = "STABLE_BF",
        [BFQ] = "BFQ",
        [SBF] = "SBF",
};

keysight_key_container_t key_pool[BF_KEY_POOL_SIZE];
int pool_ptr = 0;

/**
 *
 * @param ks
 * @param key
 * @return
 */
static inline int
keysight_lookup(keysight_t* ks, bf_key_t* key)
{
    static int packet_window = 0; 
    if (packet_window == 0)
        packet_window = ks->packet_per_window * (ks->window_num - 1);
    int idx = hash_crc32(key, BF_KEY_SIZE, CRC32) % BF_KEY_CONTAINER_SIZE;
    keysight_key_container_t * kc = &ks->key_container[idx];
    while(likely(kc->next != NULL)) 
    {
        kc = kc->next;
        if (key_compare(&kc->key, key, BF_KEY_SIZE) == 0) 
        {
             return 1;
        }
    }
    if ((ks->packet_count - kc->packet_stamp) < packet_window) 
    {
        ks->recent_false_positive++;
    }
    return 0;
}

/**
 *
 * @param ks
 * @param key
 * @param count_flag
 */
static inline void
keysight_insert(keysight_t* ks, bf_key_t* key, int count_flag)
{
    static int packet_window = 0; 
    if (packet_window == 0)
        packet_window = ks->packet_per_window * (ks->window_num - 1);
    int idx = hash_crc32(key, BF_KEY_SIZE, CRC32) % BF_KEY_CONTAINER_SIZE;
    keysight_key_container_t * kc = &ks->key_container[idx];
    while(likely(kc->next != NULL)) {
        kc = kc->next;
        if (key_compare(&kc->key, key, BF_KEY_SIZE) == 0)
        {
            kc->packet_count ++;

            if (count_flag == 1) {
                ks->false_negative ++;
                if ((ks->packet_count - kc->packet_stamp) 
                    < packet_window)
                {
                    ks->recent_false_negative++;
                }
            }
            kc->packet_stamp = ks->packet_count;
            return;
        }
    }

    if (kc->next == NULL) {
        kc->next = &key_pool[pool_ptr++];
        kc = kc->next;
        kc->key = *key;
        kc->next = NULL;
        kc->packet_stamp = ks->packet_count;
        ks->distinct_behavior_count++;
    }
}

/**
 *
 * @param packet
 * @param key
 */
static inline void
keysight_extract_switch_key(packet_t* packet, switch_key_t* key) {
    assert(packet != NULL);
    assert(packet->eth_valid == 1);

    copy_eth_addr(key->eth_dst_mac, packet->eth.dst_mac);
    copy_eth_addr(key->eth_src_mac, packet->eth.src_mac);
}

/**
 *
 * @param packet
 * @param key
 */
void
keysight_extract_router_key(packet_t* packet, router_key_t* key)
{
    assert(packet != NULL);
    assert(packet->ipv4_valid == 1);

    key->eth_type =  0x0800;
    key->dst_addr = SWAP32(packet->ipv4.dst_ip);
    copy_eth_addr(key->dst_mac, packet->eth.dst_mac);
    copy_eth_addr(key->src_mac, packet->eth.src_mac);
}

/**
 *
 * @param packet
 * @param key
 */
void
keysight_extract_stateful_firewall_key(packet_t* packet, stateful_firewall_key_t* key)
{
    assert(packet != NULL);
    assert(packet->ipv4_valid == 1);

    key->dst_addr = SWAP32(packet->ipv4.dst_ip);
    key->src_addr = SWAP32(packet->ipv4.src_ip);
    key->proto = packet->ipv4.proto;
    key->tcp_ctrl = 0;
    key->dst_port = 0;

    if (packet->tcp_valid)
    {
        key->src_port = SWAP16(packet->tcp.src_port);
        key->dst_port = SWAP16(packet->tcp.dst_port);
        key->tcp_ctrl = packet->tcp.ctrl;
    } else if (packet->udp_valid)
    {
        key->src_port = SWAP16(packet->udp.src_port);
        key->dst_port = SWAP16(packet->udp.dst_port);
    }
}

/**
 *
 * @param packet
 * @param key
 * @return
 */
void
keysight_extract_nat_key(packet_t* packet, nat_key_t* key)
{
    assert(packet != NULL);
    assert(packet->ipv4_valid == 1);

    key->dst_addr = SWAP32(packet->ipv4.dst_ip),
    key->src_addr = SWAP32(packet->ipv4.src_ip);
    key->proto = packet->ipv4.proto;
    key->src_port = 0;
    key->dst_port = 0;

    if (packet->tcp_valid) {
        key->src_port = SWAP16(packet->tcp.src_port);
        key->dst_port = SWAP16(packet->tcp.dst_port);
    } else if (packet->udp_valid) {
        key->src_port = SWAP16(packet->udp.src_port);
        key->dst_port = SWAP16(packet->udp.dst_port);
    }
}

/**
 *
 * @param ks
 * @param count_flag
 */
static void
bsbf_update(keysight_t* ks, int count_flag) {
    if (count_flag != 1) {
        return;
    }
    srand(ks->random_seed);
    int i;
    for (i = 0; i < ks->bf_num; i++) {
        ks->bf[i][rand() % ks->bf_size] = 0;
    }
    ks->random_seed = (uint32_t) rand() + time(NULL);
}

/**
 *
 * @param ks
 * @param count_flag
 */
static void
bsbfsd_update(keysight_t* ks, int count_flag) {
    srand(ks->random_seed);
    ks->bf[rand()%ks->bf_num][rand()%ks->bf_size] = 0;
    ks->random_seed = (uint32_t) rand() + time(NULL);
}

/**
 *
 * @param ks
 * @param count_flag
 */
static void
rlbsbf_update(keysight_t* ks, int count_flag) {
    if (count_flag != 1) {
        return;
    }
    srand(ks->random_seed);
    int i;
    for (i = 0; i < ks->bf_num; i++) {
        if (ks->bf_len[i] > rand() % ks->bf_size) {
            ks->bf[i][rand() % ks->bf_size] = 0;
        }
    }
    ks->random_seed = (uint32_t) rand() + time(NULL);
}

/**
 *
 * @param ks
 * @param count_flag
 */
static void
keysight_bsbfsd_update(keysight_t* ks, int count_flag) {
    srand(ks->random_seed);
    if (count_flag == 1) {
        ks->bf[rand()%ks->bf_num][rand()%ks->bf_size] = 0;
    }
    else if (count_flag == 2) {
        if (rand() % 100 < 100) {
            ks->bf[rand()%ks->bf_num][rand()%ks->bf_size] = 0;
        }
    }
    ks->random_seed = (uint32_t) rand() + time(NULL);
}

/**
 *
 * @param ks
 * @param count_flag
 */
static void
keysight_bsbf_update(keysight_t* ks, int count_flag)
{
    srand(ks->random_seed);
    int i;
    if (count_flag == 1) {
        for (i = 0; i < ks->bf_num; i++) {
            ks->bf[i][rand() % ks->bf_size] = 0;
        }
    }
    else if (count_flag == 2) {
        for (i = 0; i < ks->bf_num; i++) {
            ks->bf[i][rand() % ks->bf_size] = 0;
        }
    }

    ks->random_seed = (uint32_t) rand() + time(NULL);
}

/**
 *
 * @param ks
 * @param count_flag
 */
static void
keysight_rlbsbf_update(keysight_t* ks, int count_flag) {
    srand(ks->random_seed);
    int i;
    if (count_flag == 1) {
        for (i = 0; i < ks->bf_num; i++) {
            if (ks->bf_len[i] > rand() % ks->bf_size) {
                ks->bf[i][rand() % ks->bf_size] = 0;
            }
        }
    }
    else if (count_flag == 2) {
        if (rand() % 100 < 100) {
            for (i = 0; i < ks->bf_num; i++) {
                if (ks->bf_len[i] > rand() % ks->bf_size) {
                    ks->bf[i][rand() % ks->bf_size] = 0;
                }
            }
        }
    }

    ks->random_seed = (uint32_t) rand() + time(NULL);
}

/**
 *
 * @param ks
 * @param count_flag
 */
static void
keysight_neg_bsbfsd_update(keysight_t* ks, int count_flag)
{
    srand(ks->random_seed);
    if (count_flag == 1) {
        ks->bf[rand() % ks->bf_num][rand() % ks->bf_size] = 0;
    }
    else if (count_flag == 2)
    {
        if (rand() % 100 < 100)
        {
            ks->bf[rand() % ks->bf_num][rand() % ks->bf_size] = 0;
        }
    } else if (ks->false_negative * 100.0 / ks->distinct_behavior_count < 20)
    {
        ks->bf[rand() % ks->bf_num][rand() % ks->bf_size] = 0;
    }
    ks->random_seed = (uint32_t) rand() + time(NULL);
}

/**
 *
 * @param ks
 * @param count_flag
 */
static void
keysight_neg_bsbf_update(keysight_t* ks, int count_flag)
{
    srand(ks->random_seed);
    int i;
    if (count_flag == 1)
    {
        for (i = 0; i < ks->bf_num; i++)
        {
            ks->bf[i][rand() % ks->bf_size] = 0;
        }
    }
    else if (count_flag == 2)
    {
        for (i = 0; i < ks->bf_num; i++)
        {
            ks->bf[i][rand() % ks->bf_size] = 0;
        }
    }
    else if (ks->false_negative * 100.0 / ks->distinct_behavior_count < 20)
    {
        for (i = 0; i < ks->bf_num; i++)
        {
            ks->bf[i][rand() % ks->bf_size] = 0;
        }
    }

    ks->random_seed = (uint32_t) rand() + time(NULL);
}

/**
 *
 * @param ks
 * @param count_flag
 */
static void
keysight_neg_rlbsbf_update(keysight_t* ks, int count_flag) {
    srand(ks->random_seed);
    int i;
    if (count_flag == 1) {
        for (i = 0; i < ks->bf_num; i++) {
            if (ks->bf_len[i] > rand() % ks->bf_size) {
                ks->bf[i][rand() % ks->bf_size] = 0;
            }
        }
    }
    else if (count_flag == 2) {
        if (rand() % 100 < 100) {
            for (i = 0; i < ks->bf_num; i++) {
                if (ks->bf_len[i] > rand() % ks->bf_size) {
                    ks->bf[i][rand() % ks->bf_size] = 0;
                }
            }
        }
    } else if (ks->false_negative * 100.0 / ks->distinct_behavior_count < 20) {
        for (i = 0; i < ks->bf_num; i++) {
            ks->bf[i][rand() % ks->bf_size] = 0;
        }
    }

    ks->random_seed = (uint32_t) rand() + time(NULL);
}

/**
 *
 * @param ks
 * @param count_flag
 */
static void
stable_bf_update(keysight_t* ks, int count_flag) {
    srand(ks->random_seed);
    int i;

    for (i = 0; i < ks->bf_num; i++) {
        if (ks->bf_len[i] > rand() % ks->bf_size) {
            int tmp = rand()  % ks->bf_size;
            if (ks->bf[i][tmp] > 0) {
                ks->bf[i][tmp] --;
            }
        }
    }

    ks->random_seed = (uint32_t) rand() + time(NULL);
}

typedef void (*update_func_t) (keysight_t *, int);
typedef int (*count_func_t) (keysight_t* ks, packet_t* packet);

update_func_t update_funcs [UPDATE_ALG_NUM] = {
        [BSBF] = bsbf_update,
        [BSBFSD] = bsbfsd_update,
        [RLBSBF] = rlbsbf_update,
        [STABLE_BF] = stable_bf_update,
        [SBF] = NULL,
        [BFQ] = NULL,
        [KEYSIGHT_BSBF] = keysight_bsbf_update,
        [KEYSIGHT_BSBFSD] = keysight_bsbfsd_update,
        [KEYSIGHT_RLBSBF] = keysight_rlbsbf_update,
        [KEYSIGHT_NEG_BSBF] = keysight_neg_bsbf_update,
        [KEYSIGHT_NEG_BSBFSD] = keysight_neg_bsbfsd_update,
        [KEYSIGHT_NEG_RLBSBF] = keysight_neg_rlbsbf_update,
};


/**
 * Extract a key from packets
 * @param packet the packet structure
 * @param bf_key the keysight bloom filter key
 */
static inline void
keysight_extract_key(packet_t * packet,
                     bf_key_t * bf_key) {
    KEYSIGHT_KEY_EXTRACTOR(packet, &bf_key->key);
}

/**
 *
 * @param ks
 * @param packet
 * @return
 */
static int
sbf_count(keysight_t* ks,
          packet_t* packet) {
    int count_flag = 0;
    int i;

    bf_key_t key;

    // Populate the key
    keysight_extract_key(packet, &key);

    ks->packet_count++;
    int window_idx = (ks->packet_count / ks->packet_per_window) % ks->window_num;

    for (i = 0; i < ks->bf_num; i ++)
    { // Iterate through K arrays
        uint32_t idx = hash_crc32(&key, BF_KEY_SIZE, i) ;
        uint32_t bucket_idx = idx % ks->bucket_num;
        idx = idx / ks->bucket_num % ks->bf_size;
        uint64_t mask = ((uint64_t)((1 << ks->window_num) - 1)) << (bucket_idx * ks->window_num);
        //uint64_t mask = ((uint64_t)(1 << window_idx )) << (bucket_idx * ks->window_num);
        //printf("MASK: %llu\n", ks->bf[i][idx]&mask);
        mask = mask ^ ((uint64_t)(1 << ((window_idx + 1) % ks->window_num))) << (bucket_idx * ks->window_num);

        if((ks->bf[i][idx] & mask) == 0)
        {
           count_flag = 1;
        }

        // Set the current bit to 1
        ks->bf[i][idx] |= 1 << (window_idx + bucket_idx * ks->window_num);

        int j;
        for (j = 0; j < ks->bucket_num; j ++)
        {
            int offset = ((window_idx + 1) % ks->window_num) + j * ks->window_num;

            // Clear the oldest bits
            ks->bf[i][idx] &= ~(uint64_t)(1 << offset);
        }
    }

    if (count_flag == 1)
    {
        ks->postcard_count ++; // Labeled as negative
    }

    if (count_flag == 0)
    { // Label as positive
        if (keysight_lookup(ks, &key) == 0)
        {
            ks->false_positive ++;
            count_flag = 2;
        } 
    }
    keysight_insert(ks, &key, count_flag);
    return count_flag;
}

/**
 *
 * @param ks
 * @param packet
 * @return
 */
static int
rbf_count(keysight_t* ks, packet_t* packet)
{
    int count_flag = 0;
    int i, j;
    bf_key_t key;
    keysight_extract_key(packet, &key);
    ks->packet_count++;
    int window_idx = (ks->packet_count / ks->packet_per_window) % ks->window_num;
    for (i = 0; i < ks->bf_num; i ++)
    {
        uint32_t idx = hash_crc32(&key, BF_KEY_SIZE, i) ;
        uint32_t bucket_idx = idx % ks->bucket_num;
        idx = idx / ks->bucket_num % ks->bf_size;
        uint64_t mask = ((uint64_t)((1 << ks->window_num) - 1)) << (bucket_idx * ks->window_num);
        mask = mask ^ ((uint64_t)(1 << ((window_idx + 1) % ks->window_num))) << (bucket_idx * ks->window_num);
        if((ks->bf[i][idx] & mask) == 0)
        {
            count_flag = 1;
        }

        ks->bf[i][idx] |= 1 << (window_idx + bucket_idx * ks->window_num);
        /*
        for (j = 0; j < ks->bucket_num; j++) {
            int offset = ((window_idx + 1) % ks->window_num) + j * ks->window_num;
            ks->bf[i][clear_idx] &= ~(uint64_t) (1 << offset);
        }
        */
    }
    int b;
    if (unlikely(ks->packet_count % ks->packet_per_window == 0))
    {
        for (b = 0; b < ks->bf_num; b++)
        {
            for (i = 0; i < ks->bf_size; i++)
            {
                for (j = 0; j < ks->bucket_num; j++)
                {
                    int offset = (window_idx + 1) % ks->window_num + j * ks->window_num;
                    // Clear the oldest bits
                    ks->bf[b][i] &= ~(uint64_t) (1 << offset);
                }
            }
        }
    }


    if (count_flag == 1)
    {
        ks->postcard_count ++;
    }

    if (count_flag == 0) {
        if (keysight_lookup(ks, &key) == 0)
        { // if you can not find the key, it implies that you falsely report this as a positive (false positivse)
            ks->false_positive ++;
            count_flag = 2;
        }
    }

    keysight_insert(ks, &key, count_flag);
    return count_flag;
}

/**
 * Bloom filter count
 * @param ks
 * @param packet
 * @return
 */
static int
bf_count(keysight_t* ks, packet_t* packet) // Count with the legacy bloom filter
{
    int count_flag = 0;
    int i;
    bf_key_t key;
    keysight_extract_key(packet, &key);
    ks->packet_count++;
    
    for (i = 0; i < ks->bf_num; i ++)
    {
        uint32_t idx = hash_crc32(&key, BF_KEY_SIZE, i) % ks->bf_size;
        if(ks->bf[i][idx] == 0)
        {
            ks->bf_len[i] ++;
            count_flag = 1;
        }
        ks->bf[i][idx] = ks->bf_max;
    }

    if (count_flag == 1)
    {
        ks->postcard_count ++;
    }

    if (count_flag == 0)
    {
        if (keysight_lookup(ks, &key) == 0)
        {
            ks->false_positive ++;
            count_flag = 2;
        } 
    }
    keysight_insert(ks, &key, count_flag);
    return count_flag;
}

// Count algorithm
count_func_t count_funcs [UPDATE_ALG_NUM] = {
        [BSBF] = bf_count,
        [BSBFSD] = bf_count,
        [RLBSBF] = bf_count,
        [STABLE_BF] = bf_count,
        [BFQ] = rbf_count,
        [SBF] = sbf_count
};


/**
 *
 * @param ks
 * @param packet
 */
void
keysight_count(keysight_t* ks, packet_t* packet)
{
    assert(ks != NULL);
    assert(packet != NULL);
    int count_flag = count_funcs[ks->bf_alg](ks, packet);
    if (update_funcs[ks->bf_alg] != NULL)
    {
        update_funcs[ks->bf_alg](ks, count_flag);
    }
}
