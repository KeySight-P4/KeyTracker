#include <memory.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include "hash.h"
#include "sample.h"

#define SAMPLE_POOL_SIZE (65536*256)

sample_router_key_container_t sample_router_key_pool[SAMPLE_POOL_SIZE];
uint32_t sample_router_key_pool_ptr = 0;

sample_nat_key_container_t sample_nat_key_pool[SAMPLE_POOL_SIZE];
uint32_t sample_nat_key_pool_ptr = 0;

sample_tcp_fw_key_container_t sample_tcp_fw_key_pool[SAMPLE_POOL_SIZE];
uint32_t sample_tcp_fw_key_pool_ptr = 0;

/**
 *
 * @param key
 * @param packet
 */
static inline void
sample_extract_router_key(router_key_t* key,
                          packet_t* packet)
{
    assert(key != NULL);

    memset(key, 0, SAMPLE_ROUTER_KEY_SIZE);
    if (packet->ipv4_valid)
    {
        key->dst_addr = SWAP32(packet->ipv4.dst_ip);
    }
}

/**
 *
 * @param key
 * @param packet
 */
static inline void
sample_extract_tcp_fw_key(stateful_firewall_key_t* key,
                              packet_t* packet)
{
    assert (key != NULL);

    memset(key, 0, SAMPLE_TCP_FW_KEY_SIZE);

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
        key->tcp_ctrl = packet->tcp.ctrl;
    }
}

/**
 *
 * @param key
 * @param packet
 */
static inline void
sample_extract_nat_key(nat_key_t* key,
                           packet_t* packet)
{
    assert (key != NULL);

    memset(key, 0, SAMPLE_NAT_KEY_SIZE);

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

/**
 *
 * @param sample
 * @param key
 */
static void
sample_router_count(sample_t * sample, router_key_t* key)
{
    int idx = hash_crc32(key, SAMPLE_ROUTER_KEY_SIZE, CRC32)
              % SAMPLE_CONTAINER_SIZE;
    sample_router_key_container_t * kc = &sample->router_key_container[idx];
    while(kc->next != NULL)
    {
        kc = kc->next;
        if (key_compare(&kc->key, key, SAMPLE_ROUTER_KEY_SIZE) == 0)
        {
            kc->packet_count ++;
            if (sample->packet_count % sample->sample_period == 0)
            {
                if (kc->sampled == 0)
                {
                    sample->router_sample_count++;
                    kc->sampled = 1;
                }
            }
            return;
        }
    }

    if (kc->next == NULL)
    {
        kc->next = &sample_router_key_pool[sample_router_key_pool_ptr++];
        kc = kc->next;
        kc->key = *key;
        kc->packet_count = 1;
        kc->next = NULL;
        sample->router_behavior_count ++;
        if (sample->packet_count % sample->sample_period == 0)
        {
            sample->router_sample_count++;
            kc->sampled = 1;
        }
        else
        {
            kc->sampled = 0;
        }
    }
}

/**
 *
 * @param sample
 * @param key
 */
static void
sample_nat_count(sample_t * sample, nat_key_t* key)
{
    int idx = hash_crc32(key, SAMPLE_NAT_KEY_SIZE, CRC32)
              % SAMPLE_CONTAINER_SIZE;
    sample_nat_key_container_t * kc =
            &sample->nat_key_container[idx];
    while(kc->next != NULL) {
        kc = kc->next;
        if (key_compare(&kc->key, key, SAMPLE_NAT_KEY_SIZE) == 0)
        {
            kc->packet_count ++;
            if (sample->packet_count % sample->sample_period == 0)
            {
                if (kc->sampled == 0)
                {
                    sample->nat_sample_count++;
                    kc->sampled = 1;
                }
            }
            return;
        }
    }

    if (kc->next == NULL)
    {
        kc->next = &sample_nat_key_pool[sample_nat_key_pool_ptr++];
        kc = kc->next;
        kc->key = *key;
        kc->packet_count = 1;
        kc->next = NULL;
        sample->nat_behavior_count ++;
        if (sample->packet_count % sample->sample_period == 0)
        {
            sample->nat_sample_count++;
            kc->sampled = 1;
        }
        else
        {
            kc->sampled = 0;
        }
    }
}

/**
 *
 * @param sample
 * @param key
 */
static void
sample_tcp_fw_count(sample_t * sample,
                    stateful_firewall_key_t* key)
{
    int idx = hash_crc32(key, SAMPLE_TCP_FW_KEY_SIZE, CRC32)
              % SAMPLE_CONTAINER_SIZE;
    sample_tcp_fw_key_container_t * kc =
            &sample->tcp_fw_key_container[idx];
    while(kc->next != NULL) {
        kc = kc->next;
        if (key_compare(&kc->key, key, SAMPLE_TCP_FW_KEY_SIZE) == 0)
        {
            kc->packet_count ++;
            if (sample->packet_count % sample->sample_period == 0)
            {
                if (kc->sampled == 0)
                {
                    sample->tcp_fw_sample_count++;
                    kc->sampled = 1;
                }
            }
            return;
        }
    }

    if (kc->next == NULL)
    {
        kc->next = &sample_tcp_fw_key_pool[sample_tcp_fw_key_pool_ptr++];
        kc = kc->next;
        kc->key = *key;
        kc->packet_count = 1;
        kc->next = NULL;
        sample->tcp_fw_behavior_count ++;
        if (sample->packet_count % sample->sample_period == 0)
        {
            sample->tcp_fw_sample_count++;
            kc->sampled = 1;
        }
        else
        {
            kc->sampled = 0;
        }
    }
}

void
sample_count(sample_t * sample, packet_t* packet)
{

    router_key_t router_key;
    nat_key_t nat_key;
    stateful_firewall_key_t tcp_fw_key;

    sample->packet_count++;

    SAMPLE_EXTRACT(tcp_fw_key);
    SAMPLE_EXTRACT(router_key);
    SAMPLE_EXTRACT(nat_key);
    //if (sample->packet_count % sample->sample_period == 0) {
        sample_router_count(sample, &router_key);
        sample_nat_count(sample, &nat_key);
        sample_tcp_fw_count(sample, &tcp_fw_key);
    //}
}
