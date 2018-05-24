#include <stddef.h>
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <keytracker.h>

#include "everflow.h"
#include "hash.h"

everflow_flow_container_t flow_pool[FLOW_POOL_SIZE];
int flow_pool_ptr = 0;

static inline
int dice()
{
    int x = rand();
    if ((x % 1000) > 900)
    {
        return 0;
    }
    return  1;
}

static inline void
everflow_extract_key(packet_t * packet,
                     bf_key_t * bf_key) {
    KEYSIGHT_KEY_EXTRACTOR(packet, &bf_key->key);
}


void
everflow_count(everflow_t* ef, packet_t* packet) {
    ef->packet_count++;
    // flow_key_t key = {0};
    bf_key_t key = {0};
    everflow_extract_key(packet, &key);

    int idx = hash_crc32( &key, BF_KEY_SIZE, CRC32)
              % FLOW_CONTAINER_SIZE;
    everflow_flow_container_t* kc
            = &ef->flow_container[idx];
    while(kc->next != NULL)
    {
        kc = kc->next;
        if (key_compare(&kc->key, &key, FLOW_KEY_SIZE) == 0)
        {
            kc->packet_count ++;

            if (kc->count_enable)
            {
                ef->everflow_90_count ++;
                if (kc->packet_count - kc->p4db_packet_stamp >= 10)
                {
                    ef->p4db_90_count ++;
                    kc->p4db_packet_stamp = kc->packet_count;
                }
            }

            return;
        }
    }

    if (kc->next == NULL)
    {
        kc->next = &flow_pool[flow_pool_ptr++];
        kc = kc->next;
        kc->key = key;
        kc->count_enable = dice();
        kc->p4db_packet_stamp = 1;
        kc->packet_count = 1;
        kc->next = NULL;
        ef->distinct_flow_count ++;

        if (kc->count_enable) {
            ef->everflow_90_count ++;
            ef->count_behavior ++;
            ef->p4db_90_count ++;
        }

    }
}

void
everflow_print(everflow_t * ef) {
    printf("%u\t%u\t%u\t%u\t%u\n", ef->everflow_90_count, ef->p4db_90_count, ef->distinct_flow_count, ef->count_behavior, ef->packet_count);
}
