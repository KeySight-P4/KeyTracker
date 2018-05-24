#include <stdio.h>
#include <stdlib.h>
#include <pcap/pcap.h>
#include <getopt.h>
#include <string.h>
#include "keytracker.h"
#include "netsight.h"
#include "everflow.h"
#include "motivation.h"
#include "hash.h"
#include "sample.h"


#define DEFAULT_MAX_PACKETS 100000000000
#define MAX_SLAVE_HANDLES 1024


struct global_config_t {
    int verbose;
    int report_period;
    uint64_t max_packets;
    char  file[256];
};

struct global_config_t global_config = {
        .verbose = 0,
        .report_period = 0,
        .max_packets = DEFAULT_MAX_PACKETS,
        .file = "list.txt",
};

/**
 *
 * @param file_name
 * @return
 */
static pcap_t *
open_pcap(const char* file_name)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap =  pcap_open_offline(file_name, errbuf);
    if (pcap == NULL)
    {
        printf("Cannot find the pcap file: %s\n", file_name);
        exit(1);
    }
    return pcap;
}

/**
 *
 * @param ts1
 * @param ts2
 * @return
 */
static inline int
compare_ts(struct timeval* ts1, struct timeval* ts2) {
    if (ts1->tv_sec > ts2->tv_sec)
    {
        return 1;
    }
    else if (ts1->tv_sec < ts2->tv_sec)
    {
        return -1;
    }
    else
    {
        return ts1->tv_usec - ts2->tv_usec;
    }
}

struct slave_t {
    int handle_num;
    pcap_t * pcap_handles[MAX_SLAVE_HANDLES];
} pcap_container;

static int
init(void)
{
    FILE* flist;
    flist = fopen(global_config.file, "r");
    char file_name[512];
    if(flist == NULL)
    {
        printf("Cannot find the list.txt\n");
        return -1;
    }
    while(fscanf(flist, "%s", file_name) != EOF)
    {
        pcap_container.pcap_handles[pcap_container.handle_num++] = open_pcap(file_name);
    }
    fclose(flist);
}


keysight_t ks = {
        .enable = 0,
        .bf_alg = BSBF,
        .bf_num = MAX_BF_NUM,
        .bf_size = MAX_BF_SIZE,
        .bucket_num = DEFAULT_BUCKET_NUM,
        .window_num = DEFAULT_WINDOW_NUM,
        .bf_max = DEFAULT_BF_MAX,
        .packet_per_window = DEFAULT_PACKET_PER_WINDOW,
};
netsight_t ns = {
        .enable = 0,
};
everflow_t ef = {
        .enable = 0,
};
motivation_t motivation = {
        .enable = 0,
};

sample_t sample = {
        .enable = 0,
        .sample_period =DEFAULT_SAMPLE_PERIOD,
};

static void
print_with_formart()
{
    if (ks.enable) {
        printf("%d\t%d\t%d\t%d\t%d\t%d\t%d\t",
               ks.postcard_count,
               ks.packet_count,
               ks.distinct_behavior_count,
               ks.distinct_behavior_count - ks.false_positive,
               ks.false_negative,
               ks.false_positive,
               ks.packet_count - ks.distinct_behavior_count - ks.false_positive);

        printf("%lf\t%lf\t",
               ks.false_negative*1.0/(ks.packet_count - ks.distinct_behavior_count ), // FNR
               ks.false_positive*1.0/ks.distinct_behavior_count);  // FPR
        
        printf("%lf\t%lf\t",
               ks.postcard_count*1.0/ks.packet_count,
               (ks.distinct_behavior_count - ks.false_positive)*1.0/ks.distinct_behavior_count);  // FPR
        
        printf("%lf\t%lf\n",
               ks.recent_false_negative*1.0/(ks.packet_count - ks.distinct_behavior_count ), // Recent-FNR
               ks.recent_false_positive*1.0/ks.distinct_behavior_count);  // Recent-FPR

    }
    if (ef.enable)
    {
        everflow_print(&ef);
    }
    if (motivation.enable)
    {
        printf("%u\t", motivation.packet_count);
        printf("%d\t", motivation.switch_behavior_count);
        printf("%d\t", motivation.router_behavior_count);
        printf("%d\t", motivation.nat_behavior_count);
        printf("%d\n", motivation.tcp_fw_behavior_count);
    }
}

/**
 * print basic information whn -v is set
 */
static void
print() {
    if (ns.enable)
    {
        printf("NetSight: %d\n \tTCP: %d\n \tUDP: %d\n", ns.postcard_count, ns.tcp_packet_count, ns.udp_packet_count);
    }
    if (ks.enable)
    {
        printf("\nKeySight: %d\n", ks.postcard_count);
        //printf("False Positives: %d\n", ks.false_positive);
        //printf("False Negatives: %d\n", ks.false_negative);
        //printf("Distinct Behaviors: %d\n", ks.distinct_behavior_count);
        printf("Distinct: %d\n", ks.distinct_behavior_count);
        printf("True Negative: %d\n", ks.distinct_behavior_count - ks.false_positive);
        printf("False Negative: %d\n", ks.false_negative);
        printf("False Positive: %d\n", ks.false_positive);
        printf("True Positive: %d\n", ks.packet_count - ks.distinct_behavior_count - ks.false_positive);
    }
    if (motivation.enable)
    {
        printf("Switch distinct behaviors: %d\n", motivation.switch_behavior_count);
        printf("Router distinct behaviors: %d\n", motivation.router_behavior_count);
        printf("NAT distinct behaviors: %d\n", motivation.nat_behavior_count);
        printf("TCP FW distinct behaviors: %d\n", motivation.tcp_fw_behavior_count);
    }
}

/**
 *
 * @param slave
 * @return
 */
static int
read_worker(struct slave_t * slave)
{
    int handle_num = slave->handle_num;
    struct pcap_pkthdr pkthdrs[MAX_SLAVE_HANDLES];
    const unsigned char * pcap_buf[MAX_SLAVE_HANDLES] = {NULL};
    int curr = 0;
    packet_t packet;
    uint64_t packet_count = 0;
    for(;packet_count< global_config.max_packets;)
    {
        int i;
        for (i = 0; i < handle_num; i++)
        {
            if (pcap_buf[i] == NULL)
            {
                pcap_buf[i] = pcap_next(slave->pcap_handles[i], &pkthdrs[i]);
            }
        }

        /*
        for (i = 0; i < handle_num; i++)
        {
            if (pcap_buf[i] != NULL) {
                if (curr == -1)
                {
                    curr = i;
                }
                else if (compare_ts(&pkthdrs[curr].ts, &pkthdrs[i].ts) > 0)
                {
                    curr = i;
                }
            }
        }
         */

        if (pcap_buf[curr] == NULL)
        {
            curr ++;
        }

        if (curr == -1 || curr >= handle_num)
        {
            break;
        }

        extract_packet(&packet, pcap_buf[curr], pkthdrs[curr].len);

        if (packet.udp_valid == 1|| packet.tcp_valid == 1)
        {
            packet_count ++;
            if (ks.enable) {
                keysight_count(&ks, &packet);
            }
            if (ef.enable)
                everflow_count(&ef, &packet);
            if (motivation.enable)
                motivation_count(&motivation, &packet);
            if (ns.enable)
                netsight_count(&ns, &packet);
            if (sample.enable)
                sample_count(&sample, &packet);
            if (global_config.verbose)
            {
                if (packet_count % 5000000 == 0)
                {
                    print();
                }
            } 
            else if (global_config.report_period > 0)
            {
                if ((packet_count + 1) % global_config.report_period == 0) 
                {
                    print_with_formart();
                }

            }

        }
        pcap_buf[curr] = NULL;
        // curr = -1;
    }
}

void
parse_option(int argc, char **argv) {
    while (1) {
        int option_index = 0;
        struct option long_options[] = {
                        {"netsight"    , 0, 0, 'n'},
                        {"everflow"    , 0, 0, 'e'},
                        {"motivation"  , 0, 0, 'm'},
                        {"keysight"    , 0, 0, 'k'},
                        {"sample"    , 0, 0, 's'},
                        {"bf_size"     , 1, 0, 'M'},
                        {"bf_alg"      , 1, 0, 'a'},
                        {"bf_num"      , 1, 0, 'K'},
                        {"bf_window"   , 1, 0, 'S'},
                        {"bf_bucket"   , 1, 0, 'B'},
                        {"bf_max"      , 1, 0, 'x'},
                        {"packet_per_window", 1, 0, 'N'},
                        {"report_period", 1, 0, 'R'},
                        {"verbose"     , 0, 0, 'v'},
                        {"list_file"   , 1, 0, 'f'},
                        {"help"        , 0, 0, 'h'}
                };
        int c;
        c = getopt_long(argc, argv, "nemkx:sM:a:S:B:f:R:hN:v", long_options, &option_index);
        if (c == -1)
            break;

        switch (c)
        {
            case 'n':
                ns.enable = 1;
                break;

            case 'e':
                ef.enable = 1;
                break;

            case 'm':
                motivation.enable = 1;
                break;

            case 'k':
                ks.enable = 1;
                break;

            case 'M':
                ks.bf_size = (uint32_t) strtol(optarg, NULL, 10);
                break;

            case 'N':
                ks.packet_per_window = (uint32_t) strtol(optarg, NULL, 10);
                break;

            case 'a':
                ks.bf_alg = (uint32_t) strtol(optarg, NULL, 10);
                break;
            case 's':
                sample.enable = 1;
                break;

            case 'S':
                ks.window_num = (uint32_t) strtol(optarg, NULL, 10);
                break;

            case 'B':
                ks.bucket_num = (uint32_t) strtol(optarg, NULL, 10);
                break;

            case 'R':
                global_config.report_period = (uint32_t) strtol(optarg, NULL, 10);
                break;

            case 'K':
                ks.bf_num = (uint32_t) strtol(optarg, NULL, 10);
                break;

            case 'x':
                ks.bf_max = (uint32_t) strtol(optarg, NULL, 10);
                break;

            case 'v':
                global_config.verbose = 1;
                break;

            case 'f':
                strcpy(global_config.file, optarg);
                break;

            case 'h':
                printf("\n-------Options of KeySight Simulation-------\n");
                printf("\t -n or --netsight \t Enable NetSight. \n");
                printf("\t -e or --everflow \t Enable EverFlow. \n");
                printf("\t -k or --keysight \t Enable KeySight. \n");
                printf("\t -m or --motivation \t Enable KeySight. \n");
                printf("\t -M or --bf_size [BF_SIZE] \t Set the array size of BF. \n");
                printf("\t -S or --window_num [WINDOW_NUM] \t Set the window number of BF. \n");
                printf("\t -B or --bucket_num [BUCKET_NUM] \t Set the bucket number of BF. \n");
                printf("\t -x or --bf_max [MAX of BF Cell] \t Set the max cell size of BF. \n\n");
                printf("\t -N or --packet_per_window [Packet number] \t Set the number of packets per window. \n");
                printf("\t -R or --report_period [Period] \t Set the reprt period. \n\n");
                printf("\t -a or --bf_alg [BF_ALG] \t Set the algorithm of BF. \n");
                int i;
                for (i = 0; i < UPDATE_ALG_NUM; i++) {
                    if (BF_ALG_NAMES[i] != NULL) {
                        printf("\t\t %s : %d \n", BF_ALG_NAMES[i], i);
                    }
                }
                exit(1);
            default:
                printf("Un-known option: %c!\n", c);
                break;
        }
    }
    if (global_config.verbose) {
        // TODO
    }
}


int
main(int argc, char **argv)
{
    parse_option(argc, argv);
    init();
    read_worker(&pcap_container);

#if MOTIVATION_FLOW_PRINT
    if (motivation.enable)
        motivation_flow_print(&motivation);
#endif
    if (global_config.verbose)
    {
        print();
    }
    else
    {
        print_with_formart();
    }
    // Delete PCAP handles
    int j;
    for(j = 0; j < pcap_container.handle_num; j++)
    {
        pcap_close(pcap_container.pcap_handles[j]);
    }
    return 0;
}
