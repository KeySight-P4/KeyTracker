#ifndef DPDK_PCAP_HASH_H
#define DPDK_PCAP_HASH_H

#include <stdint.h>
#include <assert.h>

#define  likely(x)        __builtin_expect(!!(x), 1)
#define  unlikely(x)      __builtin_expect(!!(x), 0)


//#define  likely(x)        (x)
//#define  unlikely(x)     (x)

enum CRC8_ALG {
    CRC8 = 0,
    CRC8_DARC,
    CRC8_I_CODE,
    CRC8_ITU,
    CRC8_MAXIM,
    CRC8_ROHC,
    CRC8_WCDMA,
    CRC8_ALG_NUM
};

enum CRC16_ALG {
    CRC16 = 0,
    CRC16_BUYPASS,
    CRC16_DDS_110,
    CRC16_DECT,
    CRC16_DNP,
    CRC16_EN_13757,
    CRC16_GENIBUS,
    CRC16_MAXIM,
    CRC16_MCRF4XX,
    CRC16_RIELLO,
    CRC16_T10_DIF,
    CRC16_TELEDISK,
    CRC16_USB,
    X_25,
    XMODEM,
    MODBUS,
    KERMIT,
    CRC_CCITT,
    CRC_AUG_CCITT,
    CRC16_ALG_NUM
};

enum CRC32_ALG {
    CRC32 = 0,
    CRC32_BZIP2,
    CRC32C,
    CRC32D,
    CRC32_MPEG,
    POSIX,
    CRC32Q,
    JAMCRC,
    XFER,
    CRC32_ALG_NUM
};

/**
 * compare the value of key1 and key2
 * @param key1
 * @param key2
 * @param length
 * @return
 */
static inline int
key_compare(const void * key1, const void * key2, int length) {
    assert(key1 != NULL);
    assert(key2 != NULL);
    if (length == 0)
    {
        return 0;
    }
    int i, count = 0;
    int tmp = length / 8;
    for(i = 0; i < tmp; i ++) // As 64 bits
    {
        if (((const uint64_t* )key1)[i] != ((const uint64_t* )key2)[i])
        {
            return 1;
        }
        count += 8;
    }
    tmp = length / 4;
    for (i = count / 4; i < tmp; i++) // As 32 bits
    {
        if (((const uint32_t* )key1)[i] != ((const uint32_t* )key2)[i])
        {
            return 1;
        }
        count += 4;
    }
    for (i = count; i < length; i++) // As 8 bits
    {
        if (((const uint8_t* )key1)[count + i] != ((const uint8_t* )key2)[count + i])
        {
            return 1;
        }
    }
    return 0;
}

/**
 *
 * @param buf
 * @param length
 * @param alg
 * @return
 */
uint32_t hash_crc32(const void* buf, int length, int alg);

/**
 *
 * @param buf
 * @param length
 * @param alg
 * @return
 */
uint16_t hash_crc16(const void* buf, int length, int alg);

/**
 *
 * @param buf
 * @param length
 * @param alg
 * @return
 */
uint8_t hash_crc8(const void* buf, int length, int alg);

#endif
