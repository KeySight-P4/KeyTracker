#include <assert.h>
#include <stddef.h>
#include "hash.h"



const uint8_t CRC8_POLY[CRC8_ALG_NUM] = {
    [CRC8] = 0x07,
    [CRC8_DARC] = 0x39,
    [CRC8_I_CODE] = 0x1D,
    [CRC8_ITU] = 0x07,
    [CRC8_MAXIM] = 0x31,
    [CRC8_ROHC] = 0x07,
    [CRC8_WCDMA] = 0x9B
};

const uint8_t CRC8_NOT_REV[CRC8_ALG_NUM] = {
        0,
        1,
        0,
        0,
        1,
        1,
        1
};

const uint8_t CRC8_INIT[CRC8_ALG_NUM] = {
    0x00,
    0x00,
    0xFD,
    0x55,
    0x00,
    0xFF,
    0x00
};

const uint8_t CRC8_XOUT[CRC8_ALG_NUM] = {
        0x00,
        0x00,
        0x00,
        0x55,
        0x00,
        0x00,
        0x00,
};


const uint16_t CRC16_POLY[CRC16_ALG_NUM] = {
        [CRC16] = 0x8005,
        [CRC16_BUYPASS] = 0x8005,
        [CRC16_DDS_110] = 0x8005,
        [CRC16_DECT] = 0x0589,
        [CRC16_DNP] = 0x3D65,
        [CRC16_EN_13757] = 0x3D65,
        [CRC16_GENIBUS] = 0x1021,
        [CRC16_MAXIM] = 0x8005,
        [CRC16_MCRF4XX] = 0x1021,
        [CRC16_RIELLO] = 0x1021,
        [CRC16_T10_DIF] = 0x8BB7,
        [CRC16_TELEDISK] = 0xA097,
        [CRC16_USB] = 0x8005,
        [X_25] = 0x1021,
        [XMODEM] = 0x1021,
        [MODBUS] = 0x8005,
        [KERMIT] = 0x1021,
        [CRC_CCITT] = 0x1021,
        [CRC_AUG_CCITT] = 0x1021
};

const uint16_t CRC16_NOT_REV[CRC16_ALG_NUM] = {
      1,
      0,
      0,
      0,
      1,
      0,
      0,
      1,
      1,
      1,
      0,
      0,
      1,
      1,
      0,
      1,
      1,
      0,
      0
};

const uint16_t CRC16_INIT[CRC16_ALG_NUM] = {
        0x0000,
        0x0000,
        0x800D,
        0x0001,
        0xFFFF,
        0xFFFF,
        0x0000,
        0xFFFF,
        0xFFFF,
        0x554D,
        0x0000,
        0x0000,
        0x0000,
        0x0000,
        0x0000,
        0xFFFF,
        0x0000,
        0xFFFF,
        0x1D0F
};

const uint16_t CRC16_XOUT[CRC16_ALG_NUM] = {
        0x0000,
        0x0000,
        0x0000,
        0x0001,
        0xFFFF,
        0xFFFF,
        0xFFFF,
        0xFFFF,
        0x0000,
        0x0000,
        0x0000,
        0x0000,
        0xFFFF,
        0xFFFF,
        0x0000,
        0x0000,
        0x0000,
        0x0000,
        0x0000
};

const uint32_t CRC32_POLY[CRC32_ALG_NUM] = {
    [CRC32] = 0x04C11DB7,
    [CRC32_BZIP2] = 0x04C11DB7,
    [CRC32C] = 0x1EDC6F41,
    [CRC32D] = 0xAB33982B,
    [CRC32_MPEG] = 0x04C11DB7,
    [POSIX] = 0x04C11DB7,
    [CRC32Q] = 0x814141AB,
    [JAMCRC] = 0x04C11DB7,
    [XFER] = 0x000000AB
};

const uint32_t CRC32_NOT_REV[CRC32_ALG_NUM] = {
    1,
    0,
    1,
    1,
    0,
    0,
    0,
    1,
    0
};

const uint32_t CRC32_INIT[CRC32_ALG_NUM] = {
        0x00000000,
        0x00000000,
        0x00000000,
        0x00000000,
        0xFFFFFFFF,
        0xFFFFFFFF,
        0x00000000,
        0xFFFFFFFF,
        0x00000000,
};

const uint32_t CRC32_XOUT[CRC32_ALG_NUM] = {
        0xFFFFFFFF,
        0xFFFFFFFF,
        0xFFFFFFFF,
        0xFFFFFFFF,
        0x00000000,
        0xFFFFFFFF,
        0x00000000,
        0x00000000,
        0x00000000
};

static uint8_t CRC8_TABLE[CRC8_ALG_NUM][256] = {0};
static uint16_t CRC16_TABLE[CRC16_ALG_NUM][256] = {0};
static uint32_t CRC32_TABLE[CRC32_ALG_NUM][256] = {0};
static uint32_t TABLE_INIT = 0;

static void
init_crc_tables()
{

    if (likely(TABLE_INIT))
    {
        return;
    }
    int t;
    // For CRC8
    for (t = 0; t < CRC8_ALG_NUM; t++)
    {
        uint16_t i,j;
        uint8_t  crc;
        if (CRC8_NOT_REV[t] == 1)
        {
            for (i = 0; i < 256; i++)
            {
                crc = (uint8_t) i;
                for (j = 0; j < 8; j++)
                {
                    if (crc & 0x80)
                        crc = (crc << 1) ^ CRC8_POLY[t];
                    else
                        crc = crc << 1;
                }
                CRC8_TABLE[t][i] = crc;
            }
        }
        else
        {
            for (i = 0; i < 256; i++)
            {
                crc = (uint8_t) i;
                for (j = 0; j < 8; j++)
                {
                    if (crc & 0x01)
                    {
                        crc = (crc >> 1) ^ CRC8_POLY[t];
                    }
                    else {

                        crc = crc >> 1;
                    }
                }
                CRC8_TABLE[t][i] = crc;
            }
        }
    }
    // For CRC16
    for (t = 0; t < CRC16_ALG_NUM; t++)
    {
        uint16_t i,j;
        uint16_t  crc, c;
        if(CRC16_NOT_REV[t] == 1)
        {
            for (i = 0; i < 256; i++)
            {
                crc =  0;
                c = i;
                for (j = 0; j < 8; j++)
                {
                    if ((crc ^ c) & 0x0001)
                    {
                        crc = (crc >> 1) ^ CRC16_POLY[t];
                    }
                    else
                    {
                        crc = crc >> 1;
                    }
                }
                CRC16_TABLE[t][i] = crc;
            }
        }
        else
        {
            for (i = 0; i < 256; i++)
            {
                crc =  0;
                c = i << 8;
                for (j = 0; j < 8; j++)
                {
                    if ((crc ^ c) & 0x8000)
                    {
                        crc = (crc << 1) ^ CRC16_POLY[t];
                    }
                    else
                    {
                        crc = crc << 1;
                    }
                }
                CRC16_TABLE[t][i] = crc;
            }
        }
    }
    // For CRC32
    for (t = 0; t < CRC32_ALG_NUM; t++)
    {
        uint32_t i,j;
        uint32_t  crc;
        if (CRC32_NOT_REV[t] == 1)
        {
            for (i = 0; i < 256; i++)
            {
                crc = i;
                for (j = 0; j < 8; j++)
                {
                    if (crc & 0x00000001L)
                    {
                        crc = (crc >> 1) ^ CRC32_POLY[t];
                    }
                    else
                    {
                        crc = crc >> 1;
                    }
                }
                CRC32_TABLE[t][i] = crc;
            }
        }
        else
        {
            for (i = 0; i < 256; i++) {
                crc = i << (24);
                for (j = 0; j < 8; j++)
                {
                    if (crc & 0x80000000L)
                    {
                        crc = (crc << 1) ^ CRC32_POLY[t];
                    }
                    else
                    {
                        crc = crc << 1;
                    }
                }
                CRC32_TABLE[t][i] = crc;
            }
        }
    }
    TABLE_INIT = 1;
}


uint32_t
hash_crc32(const void* data, int length, int alg)
{

    if(unlikely(!TABLE_INIT))
    {
        init_crc_tables();
    }

    assert(alg < CRC32_ALG_NUM && alg >= 0);
    assert(length > 0);
    assert(data != NULL);

    uint8_t* buf = (uint8_t *)data;
    
    int i;
    uint32_t crc = CRC32_INIT[alg];
    if (CRC32_NOT_REV[alg] == 1)
    {
        for (i = 0; i < length; i++)
        {
            uint8_t tmp = (uint8_t) (( crc ^ buf[i]) & 0xFF );
            crc = (crc >> 8) ^ CRC32_TABLE[alg][tmp];
        }
    }
    else
    {
        for (i = 0; i < length; i++)
        {
            uint8_t tmp = (uint8_t) ((crc >> 24) ^ buf[i] & 0xFF);
            crc = (crc << 8) ^ CRC32_TABLE[alg][tmp];
        }
    }

    crc ^= CRC32_XOUT[alg];

    return crc;
}

uint16_t
hash_crc16(const void* data, int length, int alg)
{
    if(!TABLE_INIT)
    {
        init_crc_tables();
    }

    assert(alg < CRC16_ALG_NUM && alg >= 0);
    assert(length > 0);
    assert(data != NULL);
    
    uint8_t* buf = (uint8_t *)data;

    int i;
    uint16_t crc = CRC16_INIT[alg];
    if (CRC32_NOT_REV[alg] == 1)
    {
        for (i = 0; i < length; i++)
        {
            uint8_t tmp = (uint8_t) ((crc ^ buf[i]) & 0xFF);
            crc = (crc >> 8) ^ CRC16_TABLE[alg][tmp];
        }
    }
    else
    {
        for (i = 0; i < length; i++)
        {
            uint8_t tmp = (uint8_t) (((crc >> 8) ^ buf[i]) & 0xFF);
            crc = (crc << 8) ^ CRC16_TABLE[alg][tmp];
        }
    }
    crc ^= CRC16_XOUT[alg];
    return crc;
}

uint8_t
hash_crc8(const void* data, int length, int alg)
{
    if(!TABLE_INIT)
    {
        init_crc_tables();
    }
    assert(alg < CRC8_ALG_NUM && alg >= 0);
    assert(length > 0);
    assert(data != NULL);
    uint8_t* buf = (uint8_t *)data;
    int i ;
    uint8_t  crc = CRC8_INIT[alg];
    for (i = 0; i < alg; i++)
    {
        crc = CRC8_TABLE[alg][alg ^ buf[i]];
    }
    crc ^= CRC8_XOUT[alg];
    return crc;
}
