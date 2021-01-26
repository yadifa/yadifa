/*------------------------------------------------------------------------------
 *
 * Copyright (c) 2011-2021, EURid vzw. All rights reserved.
 * The YADIFA TM software product is provided under the BSD 3-clause license:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *        * Redistributions of source code must retain the above copyright
 *          notice, this list of conditions and the following disclaimer.
 *        * Redistributions in binary form must reproduce the above copyright
 *          notice, this list of conditions and the following disclaimer in the
 *          documentation and/or other materials provided with the distribution.
 *        * Neither the name of EURid nor the names of its contributors may be
 *          used to endorse or promote products derived from this software
 *          without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 *------------------------------------------------------------------------------
 *
 */

/** @defgroup test
 *  @ingroup test
 *  @brief skeleton file
 * 
 * skeleton test program, will not be installed with a "make install"
 * 
 * To create a new test based on the skeleton:
 * 
 * _ copy the folder
 * _ replace "skeleton" by the name of the test
 * _ add the test to the top level Makefile.am and configure.ac
 *
 */

#include <dnscore/dnscore.h>
#include <dnscore/random.h>
#include <dnscore/digest.h>
#include <dnscore/zalloc.h>
#include <dnscore/format.h>

#include <dnscore/bytearray_input_stream.h>
#include <dnscore/buffer_input_stream.h>

#include <dnscore/bytearray_output_stream.h>
#include <dnscore/buffer_output_stream.h>

// read by various amounts of length
// read fully by various amounts of length

static random_ctx rndctx;

static u8 *file_data;
static u8 *file_tmp;
static size_t file_size;
static u8 file_digest[20];

#define MOSTLY_PRIMES_COUNT 1008

static int mostly_primes[MOSTLY_PRIMES_COUNT] =
{
    4096, 4096, 4095, 1 ,4095, 4097, 4097, 4095,
    
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29,
    31, 37, 41, 43, 47, 53, 59, 61, 67, 71,
    73, 79, 83, 89, 97, 101, 103, 107, 109, 113,
    127, 131, 137, 139, 149, 151, 157, 163, 167, 173,
    179, 181, 191, 193, 197, 199, 211, 223, 227, 229,
    233, 239, 241, 251, 257, 263, 269, 271, 277, 281,
    283, 293, 307, 311, 313, 317, 331, 337, 347, 349,
    353, 359, 367, 373, 379, 383, 389, 397, 401, 409,
    419, 421, 431, 433, 439, 443, 449, 457, 461, 463,
    467, 479, 487, 491, 499, 503, 509, 521, 523, 541,
    547, 557, 563, 569, 571, 577, 587, 593, 599, 601,
    607, 613, 617, 619, 631, 641, 643, 647, 653, 659,
    661, 673, 677, 683, 691, 701, 709, 719, 727, 733,
    739, 743, 751, 757, 761, 769, 773, 787, 797, 809,
    811, 821, 823, 827, 829, 839, 853, 857, 859, 863,
    877, 881, 883, 887, 907, 911, 919, 929, 937, 941,
    947, 953, 967, 971, 977, 983, 991, 997, 1009, 1013,
    1019, 1021, 1031, 1033, 1039, 1049, 1051, 1061, 1063, 1069,
    1087, 1091, 1093, 1097, 1103, 1109, 1117, 1123, 1129, 1151,
    1153, 1163, 1171, 1181, 1187, 1193, 1201, 1213, 1217, 1223,
    1229, 1231, 1237, 1249, 1259, 1277, 1279, 1283, 1289, 1291,
    1297, 1301, 1303, 1307, 1319, 1321, 1327, 1361, 1367, 1373,
    1381, 1399, 1409, 1423, 1427, 1429, 1433, 1439, 1447, 1451,
    1453, 1459, 1471, 1481, 1483, 1487, 1489, 1493, 1499, 1511,
    1523, 1531, 1543, 1549, 1553, 1559, 1567, 1571, 1579, 1583,
    1597, 1601, 1607, 1609, 1613, 1619, 1621, 1627, 1637, 1657,
    1663, 1667, 1669, 1693, 1697, 1699, 1709, 1721, 1723, 1733,
    1741, 1747, 1753, 1759, 1777, 1783, 1787, 1789, 1801, 1811,
    1823, 1831, 1847, 1861, 1867, 1871, 1873, 1877, 1879, 1889,
    1901, 1907, 1913, 1931, 1933, 1949, 1951, 1973, 1979, 1987,
    1993, 1997, 1999, 2003, 2011, 2017, 2027, 2029, 2039, 2053,
    2063, 2069, 2081, 2083, 2087, 2089, 2099, 2111, 2113, 2129,
    2131, 2137, 2141, 2143, 2153, 2161, 2179, 2203, 2207, 2213,
    2221, 2237, 2239, 2243, 2251, 2267, 2269, 2273, 2281, 2287,
    2293, 2297, 2309, 2311, 2333, 2339, 2341, 2347, 2351, 2357,
    2371, 2377, 2381, 2383, 2389, 2393, 2399, 2411, 2417, 2423,
    2437, 2441, 2447, 2459, 2467, 2473, 2477, 2503, 2521, 2531,
    2539, 2543, 2549, 2551, 2557, 2579, 2591, 2593, 2609, 2617,
    2621, 2633, 2647, 2657, 2659, 2663, 2671, 2677, 2683, 2687,
    2689, 2693, 2699, 2707, 2711, 2713, 2719, 2729, 2731, 2741,
    2749, 2753, 2767, 2777, 2789, 2791, 2797, 2801, 2803, 2819,
    2833, 2837, 2843, 2851, 2857, 2861, 2879, 2887, 2897, 2903,
    2909, 2917, 2927, 2939, 2953, 2957, 2963, 2969, 2971, 2999,
    3001, 3011, 3019, 3023, 3037, 3041, 3049, 3061, 3067, 3079,
    3083, 3089, 3109, 3119, 3121, 3137, 3163, 3167, 3169, 3181,
    3187, 3191, 3203, 3209, 3217, 3221, 3229, 3251, 3253, 3257,
    3259, 3271, 3299, 3301, 3307, 3313, 3319, 3323, 3329, 3331,
    3343, 3347, 3359, 3361, 3371, 3373, 3389, 3391, 3407, 3413,
    3433, 3449, 3457, 3461, 3463, 3467, 3469, 3491, 3499, 3511,
    3517, 3527, 3529, 3533, 3539, 3541, 3547, 3557, 3559, 3571,
    3581, 3583, 3593, 3607, 3613, 3617, 3623, 3631, 3637, 3643,
    3659, 3671, 3673, 3677, 3691, 3697, 3701, 3709, 3719, 3727,
    3733, 3739, 3761, 3767, 3769, 3779, 3793, 3797, 3803, 3821,
    3823, 3833, 3847, 3851, 3853, 3863, 3877, 3881, 3889, 3907,
    3911, 3917, 3919, 3923, 3929, 3931, 3943, 3947, 3967, 3989,
    4001, 4003, 4007, 4013, 4019, 4021, 4027, 4049, 4051, 4057,
    4073, 4079, 4091, 4093, 4099, 4111, 4127, 4129, 4133, 4139,
    4153, 4157, 4159, 4177, 4201, 4211, 4217, 4219, 4229, 4231,
    4241, 4243, 4253, 4259, 4261, 4271, 4273, 4283, 4289, 4297,
    4327, 4337, 4339, 4349, 4357, 4363, 4373, 4391, 4397, 4409,
    4421, 4423, 4441, 4447, 4451, 4457, 4463, 4481, 4483, 4493,
    4507, 4513, 4517, 4519, 4523, 4547, 4549, 4561, 4567, 4583,
    4591, 4597, 4603, 4621, 4637, 4639, 4643, 4649, 4651, 4657,
    4663, 4673, 4679, 4691, 4703, 4721, 4723, 4729, 4733, 4751,
    4759, 4783, 4787, 4789, 4793, 4799, 4801, 4813, 4817, 4831,
    4861, 4871, 4877, 4889, 4903, 4909, 4919, 4931, 4933, 4937,
    4943, 4951, 4957, 4967, 4969, 4973, 4987, 4993, 4999, 5003,
    5009, 5011, 5021, 5023, 5039, 5051, 5059, 5077, 5081, 5087,
    5099, 5101, 5107, 5113, 5119, 5147, 5153, 5167, 5171, 5179,
    5189, 5197, 5209, 5227, 5231, 5233, 5237, 5261, 5273, 5279,
    5281, 5297, 5303, 5309, 5323, 5333, 5347, 5351, 5381, 5387,
    5393, 5399, 5407, 5413, 5417, 5419, 5431, 5437, 5441, 5443,
    5449, 5471, 5477, 5479, 5483, 5501, 5503, 5507, 5519, 5521,
    5527, 5531, 5557, 5563, 5569, 5573, 5581, 5591, 5623, 5639,
    5641, 5647, 5651, 5653, 5657, 5659, 5669, 5683, 5689, 5693,
    5701, 5711, 5717, 5737, 5741, 5743, 5749, 5779, 5783, 5791,
    5801, 5807, 5813, 5821, 5827, 5839, 5843, 5849, 5851, 5857,
    5861, 5867, 5869, 5879, 5881, 5897, 5903, 5923, 5927, 5939,
    5953, 5981, 5987, 6007, 6011, 6029, 6037, 6043, 6047, 6053,
    6067, 6073, 6079, 6089, 6091, 6101, 6113, 6121, 6131, 6133,
    6143, 6151, 6163, 6173, 6197, 6199, 6203, 6211, 6217, 6221,
    6229, 6247, 6257, 6263, 6269, 6271, 6277, 6287, 6299, 6301,
    6311, 6317, 6323, 6329, 6337, 6343, 6353, 6359, 6361, 6367,
    6373, 6379, 6389, 6397, 6421, 6427, 6449, 6451, 6469, 6473,
    6481, 6491, 6521, 6529, 6547, 6551, 6553, 6563, 6569, 6571,
    6577, 6581, 6599, 6607, 6619, 6637, 6653, 6659, 6661, 6673,
    6679, 6689, 6691, 6701, 6703, 6709, 6719, 6733, 6737, 6761,
    6763, 6779, 6781, 6791, 6793, 6803, 6823, 6827, 6829, 6833,
    6841, 6857, 6863, 6869, 6871, 6883, 6899, 6907, 6911, 6917,
    6947, 6949, 6959, 6961, 6967, 6971, 6977, 6983, 6991, 6997,
    7001, 7013, 7019, 7027, 7039, 7043, 7057, 7069, 7079, 7103,
    7109, 7121, 7127, 7129, 7151, 7159, 7177, 7187, 7193, 7207,
    7211, 7213, 7219, 7229, 7237, 7243, 7247, 7253, 7283, 7297,
    7307, 7309, 7321, 7331, 7333, 7349, 7351, 7369, 7393, 7411,
    7417, 7433, 7451, 7457, 7459, 7477, 7481, 7487, 7489, 7499,
    7507, 7517, 7523, 7529, 7537, 7541, 7547, 7549, 7559, 7561,
    7573, 7577, 7583, 7589, 7591, 7603, 7607, 7621, 7639, 7643,
    7649, 7669, 7673, 7681, 7687, 7691, 7699, 7703, 7717, 7723,
    7727, 7741, 7753, 7757, 7759, 7789, 7793, 7817, 7823, 7829,
    7841, 7853, 7867, 7873, 7877, 7879, 7883, 7901, 7907, 7919
};

static void sha1(const void* buffer, size_t size, void* digest, size_t digest_size)
{
    digest_s ctx;
    digest_sha1_init(&ctx);
    digest_update(&ctx, buffer, size);
    digest_final_copy_bytes(&ctx, digest, digest_size);
}

static ya_result sha1_match(const void* buffer, size_t size)
{
    u8 digest[20];
    
    sha1(buffer, size, digest, sizeof(digest));
    
    if(memcmp(digest, file_digest, sizeof(file_digest)) == 0)
    {
        return SUCCESS;
    }
    else
    {
        const u8* bytes = (const u8*)buffer;
        for(size_t i = 0; i < file_size; ++i)
        {
            if(file_data[i] != bytes[i])
            {
                formatln("sha1_match: error at position %i/%i (%02x != %02x)", i, file_size, file_data[i], bytes[i]);
                
                size_t from = (i >= 32)?i - 32:0;
                size_t to = MIN(i + 32, file_size);
                
                formatln("sha1_match: expected:");
                osprint_dump(termout, &file_data[from], to - from, 32, OSPRINT_DUMP_ALL);
                formatln("\nsha1_match: got:");
                osprint_dump(termout, &bytes[from], to - from, 32, OSPRINT_DUMP_ALL);
                println("");
                
                break;
            }
        }
        return ERROR;
    }
}

struct broken_input_stream_data
{
    input_stream filtered;
    size_t offset;
};

typedef struct broken_input_stream_data broken_input_stream_data;

static ya_result
broken_input_stream_read(input_stream* is, void *buffer_, u32 len)
{
    broken_input_stream_data* data = (broken_input_stream_data*)is->data;
    u8 *buffer = (u8*)buffer_;
    ya_result ret;
    
    if((data->offset & 1) != 0)
    {
        u32 low_len = data->offset % len;
        if(low_len == 0)
        {
            low_len = 1;
        }
        
        len = low_len;
    }

    ret = input_stream_read(&data->filtered, buffer, len);

    if(ISOK(ret))
    {
        data->offset += ret;
    }

    return ret;
}

static ya_result
broken_input_stream_skip(input_stream* is, u32 len)
{
    broken_input_stream_data* data = (broken_input_stream_data*)is->data;
    ya_result ret;
    
    if((data->offset & 1) == 0)
    {
        ret = input_stream_skip(&data->filtered, len);
        
        if(ISOK(ret))
        {
            data->offset += ret;
        }
        
        return ret;
    }
    else
    {
        return -1;
    }
}

static void
broken_input_stream_close(input_stream* is)
{
    broken_input_stream_data* data = (broken_input_stream_data*)is->data;
    input_stream_close(&data->filtered);
    ZFREE_OBJECT(data);
    is->data = NULL;
    is->vtbl = NULL;
}

static const input_stream_vtbl broken_input_stream_vtbl = {
    broken_input_stream_read,
    broken_input_stream_skip,
    broken_input_stream_close,
    "broken_input_stream",
};

void
broken_input_stream_init(input_stream* is, input_stream* filtered)
{
    broken_input_stream_data* data;
    ZALLOC_OBJECT_OR_DIE(data, broken_input_stream_data, GENERIC_TAG);
    data->filtered = *filtered;
    data->offset = 0;
    is->data = data;
    is->vtbl = &broken_input_stream_vtbl;
}

struct broken_output_stream_data
{
    output_stream filtered;
    size_t offset;
};

typedef struct broken_output_stream_data broken_output_stream_data;

static ya_result
broken_output_stream_write(output_stream* os, const u8* buffer, u32 len)
{
    broken_output_stream_data* data = (broken_output_stream_data*)os->data;

    ya_result ret;
    
    if((data->offset & 1) != 0)
    {
        u32 low_len = data->offset % len;
        if(low_len == 0)
        {
            low_len = 1;
        }
        
        len = low_len;
    }

    ret = output_stream_write(&data->filtered, buffer, len);

    if(ISOK(ret))
    {
        data->offset += ret;
    }
    
    return len;
}

static ya_result
broken_output_stream_flush(output_stream* os)
{
    broken_output_stream_data* data = (broken_output_stream_data*)os->data;
    
    output_stream_flush(&data->filtered);
    return SUCCESS;
}

static void
broken_output_stream_close(output_stream* os)
{
    broken_output_stream_data* data = (broken_output_stream_data*)os->data;
    
    output_stream_close(&data->filtered);
    ZFREE_OBJECT(data);
    os->data = NULL;
    os->vtbl = NULL;
}

static const output_stream_vtbl broken_output_stream_vtbl =
{
    broken_output_stream_write,
    broken_output_stream_flush,
    broken_output_stream_close,
    "broken_output_stream",
};

void
broken_output_stream_init(output_stream* os, output_stream* filtered)
{
    broken_output_stream_data* data;
    ZALLOC_OBJECT_OR_DIE(data, broken_output_stream_data, GENERIC_TAG);
    data->filtered = *filtered;
    data->offset = 0;
    os->data = data;
    os->vtbl = &broken_output_stream_vtbl;
}

static ya_result
test_input_read(input_stream* is, const char* prefix)
{
    ya_result ret = input_stream_read(is, file_tmp, file_size);
    
    if(FAIL(ret))
    {
        formatln("%s: test_input_read: failure: %r", prefix, ret);
        return ret;
    }
    
    if((size_t)ret != file_size)
    {
        formatln("%s: test_input_read: short read: %i instead of %i", prefix, ret, file_size);
        return ERROR;
    }
    
    input_stream_close(is);
    
    if(ISOK(ret = sha1_match(file_tmp, ret)))
    {
        formatln("%s: test_input_read: digest SUCCESS", prefix);
    }
    else
    {
        formatln("%s: test_input_read: digest FAILURE", prefix);
    }
    
    return ret;
}

static ya_result
test_input_readfully(input_stream* is, const char* prefix)
{
    ya_result ret = input_stream_read_fully(is, file_tmp, file_size);
    
    if(FAIL(ret))
    {
        formatln("%s: test_input_readfully: failure: %r", prefix, ret);
        return ret;
    }
    
    if((size_t)ret != file_size)
    {
        formatln("%s: test_input_readfully: short readfully: %i instead of %i", prefix, ret, file_size);
        return ERROR;
    }
    
    input_stream_close(is);
    
    if(ISOK(ret = sha1_match(file_tmp, ret)))
    {
        formatln("%s: test_input_readfully: digest SUCCESS", prefix);
    }
    else
    {
        formatln("%s: test_input_readfully: digest FAILURE", prefix);
    }
    
    return ret;
}

static ya_result
test_input_readfully_by_bits(input_stream* is, const char* prefix)
{
    ya_result ret = SUCCESS;
    s32 remaining = file_size;
    size_t offset = 0;
    int index = 0;
    
    while(remaining > 0)
    {
        s32 chunk = mostly_primes[index++ % MOSTLY_PRIMES_COUNT];
        if(chunk > remaining)
        {
            chunk = remaining;
        }
        
        remaining -= chunk;

        ret = input_stream_read_fully(is, &file_tmp[offset], chunk);
        
        if(FAIL(ret))
        {
            formatln("%s: test_input_readfully_by_bits: failure trying to read %i bytes (position %i): %r", prefix, chunk, offset, ret);
            return ret;
        }

        if(ret != chunk)
        {
            formatln("%s: test_input_readfully_by_bits: short read: %i instead of %i", prefix, ret, chunk);
            ret = ERROR;
            return ret;
        }
        
        offset += chunk;
    }
    
    input_stream_close(is);
    
    if(ISOK(ret = sha1_match(file_tmp, file_size)))
    {
        formatln("%s: test_input_readfully_by_bits: digest SUCCESS", prefix);
    }
    else
    {
        formatln("%s: test_input_readfully_by_bits: digest FAILURE", prefix);
        ret = ERROR;
    }
    
    return ret;
}

struct is_constructor
{
    ya_result (*init)(input_stream *is);
    const char* name;
};

static ya_result init_bytearray_input_stream_init_const(input_stream* is)
{
    bytearray_input_stream_init_const(is, file_data, file_size);
    return SUCCESS;
}

static ya_result init_bytearray_input_stream_init_notowned(input_stream* is)
{
    bytearray_input_stream_init(is, file_data, file_size, FALSE);
    return SUCCESS;
}

static ya_result init_buffer_input_stream_4k_init(input_stream* is)
{
    bytearray_input_stream_init_const(is, file_data, file_size);
    buffer_input_stream_init(is, is, 4096);
    return SUCCESS;
}

static ya_result init_buffer_input_stream_1b_init(input_stream* is)
{
    bytearray_input_stream_init_const(is, file_data, file_size);
    buffer_input_stream_init(is, is, 1);
    return SUCCESS;
}

static ya_result init_buffer_input_stream_4k_broken_init(input_stream* is)
{
    bytearray_input_stream_init_const(is, file_data, file_size);
    broken_input_stream_init(is, is);
    buffer_input_stream_init(is, is, 4096);
    return SUCCESS;
}

static ya_result init_buffer_input_stream_1b_broken_init(input_stream* is)
{
    bytearray_input_stream_init_const(is, file_data, file_size);
    broken_input_stream_init(is, is);
    buffer_input_stream_init(is, is, 1);
    return SUCCESS;
}

struct is_constructor is_constructors[] =
{
    {init_bytearray_input_stream_init_const, "bytearray_input_stream_init_const" },
    {init_bytearray_input_stream_init_notowned, "bytearray_input_stream_init(notowned)" },
    {init_buffer_input_stream_4k_init, "buffer_input_stream_4k_init"},
    {init_buffer_input_stream_1b_init, "buffer_input_stream_1b_init"},
    {init_buffer_input_stream_4k_broken_init, "buffer_input_stream_4k_broken_init"},
    {init_buffer_input_stream_1b_broken_init, "buffer_input_stream_1b_broken_init"},
    {NULL, NULL}
};

struct os_constructor
{
    ya_result (*init)(output_stream *is);
    const char* name;
};

static ya_result init_bytearray_output_stream_init_const(output_stream* os)
{
    bytearray_output_stream_init(os, file_tmp, file_size);
    return SUCCESS;
}

static ya_result init_bytearray_output_stream_init_notowned(output_stream* os)
{
    bytearray_output_stream_init(os, file_tmp, file_size);
    return SUCCESS;
}

static ya_result init_buffer_output_stream_4k_init(output_stream* os)
{
    bytearray_output_stream_init(os, file_tmp, file_size);
    buffer_output_stream_init(os, os, 4096);
    return SUCCESS;
}

static ya_result init_buffer_output_stream_1b_init(output_stream* os)
{
    bytearray_output_stream_init(os, file_tmp, file_size);
    buffer_output_stream_init(os, os, 1);
    return SUCCESS;
}

static ya_result init_buffer_output_stream_4k_broken_init(output_stream* os)
{
    bytearray_output_stream_init(os, file_tmp, file_size);
    broken_output_stream_init(os, os);
    buffer_output_stream_init(os, os, 4096);
    return SUCCESS;
}

static ya_result init_buffer_output_stream_1b_broken_init(output_stream* os)
{
    bytearray_output_stream_init(os, file_tmp, file_size);
    broken_output_stream_init(os, os);
    buffer_output_stream_init(os, os, 1);
    return SUCCESS;
}

struct os_constructor os_constructors[] =
{
    {init_bytearray_output_stream_init_const, "bytearray_output_stream_init_const" },
    {init_bytearray_output_stream_init_notowned, "bytearray_output_stream_init(notowned)" },
    {init_buffer_output_stream_4k_init, "buffer_output_stream_4k_init"},
    {init_buffer_output_stream_1b_init, "buffer_output_stream_1b_init"},
    {init_buffer_output_stream_4k_broken_init, "buffer_output_stream_4k_broken_init"},
    {init_buffer_output_stream_1b_broken_init, "buffer_output_stream_1b_broken_init"},
    {NULL, NULL}
};

static ya_result
test_output_write(output_stream* os, const char* prefix)
{
    ya_result ret = output_stream_write(os, file_data, file_size);
    
    if(FAIL(ret))
    {
        formatln("%s: test_output_write: failure: %r", prefix, ret);
        return ret;
    }
    
    if((size_t)ret != file_size)
    {
        formatln("%s: test_output_write: short write: %i instead of %i", prefix, ret, file_size);
        return ERROR;
    }
    
    output_stream_close(os);
    
    if(ISOK(ret = sha1_match(file_tmp, file_size)))
    {
        formatln("%s: test_output_write: digest SUCCESS", prefix);
    }
    else
    {
        formatln("%s: test_output_write: digest FAILURE", prefix);
    }
    
    return ret;
}

static ya_result
test_output_writefully(output_stream* os, const char* prefix)
{
    ya_result ret = output_stream_write_fully(os, file_data, file_size);
    
    if(FAIL(ret))
    {
        formatln("%s: test_output_writefully: failure: %r", prefix, ret);
        return ret;
    }
    
    if((size_t)ret != file_size)
    {
        formatln("%s: test_output_writefully: short writefully: %i instead of %i", prefix, ret, file_size);
        return ERROR;
    }
    
    output_stream_close(os);
    
    if(ISOK(ret = sha1_match(file_tmp, file_size)))
    {
        formatln("%s: test_output_writefully: digest SUCCESS", prefix);
    }
    else
    {
        formatln("%s: test_output_writefully: digest FAILURE", prefix);
    }
    
    return ret;
}

static ya_result
test_output_writefully_by_bits(output_stream* os, const char* prefix)
{
    ya_result ret = SUCCESS;
    s32 remaining = file_size;
    size_t offset = 0;
    int index = 0;
    
    while(remaining > 0)
    {
        s32 chunk = mostly_primes[index++ % MOSTLY_PRIMES_COUNT];
        if(chunk > remaining)
        {
            chunk = remaining;
        }
        
        remaining -= chunk;

        ret = output_stream_write_fully(os, &file_data[offset], chunk);
        
        if(FAIL(ret))
        {
            formatln("%s: test_output_writefully_by_bits: failure trying to write %i bytes (position %i): %r", prefix, chunk, offset, ret);
            return ret;
        }

        if(ret != chunk)
        {
            formatln("%s: test_output_writefully_by_bits: short write: %i instead of %i", prefix, ret, chunk);
            ret = ERROR;
            return ret;
        }
        
        offset += chunk;
    }
    
    output_stream_close(os);
    
    if(ISOK(ret = sha1_match(file_tmp, file_size)))
    {
        formatln("%s: test_output_writefully_by_bits: digest SUCCESS", prefix);
    }
    else
    {
        formatln("%s: test_output_writefully_by_bits: digest FAILURE", prefix);
        ret = ERROR;
    }
    
    return ret;
}

static void
clear_tmp()
{
    memset(file_tmp, 0xde, file_size);
}

static ya_result
test_is()
{
    input_stream is;
    ya_result ret;
    
    for(int i = 0; is_constructors[i].name != NULL; ++i)
    {
        is_constructors[i].init(&is);
        ret = test_input_read(&is, is_constructors[i].name);
        clear_tmp();
        if(FAIL(ret))
        {
            return ret;
        }

        is_constructors[i].init(&is);
        ret = test_input_readfully(&is, is_constructors[i].name);
        clear_tmp();
        if(FAIL(ret))
        {
            return ret;
        }

        is_constructors[i].init(&is);
        ret = test_input_readfully_by_bits(&is, is_constructors[i].name);
        clear_tmp();
        if(FAIL(ret))
        {
            return ret;
        }
        
        formatln("%s: PASSED", is_constructors[i].name);
        flushout();
    }
    
    return SUCCESS;
}
static ya_result
test_os()
{
    output_stream os;
    ya_result ret;
    
    for(int i = 0; os_constructors[i].name != NULL; ++i)
    {
        os_constructors[i].init(&os);
        ret = test_output_write(&os, os_constructors[i].name);
        clear_tmp();
        if(FAIL(ret))
        {
            return ret;
        }

        os_constructors[i].init(&os);
        ret = test_output_writefully(&os, os_constructors[i].name);
        clear_tmp();
        if(FAIL(ret))
        {
            return ret;
        }

        os_constructors[i].init(&os);
        ret = test_output_writefully_by_bits(&os, os_constructors[i].name);
        clear_tmp();
        if(FAIL(ret))
        {
            return ret;
        }
        
        formatln("%s: PASSED", os_constructors[i].name);
        flushout();
    }
    
    return SUCCESS;
}

int
main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;
    
    /* initializes the core library */
    dnscore_init();
    
    // prepare some input data
    
    rndctx = random_init(0); // constant seed
    
    file_size = 0x8000000; // 128 MB
    file_data = malloc(file_size * 2);
    if(file_data == NULL)
    {
        return EXIT_FAILURE;
    }
    file_tmp = &file_data[file_size];
    
    for(size_t i = 0; i < file_size; i += 4)
    {
        SET_U32_AT(file_data[i], random_next(rndctx));
    }
    
    sha1(file_data, file_size, file_digest, sizeof(file_digest));
    

    // the input data is ready
    
    ya_result ret;
    
    ret = test_is();
    
    if(ISOK(ret))
    {
        ret = test_os();
    }

    flushout();
    flusherr();
    fflush(NULL);

    dnscore_finalize();

    return ISOK(ret)?EXIT_SUCCESS:EXIT_FAILURE;
}
