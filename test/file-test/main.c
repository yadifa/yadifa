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
#include <dnscore/filesystem-file.h>
#include <dnscore/buffered-file.h>
#include <dnscore/mapped-file.h>
#include <dnscore/format.h>

#define SEED 0
#define SIZE 0x1000000

#define PAGES       16
#define LOG2_SIZE   12

static u8 *raw_data = NULL;
static u8 *tmp_data = NULL;
static ssize_t raw_size = 0;

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
    7841, 7853, 7867, 7873, 7877, 7879, 7883, 7901, 7907, 7919,
};

static int
memcmp_give_offset(const void *a_, const void *b_, size_t s)
{
    const u8 * a = (const u8 *)a_;
    const u8 * b = (const u8 *)b_;
    for(size_t i = 0 ; i < s; ++i)
    {
        if(a[i] != b[i])
        {
            formatln("memcmp: offset %llu: %02x <=> %02x", i, a[i], b[i]);
            return 1;
        }
    }
    
    return 0;
}

static int
test_linear(file_t f, const char *name)
{
    s64 ret;
    
    s64 test_start = timeus();
    
    memset(tmp_data, 0, raw_size);
    
    // fill the file linearly
    
    if((ret = file_write(f, raw_data, raw_size)) != raw_size)
    {
        formatln("test-linear: %s: could not write %llx bytes into file (returned %llx)", name, raw_size, ret);
        flushout(); return ERROR;
    }
    
    if((ret = file_seek(f, 0, SEEK_SET)) != 0)
    {
        formatln("test-linear: %s: could not seek position 0 of file (returned %llx)", name, ret);
        flushout(); return ERROR;
    }
    
    if((ret = file_seek(f, 0, SEEK_END)) != raw_size)
    {
        formatln("test-linear: %s: could not seek position %lli (the end) of file (returned %llx)", name, raw_size, ret);
        flushout(); return ERROR;
    }
    
    if((ret = file_seek(f, -raw_size, SEEK_CUR)) != 0)
    {
        formatln("test-linear: %s: could not seek relative position %lli ( => 0 the the beginning)) of file (returned %llx)", name, -raw_size, ret);
        flushout(); return ERROR;
    }
    
    if((ret = file_read(f, tmp_data, raw_size)) != raw_size)
    {
        formatln("test-linear: %s: could not read %llx bytes into file (returned %llx)", name, raw_size, ret);
        flushout(); return ERROR;
    }
    
    if(memcmp_give_offset(raw_data, tmp_data, raw_size) != 0)
    {
        formatln("test-linear: %s: read bytes do not match written bytes");
        flushout(); return ERROR;
    }
    
    if((ret = file_tell(f)) != raw_size)
    {
        formatln("test-linear: %s: expected tell to give position %lli (returned %llx)", name, raw_size, ret);
        flushout(); return ERROR;
    }
    
    if(FAIL(ret = file_close(f)))
    {
        formatln("test-linear: %s: close returned an error: %r", name, (int)ret);
        flushout(); return ERROR;
    }
    
    s64 test_end = timeus();
    double dt = (double)(test_end - test_start)/1000.0;
    
    formatln("test-linear: %s: passed (%6.3f ms)\n", name, dt);
        
    flushout(); return SUCCESS;
}

static int
test_linear_multipass(file_t f, const char *name)
{
    s64 ret;
    
    s64 test_start = timeus();
    
    memset(tmp_data, 0, raw_size);
    
    // fill the file linearly using multiple writes of various sizes
        
    s64 total = raw_size;
    
    for(int i = 0; total > 0; ++i)
    {
        int chunk = mostly_primes[i % MOSTLY_PRIMES_COUNT];
        
        s64 position = raw_size - total;
        s64 remain = raw_size - position;
        
        if(remain < chunk)
        {
            chunk = remain;
        }
        
        if((ret = file_tell(f)) != position)
        {
            formatln("test-linear-multipass: %s: expected tell to give position %lli (returned %llx) (pass %i, before write)", name, raw_size, ret, i);
            flushout(); return ERROR;
        }
        
        if((ret = file_write(f, &raw_data[position], chunk)) != chunk)
        {
            formatln("test-linear-multipass: %s: could not write %llx bytes into file (returned %llx) (pass %i, writing)", name, chunk, ret, i);
            flushout(); return ERROR;
        }
        
        position += ret;
        
        if((ret = file_tell(f)) != position)
        {
            formatln("test-linear-multipass: %s: expected tell to give position %lli (returned %llx) (pass %i, after write)", name, raw_size, ret, i);
            flushout(); return ERROR;
        }
        
        total -= chunk;
    }
    
    if((ret = file_seek(f, 0, SEEK_SET)) != 0)
    {
        formatln("test-linear-multipass: %s: could not seek position 0 of file (returned %llx)", name, ret);
        flushout(); return ERROR;
    }
    
    if((ret = file_seek(f, 0, SEEK_END)) != raw_size)
    {
        formatln("test-linear-multipass: %s: could not seek position %lli (the end) of file (returned %llx)", name, raw_size, ret);
        flushout(); return ERROR;
    }
    
    if((ret = file_seek(f, -raw_size, SEEK_CUR)) != 0)
    {
        formatln("test-linear-multipass: %s: could not seek relative position %lli ( => 0 the the beginning)) of file (returned %llx)", name, -raw_size, ret);
        flushout(); return ERROR;
    }
    
    total = raw_size;
    
    for(int i = 0; total > 0; ++i)
    {
        int chunk = mostly_primes[i % MOSTLY_PRIMES_COUNT];
        
        s64 position = raw_size - total;
        s64 remain = raw_size - position;
        
        if(remain < chunk)
        {
            chunk = remain;
        }
        
        if((ret = file_tell(f)) != position)
        {
            formatln("test-linear-multipass: %s: expected tell to give position %lli (returned %llx) (before read)", name, raw_size, ret);
            flushout(); return ERROR;
        }
        
        if((ret = file_read(f, &tmp_data[position], chunk)) != chunk)
        {
            formatln("test-linear-multipass: %s: could not read %llx bytes into file (returned %llx)", name, chunk, ret);
            flushout(); return ERROR;
        }
        
        position += ret;
        
        if((ret = file_tell(f)) != position)
        {
            formatln("test-linear-multipass: %s: expected tell to give position %lli (returned %llx) (after read)", name, raw_size, ret);
            flushout(); return ERROR;
        }
        
        total -= chunk;
    }
    
    if(memcmp_give_offset(raw_data, tmp_data, raw_size) != 0)
    {
        formatln("test-linear-multipass: %s: read bytes do not match written bytes");
        flushout(); return ERROR;
    }
    
    if((ret = file_tell(f)) != raw_size)
    {
        formatln("test-linear-multipass: %s: expected tell to give position %lli (returned %llx)", name, raw_size, ret);
        flushout(); return ERROR;
    }
    
    if(FAIL(ret = file_close(f)))
    {
        formatln("test-linear-multipass: %s: close returned an error: %r", name, (int)ret);
        flushout(); return ERROR;
    }
    
    s64 test_end = timeus();
    double dt = (double)(test_end - test_start)/1000.0;
    
    formatln("test-linear-multipass: %s: passed (%6.3f ms)\n", name, dt);
    
    flushout(); return SUCCESS;
}

static int
test_linear_multipass_readback(file_t f, const char *name)
{
    s64 ret;
    
    s64 test_start = timeus();
    
    memset(tmp_data, 0, raw_size);
    
    // fill the file linearly using multiple writes of various sizes
        
    s64 total = raw_size;
    s64 rb_position = 0;
    
    for(int i = 0; total > 0; ++i)
    {
        int chunk = mostly_primes[i % MOSTLY_PRIMES_COUNT];
        
        s64 position = raw_size - total;
        s64 remain = raw_size - position;
        
        if(remain < chunk)
        {
            chunk = remain;
        }
        
        if((ret = file_tell(f)) != position)
        {
            formatln("test-linear-multipass-readback: %s: expected tell to give position %lli (returned %llx) (pass %i, before write)", name, raw_size, ret, i);
            flushout(); return ERROR;
        }
        
        u32 r = GET_U32_AT(raw_data[i % (raw_size >> 1)]);
        
        if((i > 0) && ((r & 255) < 128))
        {
            s64 avail = position - rb_position;
            r %= avail;
            if(r > 0)
            {
                if((ret = file_seek(f, rb_position, SEEK_SET)) != rb_position)
                {
                    formatln("test-linear-multipass-readback: %s: could not seek position %lli of file (returned %llx) (pass %i)", name, rb_position, ret ,i);
                    flushout(); return ERROR;
                }

                if((ret = file_read(f, &tmp_data[rb_position], r)) != r)
                {
                    formatln("test-linear-multipass-readback: %s: could not read %i bytes (%i available) back from file (returned %llx) (pass %i)", name, r, avail, ret, i);
                    flushout(); return ERROR;
                }
                
                if(memcmp(&raw_data[rb_position], &tmp_data[rb_position], r) != 0)
                {
                    formatln("test-linear-multipass-readback: %s: intermediary read-back bytes do not match written bytes (pass %i)", name, i);
                    flushout(); return ERROR;
                }
                
                rb_position += r;
                
                if((file_seek(f, position, SEEK_SET)) != position)
                {
                    formatln("test-linear-multipass-readback: %s: could not seek position %lli of file (returned %llx) (pass %i)", name, position, ret, i);
                    flushout(); return ERROR;
                }
            }
        }
        
        if((ret = file_write(f, &raw_data[position], chunk)) != chunk)
        {
            formatln("test-linear-multipass-readback: %s: could not write %llx bytes into file (returned %llx) (pass %i, writing)", name, chunk, ret, i);
            flushout(); return ERROR;
        }
        
        position += ret;
        
        if((ret = file_tell(f)) != position)
        {
            formatln("test-linear-multipass-readback: %s: expected tell to give position %lli (returned %llx) (pass %i, after write)", name, raw_size, ret, i);
            flushout(); return ERROR;
        }
        
        total -= chunk;
    }
    
    {
        s64 avail = raw_size - rb_position;
        s64 r = avail;
        if(r > 0)
        {
            if((ret = file_seek(f, rb_position, SEEK_SET)) != rb_position)
            {
                formatln("test-linear-multipass-readback: %s: could not seek position %lli of file (returned %llx)", name, rb_position, ret);
                flushout(); return ERROR;
            }

            if((ret = file_read(f, &tmp_data[rb_position], r)) != r)
            {
                formatln("test-linear-multipass-readback: %s: could not read %i bytes (%i available) back from file (returned %llx)", name, r, avail, ret);
                flushout(); return ERROR;
            }

            if((file_seek(f, raw_size, SEEK_SET)) != raw_size)
            {
                formatln("test-linear-multipass-readback: %s: could not seek position %lli of file (returned %llx)", name, raw_size, ret);
                flushout(); return ERROR;
            }
        }
    }
    
    if(memcmp_give_offset(raw_data, tmp_data, raw_size) != 0)
    {
        formatln("test-linear-multipass-readback: %s: read-back bytes do not match written bytes");
        flushout(); return ERROR;
    }
    
    memset(tmp_data, 0, raw_size);
    
    if((ret = file_seek(f, 0, SEEK_SET)) != 0)
    {
        formatln("test-linear-multipass-readback: %s: could not seek position 0 of file (returned %llx)", name, ret);
        flushout(); return ERROR;
    }
    
    if((ret = file_seek(f, 0, SEEK_END)) != raw_size)
    {
        formatln("test-linear-multipass-readback: %s: could not seek position %lli (the end) of file (returned %llx)", name, raw_size, ret);
        flushout(); return ERROR;
    }
    
    if((ret = file_seek(f, -raw_size, SEEK_CUR)) != 0)
    {
        formatln("test-linear-multipass-readback: %s: could not seek relative position %lli ( => 0 the the beginning)) of file (returned %llx)", name, -raw_size, ret);
        flushout(); return ERROR;
    }
    
    total = raw_size;
    
    for(int i = 0; total > 0; ++i)
    {
        int chunk = mostly_primes[i % MOSTLY_PRIMES_COUNT];
        
        s64 position = raw_size - total;
        s64 remain = raw_size - position;
        
        if(remain < chunk)
        {
            chunk = remain;
        }
        
        if((ret = file_tell(f)) != position)
        {
            formatln("test-linear-multipass-readback: %s: expected tell to give position %lli (returned %llx) (before read)", name, raw_size, ret);
            flushout(); return ERROR;
        }
        
        if((ret = file_read(f, &tmp_data[position], chunk)) != chunk)
        {
            formatln("test-linear-multipass-readback: %s: could not read %llx bytes into file (returned %llx)", name, chunk, ret);
            flushout(); return ERROR;
        }
        
        position += ret;
        
        if((ret = file_tell(f)) != position)
        {
            formatln("test-linear-multipass-readback: %s: expected tell to give position %lli (returned %llx) (after read)", name, raw_size, ret);
            flushout(); return ERROR;
        }
        
        total -= chunk;
    }
    
    if(memcmp_give_offset(raw_data, tmp_data, raw_size) != 0)
    {
        formatln("test-linear-multipass-readback: %s: read bytes do not match written bytes");
        flushout(); return ERROR;
    }
    
    if((ret = file_tell(f)) != raw_size)
    {
        formatln("test-linear-multipass-readback: %s: expected tell to give position %lli (returned %llx)", name, raw_size, ret);
        flushout(); return ERROR;
    }
    
    if(FAIL(ret = file_close(f)))
    {
        formatln("test-linear-multipass-readback: %s: close returned an error: %r", name, (int)ret);
        flushout(); return ERROR;
    }

    s64 test_end = timeus();
    double dt = (double)(test_end - test_start)/1000.0;
    
    formatln("test-linear-multipass-readback: %s: passed (%6.3f ms)\n", name, dt);
    
    flushout(); return SUCCESS;
}

#define N 4

static int
test_linear_multipass_multi_readback(file_t f, const char *name)
{
    s64 ret;
    
    s64 test_start = timeus();
    
    memset(tmp_data, 0, raw_size);
    
    // fill the file linearly using multiple writes of various sizes
        
    s64 total = raw_size;
    s64 rb_position[N];
    for(int j = 0 ; j < N; ++j) rb_position[j] = 0;
    
    for(int i = 0; total > 0; ++i)
    {
        int chunk = mostly_primes[i % MOSTLY_PRIMES_COUNT];
        
        s64 position = raw_size - total;
        s64 remain = raw_size - position;
        
        if(remain < chunk)
        {
            chunk = remain;
        }
        
        if((ret = file_tell(f)) != position)
        {
            formatln("test-linear-multipass-multi-readback: %s: expected tell to give position %lli (returned %llx) (pass %i, before write)", name, raw_size, ret, i);
            flushout(); return ERROR;
        }
        
        u32 r = GET_U32_AT(raw_data[i % (raw_size >> 1)]);
        
        if((i > 0) && ((r & 255) < 128))
        {
            for(int j = 0 ; j < N; ++j)
            {
                s64 avail = position - rb_position[j];

                r %= avail;
                
                if(r > 0)
                {
                    if((ret = file_seek(f, rb_position[j], SEEK_SET)) != rb_position[j])
                    {
                        formatln("test-linear-multipass-multi-readback: %s: could not seek position %lli of file (returned %llx) (pass %i)", name, rb_position, ret ,i);
                        flushout(); return ERROR;
                    }

                    if((ret = file_read(f, &tmp_data[rb_position[j]], r)) != r)
                    {
                        formatln("test-linear-multipass-multi-readback: %s: could not read %i bytes (%i available) back from file (returned %llx) (pass %i)", name, r, avail, ret, i);
                        flushout(); return ERROR;
                    }

                    if(memcmp(&raw_data[rb_position[j]], &tmp_data[rb_position[j]], r) != 0)
                    {
                        formatln("test-linear-multipass-multi-readback: %s: intermediary read-back bytes do not match written bytes (pass %i)", name, i);
                        flushout(); return ERROR;
                    }

                    rb_position[j] += r;

                    if((file_seek(f, position, SEEK_SET)) != position)
                    {
                        formatln("test-linear-multipass-multi-readback: %s: could not seek position %lli of file (returned %llx) (pass %i)", name, position, ret, i);
                        flushout(); return ERROR;
                    }
                }
            }
        }
        
        if((ret = file_write(f, &raw_data[position], chunk)) != chunk)
        {
            formatln("test-linear-multipass-multi-readback: %s: could not write %llx bytes into file (returned %llx) (pass %i, writing)", name, chunk, ret, i);
            flushout(); return ERROR;
        }
        
        position += ret;
        
        if((ret = file_tell(f)) != position)
        {
            formatln("test-linear-multipass-multi-readback: %s: expected tell to give position %lli (returned %llx) (pass %i, after write)", name, raw_size, ret, i);
            flushout(); return ERROR;
        }
        
        total -= chunk;
    }
    
    for(int j = 0; j < N; ++j)
    {
        s64 avail = raw_size - rb_position[j];
        s64 r = avail;
        if(r > 0)
        {
            if((ret = file_seek(f, rb_position[j], SEEK_SET)) != rb_position[j])
            {
                formatln("test-linear-multipass-multi-readback: %s: could not seek position %lli of file (returned %llx)", name, rb_position[j], ret);
                flushout(); return ERROR;
            }

            if((ret = file_read(f, &tmp_data[rb_position[j]], r)) != r)
            {
                formatln("test-linear-multipass-multi-readback: %s: could not read %i bytes (%i available) back from file (returned %llx)", name, r, avail, ret);
                flushout(); return ERROR;
            }

            if((file_seek(f, raw_size, SEEK_SET)) != raw_size)
            {
                formatln("test-linear-multipass-multi-readback: %s: could not seek position %lli of file (returned %llx)", name, raw_size, ret);
                flushout(); return ERROR;
            }
        }
    }
    
    if(memcmp_give_offset(raw_data, tmp_data, raw_size) != 0)
    {
        formatln("test-linear-multipass-multi-readback: %s: read-back bytes do not match written bytes");
        flushout(); return ERROR;
    }
    
    memset(tmp_data, 0, raw_size);
    
    if((ret = file_seek(f, 0, SEEK_SET)) != 0)
    {
        formatln("test-linear-multipass-multi-readback: %s: could not seek position 0 of file (returned %llx)", name, ret);
        flushout(); return ERROR;
    }
    
    if((ret = file_seek(f, 0, SEEK_END)) != raw_size)
    {
        formatln("test-linear-multipass-multi-readback: %s: could not seek position %lli (the end) of file (returned %llx)", name, raw_size, ret);
        flushout(); return ERROR;
    }
    
    if((ret = file_seek(f, -raw_size, SEEK_CUR)) != 0)
    {
        formatln("test-linear-multipass-multi-readback: %s: could not seek relative position %lli ( => 0 the the beginning)) of file (returned %llx)", name, -raw_size, ret);
        flushout(); return ERROR;
    }
    
    total = raw_size;
    
    for(int i = 0; total > 0; ++i)
    {
        int chunk = mostly_primes[i % MOSTLY_PRIMES_COUNT];
        
        s64 position = raw_size - total;
        s64 remain = raw_size - position;
        
        if(remain < chunk)
        {
            chunk = remain;
        }
        
        if((ret = file_tell(f)) != position)
        {
            formatln("test-linear-multipass-multi-readback: %s: expected tell to give position %lli (returned %llx) (before read)", name, raw_size, ret);
            flushout(); return ERROR;
        }
        
        if((ret = file_read(f, &tmp_data[position], chunk)) != chunk)
        {
            formatln("test-linear-multipass-multi-readback: %s: could not read %llx bytes into file (returned %llx)", name, chunk, ret);
            flushout(); return ERROR;
        }
        
        position += ret;
        
        if((ret = file_tell(f)) != position)
        {
            formatln("test-linear-multipass-multi-readback: %s: expected tell to give position %lli (returned %llx) (after read)", name, raw_size, ret);
            flushout(); return ERROR;
        }
        
        total -= chunk;
    }
    
    if(memcmp_give_offset(raw_data, tmp_data, raw_size) != 0)
    {
        formatln("test-linear-multipass-multi-readback: %s: read bytes do not match written bytes");
        flushout(); return ERROR;
    }
    
    if((ret = file_tell(f)) != raw_size)
    {
        formatln("test-linear-multipass-multi-readback: %s: expected tell to give position %lli (returned %llx)", name, raw_size, ret);
        flushout(); return ERROR;
    }
    
    if(FAIL(ret = file_close(f)))
    {
        formatln("test-linear-multipass-multi-readback: %s: close returned an error: %r", name, (int)ret);
        flushout(); return ERROR;
    }

    s64 test_end = timeus();
    double dt = (double)(test_end - test_start)/1000.0;
    
    formatln("test-linear-multipass-multi-readback: %s: passed (%6.3f ms)\n", name, dt);
    
    flushout(); return SUCCESS;
}


static int
test_filesystem_file()
{
    ya_result ret;
    file_t f;
    const char * filename_0 = "/tmp/file-test-0.bin";
    const char * filename_1 = "/tmp/file-test-1.bin";
    const char * filename_2 = "/tmp/file-test-2.bin";
    const char * filename_3 = "/tmp/file-test-3.bin";
    
    if(FAIL(ret = filesystem_file_create_ex(&f, filename_0, O_RDWR|O_CREAT|O_TRUNC, 0640)))
    {
        goto test_filesystem_file_exit;
    }
    
    if(FAIL(ret = test_linear(f, filename_0)))
    {
        goto test_filesystem_file_exit;
    }
    
    if(FAIL(ret = filesystem_file_create_ex(&f, filename_1, O_RDWR|O_CREAT|O_TRUNC, 0640)))
    {
        goto test_filesystem_file_exit;
    }
    
    if(FAIL(ret = test_linear_multipass(f, filename_1)))
    {
        goto test_filesystem_file_exit;
    }
    
    if(FAIL(ret = filesystem_file_create_ex(&f, filename_2, O_RDWR|O_CREAT|O_TRUNC, 0640)))
    {
        goto test_filesystem_file_exit;
    }
    
    if(FAIL(ret = test_linear_multipass_readback(f, filename_2)))
    {
        goto test_filesystem_file_exit;
    }
    
    if(FAIL(ret = filesystem_file_create_ex(&f, filename_3, O_RDWR|O_CREAT|O_TRUNC, 0640)))
    {
        goto test_filesystem_file_exit;
    }
    
    if(FAIL(ret = test_linear_multipass_multi_readback(f, filename_3)))
    {
        goto test_filesystem_file_exit;
    }
    
    println("test_filesystem_file: passed\n\n");
    
test_filesystem_file_exit:
    
    unlink(filename_0);
    unlink(filename_1);
    unlink(filename_2);
    unlink(filename_3);
    
    return SUCCESS;
}

static int
test_mapped_file()
{
    ya_result ret;
    file_t f;
    const char * filename_0 = "/tmp/file-test-0.bin";
    const char * filename_1 = "/tmp/file-test-1.bin";
    const char * filename_2 = "/tmp/file-test-2.bin";
    const char * filename_3 = "/tmp/file-test-3.bin";
    
    if(FAIL(ret = mapped_file_create_ex(&f, filename_0, O_RDWR|O_CREAT|O_TRUNC, 0640)))
    {
        goto test_mapped_file_exit;
    }
    
    if(FAIL(ret = test_linear(f, filename_0)))
    {
        goto test_mapped_file_exit;
    }
    
    if(FAIL(ret = mapped_file_create_ex(&f, filename_1, O_RDWR|O_CREAT|O_TRUNC, 0640)))
    {
        goto test_mapped_file_exit;
    }
    
    if(FAIL(ret = test_linear_multipass(f, filename_1)))
    {
        goto test_mapped_file_exit;
    }
    
    if(FAIL(ret = mapped_file_create_ex(&f, filename_2, O_RDWR|O_CREAT|O_TRUNC, 0640)))
    {
        goto test_mapped_file_exit;
    }
    
    if(FAIL(ret = test_linear_multipass_readback(f, filename_2)))
    {
        goto test_mapped_file_exit;
    }
    
    if(FAIL(ret = mapped_file_create_ex(&f, filename_3, O_RDWR|O_CREAT|O_TRUNC, 0640)))
    {
        goto test_mapped_file_exit;
    }
    
    if(FAIL(ret = test_linear_multipass_multi_readback(f, filename_3)))
    {
        goto test_mapped_file_exit;
    }
    
    println("test_mapped_file: passed\n\n");
    
test_mapped_file_exit:
    
    unlink(filename_0);
    unlink(filename_1);
    unlink(filename_2);
    unlink(filename_3);
    
    return SUCCESS;
}

static int
test_mapped_volatile_file()
{
    ya_result ret;
    size_t base_size = SIZE;
    file_t f;
    const char * filename_0 = "/tmp/file-test-0.bin";
    const char * filename_1 = "/tmp/file-test-1.bin";
    const char * filename_2 = "/tmp/file-test-2.bin";
    const char * filename_3 = "/tmp/file-test-3.bin";

    if(FAIL(ret = mapped_file_create_volatile(&f, filename_0, base_size)))
    {
        goto test_mapped_file_exit;
    }
    
    if(FAIL(ret = test_linear(f, filename_0)))
    {
        goto test_mapped_file_exit;
    }
    
    if(FAIL(ret = mapped_file_create_volatile(&f, filename_1, base_size)))
    {
        goto test_mapped_file_exit;
    }
    
    if(FAIL(ret = test_linear_multipass(f, filename_1)))
    {
        goto test_mapped_file_exit;
    }
    
    if(FAIL(ret = mapped_file_create_volatile(&f, filename_2, base_size)))
    {
        goto test_mapped_file_exit;
    }
    
    if(FAIL(ret = test_linear_multipass_readback(f, filename_2)))
    {
        goto test_mapped_file_exit;
    }
    
    if(FAIL(ret = mapped_file_create_volatile(&f, filename_3, base_size)))
    {
        goto test_mapped_file_exit;
    }
    
    if(FAIL(ret = test_linear_multipass_multi_readback(f, filename_3)))
    {
        goto test_mapped_file_exit;
    }
    
    println("test_mapped_file (ram): passed\n\n");
    
test_mapped_file_exit:
    
    return SUCCESS;
}

static int
test_buffered_file_ex(u32 pages, u8 log2_size)
{
    ya_result ret;
    file_t f;
    file_t bf;
    const char * filename_0 = "/tmp/file-test-0.bin";
    const char * filename_1 = "/tmp/file-test-1.bin";
    const char * filename_2 = "/tmp/file-test-2.bin";
    const char * filename_3 = "/tmp/file-test-3.bin";
    
    buffered_file_cache_t cache = buffered_file_cache_new_instance("cache", pages, log2_size, FALSE);
    
    if(cache == NULL)
    {
        return ERROR;
    }
    
    if(FAIL(ret = filesystem_file_create_ex(&f, filename_0, O_RDWR|O_CREAT|O_TRUNC, 0640)))
    {
        buffered_file_cache_delete(cache);
        goto test_buffered_file_ex_exit;
    }
    
    if(FAIL(ret = buffered_file_init(&bf, f, cache)))
    {
        buffered_file_cache_delete(cache);
        goto test_buffered_file_ex_exit;
    }
    
    if(FAIL(ret = test_linear(bf, filename_0)))
    {
        buffered_file_cache_delete(cache);
        goto test_buffered_file_ex_exit;
    }
    
    if(FAIL(ret = filesystem_file_create_ex(&f, filename_1, O_RDWR|O_CREAT|O_TRUNC, 0640)))
    {
        buffered_file_cache_delete(cache);
        goto test_buffered_file_ex_exit;
    }
    
    if(FAIL(ret = buffered_file_init(&bf, f, cache)))
    {
        buffered_file_cache_delete(cache);
        goto test_buffered_file_ex_exit;
    }
    
    if(FAIL(ret = test_linear_multipass(bf, filename_1)))
    {
        buffered_file_cache_delete(cache);
        goto test_buffered_file_ex_exit;
    }
    
    if(FAIL(ret = filesystem_file_create_ex(&f, filename_2, O_RDWR|O_CREAT|O_TRUNC, 0640)))
    {
        buffered_file_cache_delete(cache);
        goto test_buffered_file_ex_exit;
    }
    
    if(FAIL(ret = buffered_file_init(&bf, f, cache)))
    {
        buffered_file_cache_delete(cache);
        goto test_buffered_file_ex_exit;
    }
    
    if(FAIL(ret = test_linear_multipass_readback(bf, filename_2)))
    {
        buffered_file_cache_delete(cache);
        goto test_buffered_file_ex_exit;
    }
    
    if(FAIL(ret = filesystem_file_create_ex(&f, filename_3, O_RDWR|O_CREAT|O_TRUNC, 0640)))
    {
        buffered_file_cache_delete(cache);
        goto test_buffered_file_ex_exit;
    }
    
    if(FAIL(ret = buffered_file_init(&bf, f, cache)))
    {
        buffered_file_cache_delete(cache);
        goto test_buffered_file_ex_exit;
    }
    
    if(FAIL(ret = test_linear_multipass_readback(bf, filename_3)))
    {
        buffered_file_cache_delete(cache);
        goto test_buffered_file_ex_exit;
    }
    
    formatln("test_buffered_file (%llu bytes in %u pages of %u bytes): passed\n\n", pages * (1 << log2_size), pages, (1 << log2_size));
    
test_buffered_file_ex_exit:
    
    buffered_file_cache_delete(cache);
    
    unlink(filename_0);
    unlink(filename_1);
    unlink(filename_2);
    unlink(filename_3);
    
    return ret;
}

static int
test_buffered_file_1_10()
{
    ya_result ret = test_buffered_file_ex(1, 10);
    return ret;
}

static int
test_buffered_file_1_12()
{
    ya_result ret = test_buffered_file_ex(1, 12);
    return ret;
}

static int
test_buffered_file_16_12()
{
    ya_result ret = test_buffered_file_ex(16, 12);
    return ret;
}

static int
test_buffered_file_256_12()
{
    ya_result ret = test_buffered_file_ex(256, 12);
    return ret;
}

static int
test_buffered_file_16_16()
{
    ya_result ret = test_buffered_file_ex(16, 16);
    return ret;
}

static int
test_buffered_file_1_20()
{
    ya_result ret = test_buffered_file_ex(1, 20);
    return ret;
}

typedef int (*test_function)();

#define TEST_COUNT 9

static test_function test_list[TEST_COUNT] =
{
    test_filesystem_file,
    test_mapped_file,
    test_mapped_volatile_file,
    test_buffered_file_1_10,
    test_buffered_file_1_12,
    test_buffered_file_16_12,
    test_buffered_file_256_12,
    test_buffered_file_16_16,
    test_buffered_file_1_20
};

int
main(int argc, char *argv[])
{
    /* initializes the core library */
    dnscore_init();
    
    size_t size = SIZE;

    if(argc > 1 )
    {
        size = atol(argv[1]);
        if((size < 16) || (size > 0x40000000))
        {
            size = SIZE;
        }
    }
    
    raw_data = (u8*)malloc(size * 2);
    
    if(raw_data == NULL)
    {    
        exit(EXIT_FAILURE);
    }
    
    tmp_data = &raw_data[size];
    
    random_ctx rnd = random_init(SEED);
    for(size_t i = 0; i < size; ++i)
    {
        raw_data[i] = random_next(rnd);
    }
    random_finalize(rnd);
    raw_size = size;
    
    if(argc > 2)
    {
        for(int i = 2; i < argc; ++i)
        {
            int index = atoi(argv[i]);
            if((index >= 0) && (index < TEST_COUNT))
            {
                test_list[index]();
            }
            else
            {
                formatln("Invalid parameter %i: expects value in [ 0; %i [", TEST_COUNT);
            }
        }
    }
    else
    {
        for(int index = 0; index < TEST_COUNT; ++index)
        {
            test_list[index]();
        }
    }
    
    free(raw_data);

    flushout();
    flusherr();
    fflush(NULL);

    dnscore_finalize();

    return EXIT_SUCCESS;
}
