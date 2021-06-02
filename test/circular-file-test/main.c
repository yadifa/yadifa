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
 *  @brief circular_file_test file
 *
 * circular_file_test test program, will not be installed with a "make install"
 *
 * To create a new test based on the circular_file_test:
 *
 * _ copy the folder
 * _ replace "circular_file_test" by the name of the test
 * _ add the test to the top level Makefile.am and configure.ac
 *
 */

#include <dnscore/dnscore.h>
#include <dnscore/circular-file.h>
#include <dnscore/format.h>
#include <dnscore/file_output_stream.h>
#include <dnscore/file_input_stream.h>
#include <dnscore/buffer_output_stream.h>
#include <dnscore/buffer_input_stream.h>
#include <dnscore/random.h>

#define JOURNAL_SIZE 16384
#define MOSTLY_PRIMES_COUNT (1008 + 8)
#define PAGE_MAGIC MAGIC4('P','A','G','E')
#define PAGE_COUNT (MOSTLY_PRIMES_COUNT * 100)

static int g_page_count = PAGE_COUNT;


struct reserved_header_s
{
    u32 from;
    u32 to;
    u32 last_soa_record;
    u32 flags;
};

struct page_header_s
{
    u32 magic;
    u32 from;
    u32 to;
    u32 size;
};

#define PAGE_SIZE_MAX (16384 - 32 - sizeof(struct page_header_s) - sizeof(struct reserved_header_s))

struct page_s
{
    struct page_header_s hdr;
    u8 data[PAGE_SIZE_MAX];
};

static int mostly_primes[MOSTLY_PRIMES_COUNT] =
{
    PAGE_SIZE_MAX,
    PAGE_SIZE_MAX,
    PAGE_SIZE_MAX - 1,
    PAGE_SIZE_MAX,
    PAGE_SIZE_MAX - 2,
    PAGE_SIZE_MAX,
    PAGE_SIZE_MAX - 3,
    PAGE_SIZE_MAX,

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

static u32 page_build(struct page_s *page, int i, random_ctx rnd)
{
    u32 data_size = mostly_primes[i % MOSTLY_PRIMES_COUNT];

    page->hdr.magic = PAGE_MAGIC;
    page->hdr.from = i;
    page->hdr.to = i + 1;
    page->hdr.size = data_size;
    for(u32 j = 0; j < data_size; ++j)
    {
        page->data[j] = random_next(rnd);
    }

    return data_size;
}

static ya_result
circular_file_test(bool can_grow)
{
    static const char* check_file = "/tmp/data-file.bin";
    static const char* journal_file = "/tmp/circular-file.cf";

    formatln("working for %i entries", g_page_count);

    file_pool_t fp = file_pool_init("circular-files", 4);
    circular_file_s *cf;
    ya_result ret;

    struct reserved_header_s hdr = {0, 0, 0, 0};
    static const u8 magic[4] = {'C','F',0,0};

    unlink(check_file);
    unlink(journal_file);

    random_ctx rnd = random_init(0);

    output_stream fos;
    file_output_stream_create(&fos, check_file, 0640);
    buffer_output_stream_init(&fos, &fos, 4096);

    bool did_grow = FALSE;

    if(ISOK(ret = circular_file_create(&cf, fp, magic, journal_file, JOURNAL_SIZE, sizeof(hdr))))
    {
        if(ISOK(ret = circular_file_write_reserved_header(cf, &hdr, sizeof(hdr))))
        {
            struct page_s page;
            u32 data_size = 0;
            int last_built_page = -1;

            for(int i = 0; i < g_page_count; ++i)
            {
                format("writing page [%5i; %5i]\nbefore: ", hdr.from, hdr.to);
                circular_file_dump(cf);

                if(last_built_page != i)
                {
                    data_size = page_build(&page, i, rnd);
                    last_built_page = i;
                }

                ret = circular_file_write(cf, &page, sizeof(page.hdr) + data_size);

                print(" after: ");
                circular_file_dump(cf);

                if(ISOK(ret))
                {
                    formatln("circular_file_write: wrote %i=%i bytes", sizeof(page.hdr) + data_size, ret);

                    hdr.to = i + 1;

                    if(FAIL(ret = circular_file_write_reserved_header(cf, &hdr, sizeof(hdr))))
                    {
                        abort();
                    }

                    if(ISOK(ret = circular_file_flush(cf)))
                    {
                        formatln("circular_file_write: synced", ret);
                    }
                    else
                    {
                        formatln("circular_file_write: failed to sync: %r", ret);
                    }
                }
                else
                {
                    if( (can_grow) && !did_grow && (circular_file_get_pending_size(cf) == circular_file_get_maximum_size(cf)) )
                    {
                        circular_file_grow(cf, circular_file_get_maximum_size(cf) + 16384);
                        formatln("circular_file_grow: allowing to grow up to: %llu", circular_file_get_pending_size(cf));
                        did_grow = TRUE;
                    }
                    else
                    {
                        did_grow = FALSE;

                        formatln("circular_file_write: failed to write %i bytes: %r", sizeof(page.hdr) + data_size, ret);

                        u64 position = circular_file_tell(cf);
                        formatln("circular_file_tell: before shift: %llu", position);

                        if(ISOK(ret = circular_file_seek(cf, 0)))
                        {
                            formatln("circular_file_seek: moved at position 0");
                        }
                        else
                        {
                            formatln("circular_file_seek: failed to move at position 0: %r", ret);
                        }

                        print(" bread: "); circular_file_dump(cf);

                        struct page_s page;

                        if(ISOK(ret = circular_file_read(cf, &page.hdr, sizeof(page.hdr))))
                        {
                            if(ISOK(ret = circular_file_read(cf, page.data, page.hdr.size)))
                            {
                                print(" aread: "); circular_file_dump(cf);

                                formatln("circular_file_read: read %i bytes at the beginning: {%x, %u, %u, %u}", sizeof(page.hdr) + page.hdr.size,
                                        page.hdr.magic, page.hdr.from, page.hdr.to, page.hdr.size);

                                output_stream_write(&fos, &page, sizeof(page.hdr) + page.hdr.size);
                            }
                        }
                        else
                        {
                            formatln("circular_file_read: failed to read %i bytes at the beginning: %r", sizeof(page.hdr) + page.hdr.size, ret);
                            break;
                        }

                        if(ISOK(ret = circular_file_shift(cf, sizeof(page.hdr) + page.hdr.size)))
                        {
                            formatln("circular_file_shift: shifted %i bytes", sizeof(page.hdr) + page.hdr.size);
                            print(" shift: "); circular_file_dump(cf);
                        }
                        else
                        {
                            formatln("circular_file_shift: failed to shift %i bytes at the beginning: %r", sizeof(page.hdr) + page.hdr.size, ret);
                            break;
                        }

                        hdr.from = page.hdr.to;

                        if(FAIL(ret = circular_file_write_reserved_header(cf, &hdr, sizeof(hdr))))
                        {
                            break;
                        }

                        position -= sizeof(page.hdr) + page.hdr.size;

                        u64 real_position;
                        real_position = circular_file_seek(cf, position);

                        if(real_position == position)
                        {
                            formatln("circular_file_seek: moved at position %llu", position);
                        }
                        else
                        {
                            formatln("circular_file_seek: failed to move at position %llu: real position is %llu", position, real_position);
                        }

                        position = circular_file_tell(cf);
                        formatln("circular_file_tell: after shift: %llu", position);
                    }

                    flushout();
                    --i;
                }
            }


        }
        else
        {
            formatln("circular_file_write_reserved_header: failed to write %i bytes: %r", sizeof(hdr), ret);
        }

        if(ISOK(ret))
        {
            formatln("copying pages still in the journal file");

            if(ISOK(ret = circular_file_seek(cf, 0)))
            {
                formatln("circular_file_seek: moved at position 0");

                while(circular_file_get_read_available(cf) > 0)
                {
                    struct page_s page;

                    if(ISOK(ret = circular_file_read(cf, &page.hdr, sizeof(page.hdr))))
                    {
                        if(ISOK(ret = circular_file_read(cf, page.data, page.hdr.size)))
                        {
                            print(" aread: "); circular_file_dump(cf);

                            formatln("circular_file_read: read %i bytes at the beginning: {%x, %u, %u, %u}", sizeof(page.hdr) + page.hdr.size,
                                    page.hdr.magic, page.hdr.from, page.hdr.to, page.hdr.size);

                            output_stream_write(&fos, &page, sizeof(page.hdr) + page.hdr.size);
                        }
                    }
                }
            }

            if(ISOK(ret = circular_file_close(cf)))
            {
                formatln("circular_file_close: success", ret);
            }
            else
            {
                formatln("circular_file_create: failed: %r", ret);
            }

            output_stream_close(&fos);

            random_finalize(rnd);
            random_ctx rnd = random_init(0);
            input_stream fis;
            file_input_stream_open(&fis, check_file);
            buffer_input_stream_init(&fis, &fis, 4096);

            for(int i = 0; i < g_page_count; ++i)
            {
                struct page_s page;
                if(ISOK(ret = input_stream_read(&fis, &page.hdr, sizeof(page.hdr))))
                {
                    if(page.hdr.magic != PAGE_MAGIC)
                    {
                        formatln("data integrity error at page #%i: wrong magic", i);
                        break;
                    }

                    if(ISOK(ret = input_stream_read(&fis, page.data, page.hdr.size)))
                    {
                        // check for content

                        bool valid = TRUE;

                        for(u32 j = 0; j < page.hdr.size; ++j)
                        {
                            u8 b = random_next(rnd);
                            if(page.data[j] != b)
                            {
                                formatln("data integrity error at page #%i offset %i (%08x != %08x)", i, j, page.data[j], b);
                                flushout();
                                valid = FALSE;
                                break;
                            }
                        }

                        if(valid)
                        {
                            formatln("data integrity of page #%i is verified", i);
                        }
                    }
                }
            }

            input_stream_close(&fis);
            random_finalize(rnd);
        }
    }
    else
    {
        formatln("circular_file_create: failed: %r", ret);
    }

    formatln("circular-file test for %i entries done", g_page_count);

    file_pool_finalize(fp);

    return ret;
}

struct circular_file_resize_script_line_s
{
    char command;
    s64 size;
};

typedef struct circular_file_resize_script_line_s circular_file_resize_script_line_t;

static u8 *vf_buffer = NULL;
static s64 vf_buffer_size = 0;

/*
 * C create with sizemax
 * W write
 * R read
 * S shift
 * P set position (seek)
 * Z resize
 * w available to write expected
 * r available to read expected
 */

static ya_result
circular_file_script_test(const circular_file_resize_script_line_t *lines, size_t lines_count)
{
    if(vf_buffer == NULL)
    {
        vf_buffer_size = 16 * 1024 * 1024;
        vf_buffer_size &= ~3;
        vf_buffer = (u8*)malloc(vf_buffer_size);
        random_ctx rnd = random_init(0);
        for(s64 i = 0; i < vf_buffer_size; i += 4)
        {
            SET_U32_AT(vf_buffer[i], random_next(rnd));
        }
        random_finalize(rnd);
    }

    static const char* journal_file = "/tmp/circular-file-2.cf";

    file_pool_t fp = file_pool_init("circular-files", 4);
    circular_file_s *cf = NULL;
    ya_result ret;

    struct reserved_header_s hdr = {0, 0, 0, 0};
    static const u8 magic[4] = {'C','F',0,0};

    unlink(journal_file);

    s64 position = 0;
    s64 shift = 0;

    if(lines[0].command != 'C')
    {
        formatln("expected to start with a 'C', got a '%c'", lines[0].command);
        return ERROR;
    }

    for(size_t line_num = 0; line_num < lines_count; ++line_num)
    {
        const circular_file_resize_script_line_t *line = &lines[line_num];

        formatln("vf: %lli + %lli", shift, position);

        if(cf != NULL)
        {
            formatln("size: %lli, position: %lli, available: read: %lli, write: %lli", circular_file_get_size(cf), circular_file_tell(cf), circular_file_get_read_available(cf), circular_file_get_write_available(cf));
        }

        formatln("[%2llu] command: '%c' %lli", line_num, line->command, line->size);
        flushout();

        switch(line->command)
        {
            case 'C':
            {
                if(ISOK(ret = circular_file_create(&cf, fp, magic, journal_file, line->size, sizeof(hdr))))
                {
                    if(ISOK(ret = circular_file_write_reserved_header(cf, &hdr, sizeof(hdr))))
                    {
                        break;
                    }
                }

                goto circular_file_test_exit;
            }
            case 'W':
            {
                ret = circular_file_write(cf, &vf_buffer[shift + position], line->size);

                if(FAIL(ret))
                {

                    formatln("write %lli bytes failed: %r", line->size, ret);
                    flushout();
                    goto circular_file_test_exit;
                }

                if(ret != line->size)
                {
                    formatln("write failed: %i bytes instead of %lli", ret, line->size);
                    flushout();
                    goto circular_file_test_exit;
                }

                position += ret;

                break;
            }
            case 'R':
            {
                char tmp[line->size];

                ret = circular_file_read(cf, tmp, line->size);

                if(FAIL(ret))
                {

                    formatln("read %lli bytes failed: %r", line->size, ret);
                    flushout();
                    goto circular_file_test_exit;
                }

                if(ret != line->size)
                {
                    formatln("read failed: %i bytes instead of %lli", ret, line->size);
                    flushout();
                    goto circular_file_test_exit;
                }

                if(memcmp(tmp, &vf_buffer[shift + position], ret) != 0)
                {
                    s64 failed_offset = -1;
                    for(int i = 0; i < ret; ++i)
                    {
                        if(tmp[i] != vf_buffer[shift + position + i])
                        {
                            failed_offset = i;
                            break;
                        }
                    }

                    formatln("read failed: content isn't matching at %lli + %lli + %lli", shift, position, failed_offset);
                    flushout();
                    goto circular_file_test_exit;
                }

                position += ret;

                break;
            }
            case 'S':
            {
                circular_file_shift(cf, line->size);

                shift += line->size;
                position -= line->size;
                break;
            }
            case 'P':
            {
                circular_file_seek(cf, line->size);

                s64 n = circular_file_tell(cf);
                if(n != line->size)
                {
                    formatln("seek failed: went to position %lli instead of %lli", n, line->size);
                    flushout();
                    ret = ERROR; goto circular_file_test_exit;
                }

                position = line->size;
                break;
            }
            case 'Z':
            {
                circular_file_set_size(cf, line->size);
                break;
            }
            case 'w':
            {
                s64 n = circular_file_get_write_available(cf);

                if(n != line->size)
                {
                    formatln("write available: %lli bytes instead of %lli", n, line->size);
                    flushout();
                    ret = ERROR; goto circular_file_test_exit;
                }
                break;
            }
            case 'r':
            {
                s64 n = circular_file_get_read_available(cf);

                if(n != line->size)
                {
                    formatln("read available: %lli bytes instead of %lli", n, line->size);
                    flushout();
                    ret = ERROR; goto circular_file_test_exit;
                }
                break;
            }
        }
    }
    
circular_file_test_exit:
    
    if(cf != NULL)
    {
        if(ISOK(ret = circular_file_close(cf)))
        {
            formatln("circular_file_close: success", ret);
        }
        else
        {
            formatln("circular_file_create: failed: %r", ret);
        }
    }

    file_pool_finalize(fp);

    return SUCCESS;
}

int
main(int argc, char *argv[])
{
    if(argc > 1)
    {
        g_page_count = atoi(argv[1]);
        if(g_page_count <= 0)
        {
            g_page_count = PAGE_COUNT;
        }
    }
    
    /* initializes the core library */
    
    dnscore_init();

    ya_result ret;
    int exit_code = EXIT_SUCCESS;
/*
    if(FAIL(ret = circular_file_test(TRUE)))
    {
        formatln("can-grow failed: %r", ret);
        exit_code = EXIT_FAILURE;
        
    }
    else if(FAIL(ret = circular_file_test(FALSE)))
    {
        formatln("no-grow failed: %r", ret);
        exit_code = EXIT_FAILURE;
    }
    else
    */
    {
        static const circular_file_resize_script_line_t script[] =
        {
            {'C', 16384 + 48},
            {'W', 16384},
            {'w', 0},
            {'S', 2048},
            {'w', 2048},
            {'W', 2048},
            {'w', 0},
            {'Z', 2048},
            {'P', 0},
            {'r', 2048},
            {'R', 2048},
            {'P', 0},
            {'r', 2048},
            {'R', 2048},
            {'W', 4096},
            {'P', 0},
            {'r', 2048 + 4096},
            {'R', 2048 + 4096},
            //{'P', 0},
            {'S', 4096},
            {'P', 0},   // mandatory as the shift doesn't handle underflow
            {'r', 2048},
            {'R', 2048},
        };

        s64 script_lines = sizeof(script) / sizeof(script[0]);

        if(FAIL(ret =  circular_file_script_test(&script[0], script_lines)))
        {
            formatln("script failed");
            exit_code = EXIT_FAILURE;
        }
    }

    flushout();
    flusherr();
    fflush(NULL);

    dnscore_finalize();

    return exit_code;
}
