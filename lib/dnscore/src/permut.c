/*------------------------------------------------------------------------------
 *
 * Copyright (c) 2011-2024, EURid vzw. All rights reserved.
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
 *----------------------------------------------------------------------------*/

/**-----------------------------------------------------------------------------
 * @defgroup
 * @ingroup dnscore
 * @brief
 *
 *
 *
 * @{
 *----------------------------------------------------------------------------*/

#include "dnscore/dnscore_config.h"

#include "dnscore/sys_types.h"
#include "dnscore/pcg_basic.h"

#define FACTORIAL_MAX 20

static const uint64_t factorial_list[FACTORIAL_MAX + 1] = {
    1LL,
    1LL,
    2LL,
    6LL,
    24LL,
    120LL,
    720LL,
    5040LL,
    40320LL,
    362880LL,
    3628800LL,
    39916800LL,
    479001600LL,
    6227020800LL,
    87178291200LL,
    1307674368000LL,
    20922789888000LL,
    355687428096000LL,
    6402373705728000LL,
    121645100408832000LL,
    2432902008176640000LL,
};

static const uint32_t permut_2[2][2] = {
    {
        0,
        1,
    }, // 2, 0
    {
        1,
        0,
    } // 2, 1
};

static const uint32_t permut_3[6][3] = {
    {
        0,
        2,
        1,
    }, // 3, 0
    {
        0,
        1,
        2,
    }, // 3, 1
    {
        1,
        0,
        2,
    }, // 3, 2
    {
        1,
        2,
        0,
    }, // 3, 3
    {
        2,
        0,
        1,
    }, // 3, 4
    {
        2,
        1,
        0,
    } // 3, 5
};

static const uint32_t permut_4[24][4] = {
    {
        0,
        3,
        2,
        1,
    }, // 4, 0
    {
        0,
        3,
        1,
        2,
    }, // 4, 1
    {
        0,
        1,
        3,
        2,
    }, // 4, 2
    {
        0,
        1,
        2,
        3,
    }, // 4, 3
    {
        0,
        2,
        3,
        1,
    }, // 4, 4
    {
        0,
        2,
        1,
        3,
    }, // 4, 5
    {
        1,
        0,
        2,
        3,
    }, // 4, 6
    {
        1,
        0,
        3,
        2,
    }, // 4, 7
    {
        1,
        3,
        0,
        2,
    }, // 4, 8
    {
        1,
        3,
        2,
        0,
    }, // 4, 9
    {
        1,
        2,
        0,
        3,
    }, // 4, 10
    {
        1,
        2,
        3,
        0,
    }, // 4, 11
    {
        2,
        0,
        3,
        1,
    }, // 4, 12
    {
        2,
        0,
        1,
        3,
    }, // 4, 13
    {
        2,
        1,
        0,
        3,
    }, // 4, 14
    {
        2,
        1,
        3,
        0,
    }, // 4, 15
    {
        2,
        3,
        0,
        1,
    }, // 4, 16
    {
        2,
        3,
        1,
        0,
    }, // 4, 17
    {
        3,
        0,
        2,
        1,
    }, // 4, 18
    {
        3,
        0,
        1,
        2,
    }, // 4, 19
    {
        3,
        1,
        0,
        2,
    }, // 4, 20
    {
        3,
        1,
        2,
        0,
    }, // 4, 21
    {
        3,
        2,
        0,
        1,
    }, // 4, 22
    {
        3,
        2,
        1,
        0,
    } // 4, 23
};

static const uint32_t permut_5[120][5] = {
    {
        0,
        4,
        3,
        2,
        1,
    }, // 5, 0
    {
        0,
        4,
        3,
        1,
        2,
    }, // 5, 1
    {
        0,
        4,
        1,
        3,
        2,
    }, // 5, 2
    {
        0,
        4,
        1,
        2,
        3,
    }, // 5, 3
    {
        0,
        4,
        2,
        3,
        1,
    }, // 5, 4
    {
        0,
        4,
        2,
        1,
        3,
    }, // 5, 5
    {
        0,
        1,
        4,
        2,
        3,
    }, // 5, 6
    {
        0,
        1,
        4,
        3,
        2,
    }, // 5, 7
    {
        0,
        1,
        3,
        4,
        2,
    }, // 5, 8
    {
        0,
        1,
        3,
        2,
        4,
    }, // 5, 9
    {
        0,
        1,
        2,
        4,
        3,
    }, // 5, 10
    {
        0,
        1,
        2,
        3,
        4,
    }, // 5, 11
    {
        0,
        2,
        4,
        3,
        1,
    }, // 5, 12
    {
        0,
        2,
        4,
        1,
        3,
    }, // 5, 13
    {
        0,
        2,
        1,
        4,
        3,
    }, // 5, 14
    {
        0,
        2,
        1,
        3,
        4,
    }, // 5, 15
    {
        0,
        2,
        3,
        4,
        1,
    }, // 5, 16
    {
        0,
        2,
        3,
        1,
        4,
    }, // 5, 17
    {
        0,
        3,
        4,
        2,
        1,
    }, // 5, 18
    {
        0,
        3,
        4,
        1,
        2,
    }, // 5, 19
    {
        0,
        3,
        1,
        4,
        2,
    }, // 5, 20
    {
        0,
        3,
        1,
        2,
        4,
    }, // 5, 21
    {
        0,
        3,
        2,
        4,
        1,
    }, // 5, 22
    {
        0,
        3,
        2,
        1,
        4,
    }, // 5, 23
    {
        1,
        0,
        3,
        2,
        4,
    }, // 5, 24
    {
        1,
        0,
        3,
        4,
        2,
    }, // 5, 25
    {
        1,
        0,
        4,
        3,
        2,
    }, // 5, 26
    {
        1,
        0,
        4,
        2,
        3,
    }, // 5, 27
    {
        1,
        0,
        2,
        3,
        4,
    }, // 5, 28
    {
        1,
        0,
        2,
        4,
        3,
    }, // 5, 29
    {
        1,
        4,
        0,
        2,
        3,
    }, // 5, 30
    {
        1,
        4,
        0,
        3,
        2,
    }, // 5, 31
    {
        1,
        4,
        3,
        0,
        2,
    }, // 5, 32
    {
        1,
        4,
        3,
        2,
        0,
    }, // 5, 33
    {
        1,
        4,
        2,
        0,
        3,
    }, // 5, 34
    {
        1,
        4,
        2,
        3,
        0,
    }, // 5, 35
    {
        1,
        2,
        0,
        3,
        4,
    }, // 5, 36
    {
        1,
        2,
        0,
        4,
        3,
    }, // 5, 37
    {
        1,
        2,
        4,
        0,
        3,
    }, // 5, 38
    {
        1,
        2,
        4,
        3,
        0,
    }, // 5, 39
    {
        1,
        2,
        3,
        0,
        4,
    }, // 5, 40
    {
        1,
        2,
        3,
        4,
        0,
    }, // 5, 41
    {
        1,
        3,
        0,
        2,
        4,
    }, // 5, 42
    {
        1,
        3,
        0,
        4,
        2,
    }, // 5, 43
    {
        1,
        3,
        4,
        0,
        2,
    }, // 5, 44
    {
        1,
        3,
        4,
        2,
        0,
    }, // 5, 45
    {
        1,
        3,
        2,
        0,
        4,
    }, // 5, 46
    {
        1,
        3,
        2,
        4,
        0,
    }, // 5, 47
    {
        2,
        0,
        3,
        4,
        1,
    }, // 5, 48
    {
        2,
        0,
        3,
        1,
        4,
    }, // 5, 49
    {
        2,
        0,
        1,
        3,
        4,
    }, // 5, 50
    {
        2,
        0,
        1,
        4,
        3,
    }, // 5, 51
    {
        2,
        0,
        4,
        3,
        1,
    }, // 5, 52
    {
        2,
        0,
        4,
        1,
        3,
    }, // 5, 53
    {
        2,
        1,
        0,
        4,
        3,
    }, // 5, 54
    {
        2,
        1,
        0,
        3,
        4,
    }, // 5, 55
    {
        2,
        1,
        3,
        0,
        4,
    }, // 5, 56
    {
        2,
        1,
        3,
        4,
        0,
    }, // 5, 57
    {
        2,
        1,
        4,
        0,
        3,
    }, // 5, 58
    {
        2,
        1,
        4,
        3,
        0,
    }, // 5, 59
    {
        2,
        4,
        0,
        3,
        1,
    }, // 5, 60
    {
        2,
        4,
        0,
        1,
        3,
    }, // 5, 61
    {
        2,
        4,
        1,
        0,
        3,
    }, // 5, 62
    {
        2,
        4,
        1,
        3,
        0,
    }, // 5, 63
    {
        2,
        4,
        3,
        0,
        1,
    }, // 5, 64
    {
        2,
        4,
        3,
        1,
        0,
    }, // 5, 65
    {
        2,
        3,
        0,
        4,
        1,
    }, // 5, 66
    {
        2,
        3,
        0,
        1,
        4,
    }, // 5, 67
    {
        2,
        3,
        1,
        0,
        4,
    }, // 5, 68
    {
        2,
        3,
        1,
        4,
        0,
    }, // 5, 69
    {
        2,
        3,
        4,
        0,
        1,
    }, // 5, 70
    {
        2,
        3,
        4,
        1,
        0,
    }, // 5, 71
    {
        3,
        0,
        4,
        2,
        1,
    }, // 5, 72
    {
        3,
        0,
        4,
        1,
        2,
    }, // 5, 73
    {
        3,
        0,
        1,
        4,
        2,
    }, // 5, 74
    {
        3,
        0,
        1,
        2,
        4,
    }, // 5, 75
    {
        3,
        0,
        2,
        4,
        1,
    }, // 5, 76
    {
        3,
        0,
        2,
        1,
        4,
    }, // 5, 77
    {
        3,
        1,
        0,
        2,
        4,
    }, // 5, 78
    {
        3,
        1,
        0,
        4,
        2,
    }, // 5, 79
    {
        3,
        1,
        4,
        0,
        2,
    }, // 5, 80
    {
        3,
        1,
        4,
        2,
        0,
    }, // 5, 81
    {
        3,
        1,
        2,
        0,
        4,
    }, // 5, 82
    {
        3,
        1,
        2,
        4,
        0,
    }, // 5, 83
    {
        3,
        2,
        0,
        4,
        1,
    }, // 5, 84
    {
        3,
        2,
        0,
        1,
        4,
    }, // 5, 85
    {
        3,
        2,
        1,
        0,
        4,
    }, // 5, 86
    {
        3,
        2,
        1,
        4,
        0,
    }, // 5, 87
    {
        3,
        2,
        4,
        0,
        1,
    }, // 5, 88
    {
        3,
        2,
        4,
        1,
        0,
    }, // 5, 89
    {
        3,
        4,
        0,
        2,
        1,
    }, // 5, 90
    {
        3,
        4,
        0,
        1,
        2,
    }, // 5, 91
    {
        3,
        4,
        1,
        0,
        2,
    }, // 5, 92
    {
        3,
        4,
        1,
        2,
        0,
    }, // 5, 93
    {
        3,
        4,
        2,
        0,
        1,
    }, // 5, 94
    {
        3,
        4,
        2,
        1,
        0,
    }, // 5, 95
    {
        4,
        0,
        3,
        2,
        1,
    }, // 5, 96
    {
        4,
        0,
        3,
        1,
        2,
    }, // 5, 97
    {
        4,
        0,
        1,
        3,
        2,
    }, // 5, 98
    {
        4,
        0,
        1,
        2,
        3,
    }, // 5, 99
    {
        4,
        0,
        2,
        3,
        1,
    }, // 5, 100
    {
        4,
        0,
        2,
        1,
        3,
    }, // 5, 101
    {
        4,
        1,
        0,
        2,
        3,
    }, // 5, 102
    {
        4,
        1,
        0,
        3,
        2,
    }, // 5, 103
    {
        4,
        1,
        3,
        0,
        2,
    }, // 5, 104
    {
        4,
        1,
        3,
        2,
        0,
    }, // 5, 105
    {
        4,
        1,
        2,
        0,
        3,
    }, // 5, 106
    {
        4,
        1,
        2,
        3,
        0,
    }, // 5, 107
    {
        4,
        2,
        0,
        3,
        1,
    }, // 5, 108
    {
        4,
        2,
        0,
        1,
        3,
    }, // 5, 109
    {
        4,
        2,
        1,
        0,
        3,
    }, // 5, 110
    {
        4,
        2,
        1,
        3,
        0,
    }, // 5, 111
    {
        4,
        2,
        3,
        0,
        1,
    }, // 5, 112
    {
        4,
        2,
        3,
        1,
        0,
    }, // 5, 113
    {
        4,
        3,
        0,
        2,
        1,
    }, // 5, 114
    {
        4,
        3,
        0,
        1,
        2,
    }, // 5, 115
    {
        4,
        3,
        1,
        0,
        2,
    }, // 5, 116
    {
        4,
        3,
        1,
        2,
        0,
    }, // 5, 117
    {
        4,
        3,
        2,
        0,
        1,
    }, // 5, 118
    {
        4,
        3,
        2,
        1,
        0,
    } // 5, 119
};

static uint64_t factorial(uint64_t x)
{
    if(x <= FACTORIAL_MAX)
    {
        return factorial_list[x];
    }
    else
    {
        return U64_MAX;
    }
}

static void permut_combi_n_ptr(uint64_t values, uint64_t line, uint64_t d, void **p, void **b)
{
    assert(values >= 2);

    line %= d;

    d /= values;

    for(uint_fast64_t i = 0, v = values - 1; v > 0; ++i)
    {
        uint64_t index = line / d;
        line -= index * d;
        p[i] = b[index];
        b[index] = b[v];

        d /= v;
        --v;
    }

    p[values - 1] = b[0];
}

static void permut_random_n_ptr(uint64_t values, void **p, void **b, pcg32_random_t *rng)
{
    int i = 0;
    for(uint_fast64_t mod = values; mod > 0;)
    {
        uint64_t index = pcg32_random_r(rng) % mod;
        p[i++] = b[index];
        b[index] = b[--mod];
    }
}

void permut_pointers_randomly(void **dst, void *const *src, size_t count, pcg32_random_t *rng)
{
    if(count <= 5)
    {
        switch(count)
        {
            case 0:
            {
                break;
            }
            case 1:
            {
                dst[0] = src[0];
                break;
            }
            case 2:
            {
                uint32_t        n = pcg32_random_r(rng);
                const uint32_t *line = permut_2[n & 1];
                dst[0] = src[line[0]];
                dst[1] = src[line[1]];
                break;
            }
            case 3:
            {
                uint32_t        n = pcg32_random_r(rng);
                const uint32_t *line = permut_3[n % 3];
                dst[0] = src[line[0]];
                dst[1] = src[line[1]];
                dst[2] = src[line[2]];
                break;
            }
            case 4:
            {
                uint32_t        n = pcg32_random_r(rng);
                const uint32_t *line = permut_4[n & 3];
                dst[0] = src[line[0]];
                dst[1] = src[line[1]];
                dst[2] = src[line[2]];
                dst[3] = src[line[3]];
                break;
            }
            case 5:
            {
                uint32_t        n = pcg32_random_r(rng);
                const uint32_t *line = permut_5[n % 5];
                dst[0] = src[line[0]];
                dst[1] = src[line[1]];
                dst[2] = src[line[2]];
                dst[3] = src[line[3]];
                dst[4] = src[line[4]];
                break;
            }
        }
    }
    else if(count <= FACTORIAL_MAX)
    {
        uint64_t d = factorial(count);
        uint64_t n = pcg32_random_r(rng);
        n <<= 32;
        n |= pcg32_random_r(rng);
        uint64_t line = n % d;

        void    *src_copy[FACTORIAL_MAX];

        memcpy(src_copy, src, sizeof(void *) * count);

        permut_combi_n_ptr(count, line, d, dst, src_copy);
    }
    else // the slowest case, that hopefully doens't happen
    {
        void **src_copy = (void **)malloc(sizeof(void *) * count);

        memcpy(src_copy, src, sizeof(void *) * count);

        permut_random_n_ptr(count, dst, src_copy, rng);

        free(src_copy);
    }
}

/** @} */
