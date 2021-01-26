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

/** @defgroup hmac
 *  @ingroup dnscore
 *  @brief
 *
 * @{
 */

#pragma once

#include <dnscore/sys_types.h>

#define HMAC_UNKNOWN	  0
#define HMAC_MD5        157
#define HMAC_SHA1       161
#define HMAC_SHA224     162
#define HMAC_SHA256     163
#define HMAC_SHA384     164
#define HMAC_SHA512     165

#ifdef __cplusplus
extern "C" {
#endif
 
struct hmac_vtbl;

struct tsig_hmac_t
{
    const struct hmac_vtbl *vtbl;
    // ideally, implementations will append their fields on their opaque type
    // so only one allocation is used
};
    
typedef struct tsig_hmac_t* tsig_hmac_t;

struct hmac_vtbl
{
    int (*hmac_update)(tsig_hmac_t hmac, const void *data, size_t len);
    int (*hmac_final)(tsig_hmac_t hmac, void *out_data, unsigned int *out_len);
    void (*hmac_reset)(tsig_hmac_t t);
    ya_result (*hmac_init)(tsig_hmac_t t, const void *key, int len, u8 algorithm);
    void (*hmac_free)(tsig_hmac_t t);
};

typedef struct hmac_vtbl hmac_vtbl;

tsig_hmac_t tsig_hmac_allocate();

static inline void hmac_free(tsig_hmac_t t)
{
    t->vtbl->hmac_free(t);
}

static inline ya_result hmac_init(tsig_hmac_t t, const void *key, int len, u8 algorithm)
{
    return t->vtbl->hmac_init(t, key, len, algorithm);
}

static inline int hmac_update(tsig_hmac_t t, const void *data, size_t len)
{
    return t->vtbl->hmac_update(t, data, len);
}

static inline int hmac_final(tsig_hmac_t t, void *out_data, unsigned int *out_len)
{
    return t->vtbl->hmac_final(t, out_data, out_len);
}

static inline void hmac_reset(tsig_hmac_t t)
{
    t->vtbl->hmac_reset(t);
}

#ifdef __cplusplus
}
#endif

/** @} */
