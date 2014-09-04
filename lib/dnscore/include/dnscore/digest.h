/*------------------------------------------------------------------------------
*
* Copyright (c) 2011, EURid. All rights reserved.
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
/** @defgroup dnskey DNSSEC keys functions
 *  @ingroup dnsdbdnssec
 *  @brief 
 *
 *
 * @{
 */
#ifndef _DIGEST_H
#define	_DIGEST_H

#include <openssl/engine.h>
#include <openssl/sha.h>
#include <dnscore/sys_types.h>

#define DIGEST_BUFFER_SIZE 64

struct digest_s;

typedef s32 digest_update_method(struct digest_s*,const void*, u32);
typedef s32 digest_final_method(struct digest_s*, void*, u32);
typedef s32 digest_get_size_method(struct digest_s*);

struct digest_vtbl
{
    digest_update_method* update;
    digest_final_method* final;
    digest_get_size_method* get_size;
    const char * __class__;
};

struct digest_s
{
    const struct digest_vtbl *vtbl;
    union
    {
        SHA_CTX sha0;
        SHA_CTX sha1;
        SHA256_CTX sha256;
        SHA512_CTX sha384;
        SHA512_CTX sha512;
    } ctx;
};

typedef struct digest_s digest_s;

#define digest_class(is_) ((is_)->vtbl)
#define digest_class_name(is_) ((is_)->vtbl->__class__)
#define digest_update(ctx_,buffer_,len_) (ctx_)->vtbl->update(ctx_,buffer_,len_)
#define digest_final(ctx_,buffer_,len_) (ctx_)->vtbl->final(ctx_,buffer_,len_)
#define digest_get_size(ctx_) (ctx_)->vtbl->get_size(ctx_)

#ifndef OPENSSL_NO_SHA1
void digest_sha1_init(digest_s *ctx);
#endif

#ifndef OPENSSL_NO_SHA256
void digest_sha256_init(digest_s *ctx);
#endif

#ifndef OPENSSL_NO_SHA512
void digest_sha384_init(digest_s *ctx);
void digest_sha512_init(digest_s *ctx);
#endif

#ifndef OPENSSL_NO_SHA0
void digest_sha0_init(digest_s *ctx);
#endif

#endif // _DIGEST_H
