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

/** @defgroup ### #######
 *  @ingroup dnscore
 *  @brief
 *
 * @{
 */

#pragma once

#include <openssl/ssl.h>


#define SSL_TOSTRING(s) TOSTRING_(s)
#define SSL_TOSTRING_(s) #s    

#if LIBRESSL_VERSION_NUMBER
// Cannot trust LIBRESSL's OPENSSL_VERSION_NUMBER value
#define SSL_API 1

#if (LIBRESSL_VERSION_NUMBER >= 0x20000000L) && (LIBRESSL_VERSION_NUMBER < 0x40000000L)
//#pragma message "LIBRESSL [v2; v4["
#define SSL_API_LT_111 1
#define SSL_API_LT_110 0
#define SSL_API_LT_100 0
#else
#pragma message("Unsupported LibreSSL version " SSL_TOSTRING(LIBRESSL_VERSION_NUMBER))
#error "Unsupported LibreSSL version"
#endif

#elif  OPENSSL_VERSION_NUMBER
#define SSL_API 1

// warning: this use of "defined" may not be portable [-Wexpansion-to-defined]
//
// #define SSL_API_LT_110 ((OPENSSL_VERSION_NUMBER < 0x10100000L) || defined(LIBRESSL_VERSION_NUMBER))
//
// hence:
//

#if OPENSSL_VERSION_NUMBER < 0x10101000L
#define SSL_API_LT_111 1
#endif

#if OPENSSL_VERSION_NUMBER < 0x10100000L
#define SSL_API_LT_110 1
#else
#define SSL_API_LT_110 0
#endif

#define SSL_API_LT_100 (OPENSSL_VERSION_NUMBER < 0x10000000L)
#else
#define SSL_API 0
#endif

#ifdef __cplusplus
extern "C" {
#endif




#ifdef __cplusplus
}
#endif

/** @} */
