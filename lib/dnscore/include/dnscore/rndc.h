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
#pragma once

#include <dnscore/output_stream.h>
#include <dnscore/ptr_vector.h>
#include <dnscore/tsig.h>
#include <dnscore/host_address.h>

/*
struct rndc_dict_s
{
    ptr_vector_t fields;
};
*/

#define RNDC_PARSE_DICT_TOP        0
#define RNDC_PARSE_DICT_AUTH       1
#define RNDC_PARSE_DICT_CTRL       2
#define RNDC_PARSE_DICT_DATA       3

#define RNDC_CONNECTED             1
#define RNDC_HANDSHAKED            2
#define RNDC_HAS_NONCE             4
#define RNDC_HAS_RESULT            8
#define RNDC_HAS_QUERY             16
#define RNDC_HAS_VALUE             32
#define RNDC_HAS_TEXT              64
#define RNDC_HAS_ERR               128

// result codes from : contrib/dlz/modules/include/dlz_minimal.h
// The ISC_R prefix is replaced by NAMED_ERROR to avoid potential collisions
/*
#define ISC_R_SUCCESS        0
#define ISC_R_NOMEMORY       1
#define ISC_R_NOPERM         6
#define ISC_R_NOSPACE        19
#define ISC_R_NOTFOUND       23
#define ISC_R_FAILURE        25
#define ISC_R_NOTIMPLEMENTED 27
#define ISC_R_NOMORE         29
#define ISC_R_INVALIDFILE    30
#define ISC_R_UNEXPECTED     34
#define ISC_R_FILENOTFOUND   38
*/
#define NAMED_ERROR_SUCCESS        0
#define NAMED_ERROR_NOMEMORY       1
#define NAMED_ERROR_NOPERM         6
#define NAMED_ERROR_NOSPACE        19
#define NAMED_ERROR_NOTFOUND       23
#define NAMED_ERROR_FAILURE        25
#define NAMED_ERROR_NOTIMPLEMENTED 27
#define NAMED_ERROR_NOMORE         29
#define NAMED_ERROR_INVALIDFILE    30
#define NAMED_ERROR_UNEXPECTED     34
#define NAMED_ERROR_FILENOTFOUND   38

struct rndc_message_s
{
    output_stream_t    baos;

    output_stream_t    tcp_os;
    input_stream_t     tcp_is;

    int                sockfd;

    output_stream_t    text_output;
    struct tsig_key_s *tsig_key;

    char              *auth_pointer;
    const uint8_t     *auth_message;

    char              *type_value;
    char              *err_value;
    char              *text_value;

    uint32_t           auth_size;
    uint32_t           auth_message_size;
    uint32_t           type_len;
    uint32_t           err_len;
    uint32_t           text_len;
    uint32_t           result;

    uint32_t           ser;
    uint32_t           tim;
    uint32_t           exp;
    uint32_t           nonce;

    uint8_t            state_flags;
    uint8_t            parse_location;
};

typedef struct rndc_message_s rndc_message_t;

typedef ya_result             rndc_recv_process_callback(rndc_message_t *, void *); // rndc, args

// gets the type in the rndc message
ya_result rndc_message_type_get(rndc_message_t *rndcmsg, const void **type_valuep, uint32_t *type_sizep);

// sets the type in the rndc message
ya_result rndc_message_type_set(rndc_message_t *rndcmsg, const void *type_value, uint32_t type_size);

// gets the text in the rndc message
ya_result rndc_message_text_get(rndc_message_t *rndcmsg, const void **textp, uint32_t *sizep);

// sets the text in the rndc message
ya_result rndc_message_text_set(rndc_message_t *rndcmsg, const void *text_value, uint32_t text_size);

// gets the err in the rndc message
ya_result rndc_message_err_get(rndc_message_t *rndcmsg, const void **errp, uint32_t *sizep);

// sets the err in the rndc message
ya_result rndc_message_err_set(rndc_message_t *rndcmsg, const void *err_value, uint32_t err_size);

ya_result rndc_message_result_set(rndc_message_t *rndcmsg, uint32_t value);

ya_result rndc_init_and_connect(rndc_message_t *rndcmsg, const host_address_t *ha, struct tsig_key_s *tsig_key);
ya_result rndc_init_and_recv_from_socket(rndc_message_t *rndcmsg, int sockfd, struct tsig_key_s *tsig_key);
ya_result rndc_send(rndc_message_t *rndcmsg, const void *command, size_t command_size);
ya_result rndc_send_command(rndc_message_t *rndcmsg, const char *command);
ya_result rndc_result(rndc_message_t *rndcmsg, uint32_t *resultp);
// ya_result rndc_recv(rndc_message_t *rndcmsg, const void *command, size_t command_size);
ya_result rndc_recv_process(rndc_message_t *rndcmsg, rndc_recv_process_callback *process_callback, void *args);
void      rndc_disconnect(rndc_message_t *rndcmsg);

uint32_t  yadifa_error_to_named_error(ya_result code);

/** @} */
