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

/** @defgroup dnscoreerror Error
 *  @ingroup dnscore
 *  @brief
 *
 *
 *
 * @{
 *
 *----------------------------------------------------------------------------*/

#include <openssl/err.h>
#include <dnscore/logger_handle.h>
#include "dnscore/dnscore-config.h"
#include "dnscore/sys_types.h"
#include "dnscore/sys_error.h"
#include "dnscore/rfc.h"
#include "dnscore/u32_set.h"
#include "dnscore/output_stream.h"
#include "dnscore/format.h"
#include "dnscore/dnssec_errors.h"
#include "dnscore/parser.h"
#include "dnscore/config_settings.h"
#include "dnscore/cmdline.h"
#include "dnscore/zone_reader.h"
#include "dnscore/zone_reader_text.h"

extern logger_handle *g_system_logger;
#define MODULE_MSG_HANDLE g_system_logger

#define ERRORTBL_TAG 0x4c4254524f525245

#define ERROR_TEXT_COPIED 0

/*----------------------------------------------------------------------------*/

void
dief(ya_result error_code, const char* format, ...)
{
    /**
     * @note Cannot use format here.  The output call HAS to be from the standard library/system.
     */
    fflush(NULL);
    fprintf(stderr, "critical error : %i %x '%s'\n", error_code, error_code, error_gettext(error_code));
    fflush(NULL);
    va_list args;
    va_start(args, format);
    vfprintf(stderr, format, args); /* Keep native */
    va_end(args);
    fflush(NULL);
    abort();
}

static u32_node *error_set = NULL;

void
error_register(ya_result code, const char* const text)
{
    if(text == NULL)
    {
        fprintf(stderr, "error_register(%08x, NULL): text cannot be NULL", code);
        fflush(stderr);
    }

    if(YA_ERROR_BASE(code) == ERRNO_ERROR_BASE)
    {
        fprintf(stderr, "error_register(%08x,%s): the errno space is reserved (0x8000xxxx), ignoring code", code, text);
        fflush(stderr);
        return;
    }

    u32_node *error_node;

    if((error_node = u32_set_find(&error_set, code)) == NULL)
    {
        error_node = u32_set_insert(&error_set, code);

        if(error_node->value == 0)
        {
#if ERROR_TEXT_COPIED
            error_node->value = strdup(text);
#else
            error_node->value = (void*)text; /// @note 20210427 edf -- it used to be strdup(text), but the parameter is supposed to be a constant string.
#endif
        }
    }
    else
    {
        fprintf(stderr, "error_register(%08x,%s): duplicate key, previous value = '%s'", code, text, (const char*)error_node->value);
        fflush(stderr);
    }
}

#if ERROR_TEXT_COPIED
static void
error_unregister_all_cb(u32_node *node)
{
    free(node->value);
}
#endif

void
error_unregister_all()
{
#if ERROR_TEXT_COPIED
    u32_set_callback_and_destroy(&error_set, error_unregister_all_cb);
#else
    u32_set_destroy(&error_set);
#endif
}

static char error_gettext_tmp[64];

/**
 * 
 * DEPRECATED
 * 
 * @param code
 * @return 
 */

const char*
error_gettext(ya_result code)
{
    /* errno handling */

    if(code > 0)
    {
        snprintf(error_gettext_tmp, sizeof(error_gettext_tmp), "success (%08x)", code);
        return error_gettext_tmp;
    }

    if(YA_ERROR_BASE(code) == ERRNO_ERROR_BASE)
    {
        return strerror(YA_ERROR_CODE(code));
    }

    /**/
    
    u32_node *error_node;
    
    error_node = u32_set_find(&error_set, code);
    if(error_node != NULL)
    {
        return (const char*)error_node->value;
    }
    
    u32 error_base = YA_ERROR_BASE(code);

    error_node = u32_set_find(&error_set, error_base);
    if(error_node != NULL)
    {
        return (const char*)error_node->value;
    }

    snprintf(error_gettext_tmp, sizeof(error_gettext_tmp), "undefined error code %08x", code);

    return error_gettext_tmp;
}

/**
 * 
 * Text representation of the error code
 * 
 * @param os
 * @param code
 */

void
error_writetext(output_stream *os, ya_result code)
{
    /* errno handling */

    if(code > 0)
    {
        osformat(os, "success (%08x)", code);
        return;
    }

    if(YA_ERROR_BASE(code) == ERRNO_ERROR_BASE)
    {
        code &= 0xffff;
#if DEBUG
        if(code == EINTR)
        {
            osprint(os, "<EINTR> "); // whoopsie
        }
#endif
        osprint(os, strerror(code));
        return;
    }
    else if(YA_ERROR_BASE(code) == SSL_ERROR_BASE)
    {
        code &= 0xffff;
        char buffer[256];
        ERR_error_string_n(code, buffer, sizeof(buffer));
        osformat(os, "SSL error %i '%s'", code, buffer);
        return;
    }

    /**/
    
    u32_node *error_node;
    
    error_node = u32_set_find(&error_set, code);
    if(error_node != NULL)
    {
        osprint(os, (const char*)error_node->value);
        return;
    }
    
    u32 error_base = YA_ERROR_BASE(code);

    error_node = u32_set_find(&error_set, error_base);
    if(error_node != NULL)
    {
        osformatln(os, "%s(%08x)", (const char*)error_node->value, code);
        return;
    }

    osformat(os, "undefined error code %08x", code);
}

static bool dnscore_register_errors_done = FALSE;

void
dnscore_register_errors()
{
    if(dnscore_register_errors_done)
    {
        return;
    }

    dnscore_register_errors_done = TRUE;

    error_register(SUCCESS, "SUCCESS");

    error_register(PARSEB16_ERROR, "PARSEB16_ERROR");
    error_register(PARSEB32_ERROR, "PARSEB32_ERROR");
    error_register(PARSEB32H_ERROR, "PARSEB32H_ERROR");
    error_register(PARSEB64_ERROR, "PARSEB64_ERROR");
    error_register(PARSEINT_ERROR, "PARSEINT_ERROR");
    error_register(PARSEDATE_ERROR, "PARSEDATE_ERROR");
    error_register(PARSEIP_ERROR, "PARSEIP_ERROR");

    error_register(CIRCULAR_FILE_FULL, "CIRCULAR_FILE_FULL");
    error_register(CIRCULAR_FILE_SHORT, "CIRCULAR_FILE_SHORT");
    error_register(CIRCULAR_FILE_END, "CIRCULAR_FILE_FULL");
    error_register(CIRCULAR_FILE_LIMIT_EXCEEDED, "CIRCULAR_FILE_LIMIT_EXCEEDED");

    error_register(DATA_FORMAT_ERROR, "DATA_FORMAT_ERROR");

    error_register(LOCK_FAILED, "LOCK_FAILED");
    
    error_register(TCP_RATE_TOO_SLOW, "TCP_RATE_TOO_SLOW");

    error_register(PARSEWORD_NOMATCH_ERROR, "PARSEWORD_NOMATCH_ERROR");
    error_register(PARSESTRING_ERROR, "PARSESTRING_ERROR");
    error_register(PARSE_BUFFER_TOO_SMALL_ERROR, "PARSE_BUFFER_TOO_SMALL_ERROR");
    error_register(PARSE_INVALID_CHARACTER, "PARSE_INVALID_CHARACTER");
    error_register(PARSE_INVALID_ARGUMENT, "PARSE_INVALID_ARGUMENT");
    error_register(PARSE_EMPTY_ARGUMENT, "PARSE_EMPTY_ARGUMENT");
    
    error_register(CONFIG_SECTION_CALLBACK_ALREADY_SET, "CONFIG_SECTION_CALLBACK_ALREADY_SET");
    error_register(CONFIG_SECTION_CALLBACK_NOT_SET, "CONFIG_SECTION_CALLBACK_NOT_SET");
    error_register(CONFIG_SECTION_CALLBACK_NOT_FOUND, "CONFIG_SECTION_CALLBACK_NOT_FOUND");
    error_register(CONFIG_NOT_A_REGULAR_FILE, "CONFIG_NOT_A_REGULAR_FILE");
    error_register(CONFIG_TOO_MANY_HOSTS, "CONFIG_TOO_MANY_HOSTS");
    error_register(CONFIG_FQDN_NOT_ALLOWED, "CONFIG_FQDN_NOT_ALLOWED");
    error_register(CONFIG_PORT_NOT_ALLOWED, "CONFIG_PORT_NOT_ALLOWED");
    error_register(CONFIG_EXPECTED_VALID_PORT_VALUE, "CONFIG_EXPECTED_VALID_PORT_VALUE");
    error_register(CONFIG_TSIG_NOT_ALLOWED, "CONFIG_TSIG_NOT_ALLOWED");
    error_register(CONFIG_INTERNAL_ERROR, "CONFIG_INTERNAL_ERROR");
    error_register(CONFIG_IPV4_NOT_ALLOWED, "CONFIG_IPV4_NOT_ALLOWED");
    error_register(CONFIG_IPV6_NOT_ALLOWED, "CONFIG_IPV6_NOT_ALLOWED");
    error_register(CONFIG_KEY_UNKNOWN, "CONFIG_KEY_UNKNOWN");
    error_register(CONFIG_KEY_PARSE_ERROR, "CONFIG_KEY_PARSE_ERROR");
    error_register(CONFIG_SECTION_ERROR, "CONFIG_SECTION_ERROR");
    error_register(CONFIG_IS_BUSY, "CONFIG_IS_BUSY");
    error_register(CONFIG_FILE_NOT_FOUND, "CONFIG_FILE_NOT_FOUND");

    error_register(LOGGER_INITIALISATION_ERROR, "LOGGER_INITIALISATION_ERROR");
    error_register(COMMAND_ARGUMENT_EXPECTED, "COMMAND_ARGUMENT_EXPECTED");
    error_register(OBJECT_NOT_INITIALIZED, "OBJECT_NOT_INITIALIZED");
    error_register(FORMAT_ALREADY_REGISTERED, "FORMAT_ALREADY_REGISTERED");
    error_register(STOPPED_BY_APPLICATION_SHUTDOWN, "STOPPED_BY_APPLICATION_SHUTDOWN");
    error_register(INVALID_STATE_ERROR, "INVALID_STATE_ERROR");
    error_register(FEATURE_NOT_IMPLEMENTED_ERROR, "FEATURE_NOT_IMPLEMENTED_ERROR");
    error_register(UNEXPECTED_NULL_ARGUMENT_ERROR, "UNEXPECTED_NULL_ARGUMENT_ERROR");
    error_register(INVALID_ARGUMENT_ERROR, "INVALID_ARGUMENT_ERROR");

    error_register(INVALID_PATH, "INVALID_PATH");
    error_register(PID_LOCKED, "PID_LOCKED");

    error_register(UNABLE_TO_COMPLETE_FULL_READ, "UNABLE_TO_COMPLETE_FULL_READ");
    error_register(UNEXPECTED_EOF, "UNEXPECTED_EOF");
    error_register(UNSUPPORTED_TYPE, "UNSUPPORTED_TYPE");
    error_register(UNSUPPORTED_CLASS, "UNSUPPORTED_CLASS");

    error_register(CANNOT_OPEN_FILE, "CANNOT_OPEN_FILE");

    error_register(UNKNOWN_NAME, "UNKNOWN_NAME");
    error_register(BIGGER_THAN_PATH_MAX, "BIGGER_THAN_PATH_MAX");
    error_register(UNABLE_TO_COMPLETE_FULL_WRITE, "UNABLE_TO_COMPLETE_FULL_WRITE");
    error_register(BUFFER_WOULD_OVERFLOW, "BUFFER_WOULD_OVERFLOW");
    error_register(CHROOT_NOT_A_DIRECTORY, "CHROOT_NOT_A_DIRECTORY");
    error_register(CHROOT_ALREADY_JAILED, "CHROOT_ALREADY_JAILED");
    error_register(IP_VERSION_NOT_SUPPORTED, "IP_VERSION_NOT_SUPPORTED");

    error_register(THREAD_CREATION_ERROR, "THREAD_CREATION_ERROR");
    error_register(THREAD_DOUBLEDESTRUCTION_ERROR, "THREAD_DOUBLEDESTRUCTION_ERROR");
    error_register(SERVICE_ID_ERROR, "SERVICE_ID_ERROR");
    error_register(SERVICE_WITHOUT_ENTRY_POINT, "SERVICE_WITHOUT_ENTRY_POINT");
    error_register(SERVICE_ALREADY_INITIALISED, "SERVICE_ALREADY_INITIALISED");
    error_register(SERVICE_ALREADY_RUNNING, "SERVICE_ALREADY_RUNNING");
    error_register(SERVICE_NOT_RUNNING, "SERVICE_NOT_RUNNING");
    error_register(SERVICE_NOT_INITIALISED, "SERVICE_NOT_INITIALISED");
    error_register(SERVICE_HAS_RUNNING_THREADS, "SERVICE_HAS_RUNNING_THREADS");

    error_register(TSIG_DUPLICATE_REGISTRATION, "TSIG_DUPLICATE_REGISTRATION");
    error_register(TSIG_UNABLE_TO_SIGN, "TSIG_UNABLE_TO_SIGN");

    error_register(NET_UNABLE_TO_RESOLVE_HOST, "NET_UNABLE_TO_RESOLVE_HOST");

    error_register(CHARON_ERROR_FILE_LOCKED, "CHARON_ERROR_FILE_LOCKED");
    error_register(CHARON_ERROR_NOT_AUTHORISED, "CHARON_ERROR_NOT_AUTHORISED");
    error_register(CHARON_ERROR_UNKNOWN_ID, "CHARON_ERROR_UNKNOWN_ID");
    error_register(CHARON_ERROR_EXPECTED_MAGIC_HEAD, "CHARON_ERROR_EXPECTED_MAGIC_HEAD");
    error_register(CHARON_ERROR_INVALID_HEAD, "CHARON_ERROR_INVALID_HEAD");
    error_register(CHARON_ERROR_INVALID_TAIL, "CHARON_ERROR_INVALID_TAIL");
    error_register(CHARON_ERROR_INVALID_COMMAND, "CHARON_ERROR_INVALID_COMMAND");
    error_register(CHARON_ERROR_COMMAND_SEQ_MISMATCHED, "CHARON_ERROR_COMMAND_SEQ_MISMATCHED");

    error_register(CHARON_ERROR_UNKNOWN_MAGIC, "CHARON_ERROR_UNKNOWN_MAGIC");
    error_register(CHARON_ERROR_ALREADY_RUNNING, "CHARON_ERROR_ALREADY_RUNNING");
    error_register(CHARON_ERROR_ALREADY_STOPPED, "CHARON_ERROR_ALREADY_STOPPED");

    error_register(LOGGER_CHANNEL_ALREADY_REGISTERED, "LOGGER_CHANNEL_ALREADY_REGISTERED");
    error_register(LOGGER_CHANNEL_NOT_REGISTERED, "LOGGER_CHANNEL_NOT_REGISTERED");
    error_register(LOGGER_CHANNEL_HAS_LINKS, "LOGGER_CHANNEL_HAS_LINKS");
    
    error_register(ALARM_REARM, "ALARM_REARM");

    error_register(DNS_ERROR_BASE, "DNS_ERROR_BASE");
    error_register(DOMAIN_TOO_LONG, "DOMAIN_TOO_LONG");
    error_register(INCORRECT_IPADDRESS, "INCORRECT_IPADDRESS");
    error_register(INCORRECT_RDATA, "INCORRECT_RDATA");
    error_register(LABEL_TOO_LONG, "LABEL_TOO_LONG");
    error_register(INVALID_CHARSET, "INVALID_CHARSET");
    error_register(ZONEFILE_INVALID_TYPE, "ZONEFILE_INVALID_TYPE");
    error_register(DOMAINNAME_INVALID, "DOMAINNAME_INVALID");
    error_register(TSIG_BADKEY, "TSIG_BADKEY");
    error_register(TSIG_BADTIME, "TSIG_BADTIME");
    error_register(TSIG_BADSIG, "TSIG_BADSIG");
    error_register(TSIG_FORMERR, "TSIG_FORMERR");
    error_register(TSIG_SIZE_LIMIT_ERROR, "TSIG_SIZE_LIMIT_ERROR");
    error_register(UNPROCESSABLE_MESSAGE, "UNPROCESSABLE_MESSAGE");
    error_register(INVALID_PROTOCOL, "INVALID_PROTOCOL");
    error_register(INVALID_RECORD, "INVALID_RECORD");
    error_register(UNSUPPORTED_RECORD, "UNSUPPORTED_RECORD");
    error_register(ZONE_ALREADY_UP_TO_DATE, "ZONE_ALREADY_UP_TO_DATE");
    error_register(UNKNOWN_DNS_TYPE, "UNKNOWN_DNS_TYPE");
    error_register(UNKNOWN_DNS_CLASS, "UNKNOWN_DNS_CLASS");
    //error_register(INVALID_MESSAGE, "INVALID_MESSAGE");
    error_register(MESSAGE_HAS_WRONG_ID, "MESSAGE_HAS_WRONG_ID");
    error_register(MESSAGE_IS_NOT_AN_ANSWER, "MESSAGE_IS_NOT_AN_ANSWER");
    error_register(MESSAGE_UNEXPECTED_ANSWER_DOMAIN, "MESSAGE_UNEXPECTED_ANSWER_DOMAIN");
    error_register(MESSAGE_UNEXPECTED_ANSWER_TYPE_CLASS, "MESSAGE_UNEXPECTED_ANSWER_TYPE_CLASS");
    error_register(MESSAGE_CONTENT_OVERFLOW, "MESSAGE_CONTENT_OVERFLOW");
    error_register(MESSAGE_TRUNCATED, "MESSAGE_TRUNCATED");
    
    error_register(RRSIG_COVERED_TYPE_DIFFERS, "RRSIG_COVERED_TYPE_DIFFERS");
    error_register(RRSIG_OUTPUT_DIGEST_SIZE_TOO_BIG, "RRSIG_OUTPUT_DIGEST_SIZE_TOO_BIG");
    error_register(RRSIG_UNSUPPORTED_COVERED_TYPE, "RRSIG_UNSUPPORTED_COVERED_TYPE");
    error_register(RRSIG_VERIFICATION_FAILED, "RRSIG_VERIFICATION_FAILED");

    error_register(DNSSEC_ALGORITHM_UNKOWN, "DNSSEC_ALGORITHM_UNKOWN");
    
    /* DNS */

    error_register(RCODE_ERROR_CODE(RCODE_NOERROR), "NOERROR");
    error_register(RCODE_ERROR_CODE(RCODE_FORMERR), "FORMERR");
    error_register(RCODE_ERROR_CODE(RCODE_SERVFAIL), "SERVFAIL");
    error_register(RCODE_ERROR_CODE(RCODE_NXDOMAIN), "NXDOMAIN");
    error_register(RCODE_ERROR_CODE(RCODE_NOTIMP), "NOTIMP");
    error_register(RCODE_ERROR_CODE(RCODE_REFUSED), "REFUSED");
    error_register(RCODE_ERROR_CODE(RCODE_YXDOMAIN), "YXDOMAIN");
    error_register(RCODE_ERROR_CODE(RCODE_YXRRSET), "YXRRSET");
    error_register(RCODE_ERROR_CODE(RCODE_NXRRSET), "NXRRSET");
    error_register(RCODE_ERROR_CODE(RCODE_NOTAUTH), "NOTAUTH");
    error_register(RCODE_ERROR_CODE(RCODE_NOTZONE), "NOTZONE");

    error_register(RCODE_ERROR_CODE(RCODE_BADVERS), "BADVERS");
    //error_register(RCODE_ERROR_CODE(RCODE_BADSIG), "BADSIG");
    error_register(RCODE_ERROR_CODE(RCODE_BADKEY), "BADKEY");
    error_register(RCODE_ERROR_CODE(RCODE_BADTIME), "BADTIME");
    error_register(RCODE_ERROR_CODE(RCODE_BADMODE), "BADMODE");
    error_register(RCODE_ERROR_CODE(RCODE_BADNAME), "BADNAME");
    error_register(RCODE_ERROR_CODE(RCODE_BADALG), "BADALG");
    error_register(RCODE_ERROR_CODE(RCODE_BADTRUNC), "BADTRUNC");

    error_register(DNSSEC_ERROR_BASE, "DNSSEC_ERROR_BASE");

    error_register(DNSSEC_ERROR_NOENGINE, "DNSSEC_ERROR_NOENGINE");
    error_register(DNSSEC_ERROR_INVALIDENGINE, "DNSSEC_ERROR_INVALIDENGINE");
    error_register(DNSSEC_ERROR_CANTPOOLTHREAD, "DNSSEC_ERROR_CANTPOOLTHREAD");

    error_register(DNSSEC_ERROR_UNSUPPORTEDKEYALGORITHM, "DNSSEC_ERROR_UNSUPPORTEDKEYALGORITHM");
    error_register(DNSSEC_ERROR_UNSUPPORTEDDIGESTALGORITHM, "DNSSEC_ERROR_UNSUPPORTEDDIGESTALGORITHM");
    error_register(DNSSEC_ERROR_FILE_FORMAT_VERSION, "DNSSEC_ERROR_FILE_FORMAT_VERSION");
    error_register(DNSSEC_ERROR_EXPECTED_CLASS_IN, "DNSSEC_ERROR_EXPECTED_CLASS_IN");
    error_register(DNSSEC_ERROR_EXPECTED_TYPE_DNSKEY, "DNSSEC_ERROR_EXPECTED_TYPE_DNSKEY");

    error_register(DNSSEC_ERROR_DUPLICATEKEY, "DNSSEC_ERROR_DUPLICATEKEY");
    error_register(DNSSEC_ERROR_INCOMPLETEKEY, "DNSSEC_ERROR_INCOMPLETEKEY");
    error_register(DNSSEC_ERROR_KEYSTOREPATHISTOOLONG, "DNSSEC_ERROR_KEYSTOREPATHISTOOLONG");
    error_register(DNSSEC_ERROR_UNABLETOCREATEKEYFILES, "DNSSEC_ERROR_UNABLETOCREATEKEYFILES");
    error_register(DNSSEC_ERROR_KEYWRITEERROR, "DNSSEC_ERROR_KEYWRITEERROR");
    error_register(DNSSEC_ERROR_BNISNULL, "DNSSEC_ERROR_BNISNULL");
    error_register(DNSSEC_ERROR_BNISBIGGERTHANBUFFER, "DNSSEC_ERROR_BNISBIGGERTHANBUFFER");
    error_register(DNSSEC_ERROR_UNEXPECTEDKEYSIZE, "DNSSEC_ERROR_UNEXPECTEDKEYSIZE");
    error_register(DNSSEC_ERROR_KEYISTOOBIG, "DNSSEC_ERROR_KEYISTOOBIG");
    error_register(DNSSEC_ERROR_KEYRING_ALGOTAG_COLLISION, "DNSSEC_ERROR_KEYRING_ALGOTAG_COLLISION");

    error_register(DNSSEC_ERROR_KEYRING_KEY_IS_NOT_PRIVATE,"DNSSEC_ERROR_KEYRING_KEY_IS_NOT_PRIVATE");

    error_register(DNSSEC_ERROR_KEY_GENERATION_FAILED, "DNSSEC_ERROR_KEY_GENERATION_FAILED");
    error_register(DNSSEC_ERROR_NO_KEY_FOR_DOMAIN, "DNSSEC_ERROR_NO_KEY_FOR_DOMAIN");

    error_register(DNSSEC_ERROR_CANNOT_WRITE_NEW_FILE, "DNSSEC_ERROR_CANNOT_WRITE_NEW_FILE");
    error_register(DNSSEC_ERROR_FIELD_NOT_HANDLED, "DNSSEC_ERROR_FIELD_NOT_HANDLED");
    error_register(DNSSEC_ERROR_CANNOT_READ_KEY_FROM_RDATA, "DNSSEC_ERROR_CANNOT_READ_KEY_FROM_RDATA");

    error_register(DNSSEC_ERROR_RSASIGNATUREFAILED, "DNSSEC_ERROR_RSASIGNATUREFAILED");
    error_register(DNSSEC_ERROR_DSASIGNATUREFAILED, "DNSSEC_ERROR_DSASIGNATUREFAILED");

    error_register(DNSSEC_ERROR_NSEC3_INVALIDZONESTATE, "DNSSEC_ERROR_NSEC3_INVALIDZONESTATE");
    error_register(DNSSEC_ERROR_NSEC3_LABELTODIGESTFAILED, "DNSSEC_ERROR_NSEC3_LABELTODIGESTFAILED");
    error_register(DNSSEC_ERROR_NSEC3_DIGESTORIGINOVERFLOW, "DNSSEC_ERROR_NSEC3_DIGESTORIGINOVERFLOW");
    error_register(DNSSEC_ERROR_NSEC3_LABELNOTFOUND, "DNSSEC_ERROR_NSEC3_LABELNOTFOUND");
    
    error_register(DNSSEC_ERROR_NSEC_INVALIDZONESTATE, "DNSSEC_ERROR_NSEC_INVALIDZONESTATE");

    error_register(DNSSEC_ERROR_RRSIG_NOENGINE, "DNSSEC_ERROR_RRSIG_NOENGINE");
    error_register(DNSSEC_ERROR_RRSIG_NOZONEKEYS, "DNSSEC_ERROR_RRSIG_NOZONEKEYS");
    error_register(DNSSEC_ERROR_RRSIG_NOUSABLEKEYS, "DNSSEC_ERROR_RRSIG_NOUSABLEKEYS");
    error_register(DNSSEC_ERROR_RRSIG_NOSOA, "DNSSEC_ERROR_RRSIG_NOSOA");
    error_register(DNSSEC_ERROR_RRSIG_NOSIGNINGKEY, "DNSSEC_ERROR_RRSIG_NOSIGNINGKEY");
    error_register(DNSSEC_ERROR_RRSIG_UNSUPPORTEDRECORD, "DNSSEC_ERROR_RRSIG_UNSUPPORTEDRECORD");

    error_register(ZALLOC_ERROR_MMAPFAILED, "ZALLOC_ERROR_MMAPFAILED");
    error_register(ZALLOC_ERROR_OUTOFMEMORY, "ZALLOC_ERROR_OUTOFMEMORY");

    zone_reader_text_init_error_codes();
    
    parser_init_error_codes();
    config_init_error_codes();
    cmdline_init_error_codes();
}

ya_result ya_ssl_error()
{
    unsigned long ssl_err = ERR_get_error();

    if(ssl_err != 0)
    {
        LOGGER_EARLY_CULL_PREFIX(MSG_ERR)
        {
            char buffer[256];
            ERR_error_string_n(ssl_err, buffer, sizeof(buffer));
            log_err("ssl: %i, %s", ssl_err, buffer);

            unsigned long next_ssl_err;
            while((next_ssl_err = ERR_get_error()) != 0)
            {
                ERR_error_string_n(next_ssl_err, buffer, sizeof(buffer));
                log_err("ssl: %i, %s", next_ssl_err, buffer);
            }

            ERR_clear_error();
        }
    }

    return SSL_ERROR_CODE(ssl_err);
}

/** @} */
