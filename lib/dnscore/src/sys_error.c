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
/** @defgroup dnscoreerror Error
 *  @ingroup dnscore
 *  @brief
 *
 *
 *
 * @{
 *
 *----------------------------------------------------------------------------*/

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

#define ERRORTBL_TAG 0x4c4254524f525245

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
    exit(EXIT_FAILURE);
}

/*
#define ERROR_TABLE_SIZE_INCREMENT 32
static value_name_table* error_table = NULL;
static u32 error_table_count = 0;
static u32 error_table_size = 0;
*/

static u32_node *error_set = NULL;

void
error_unregister_all()
{
    u32_set_avl_iterator iter;
    
    u32_set_avl_iterator_init(&error_set, &iter);
    while(u32_set_avl_iterator_hasnext(&iter))
    {
        u32_node *error_node = u32_set_avl_iterator_next_node(&iter);
        free(error_node->value);
        error_node->value = NULL;
    }
    
    u32_set_avl_destroy(&error_set);
}

void
error_register(ya_result code, const char* text)
{
    if(text == NULL)
    {
        text = "NULL";
    }

    if((code & 0xffff0000) == ERRNO_ERROR_BASE)
    {
        fprintf(stderr, "error_register(%08x,%s) : the errno space is reserved (0x8000xxxx)", code, text);
        fflush(stderr);
        exit(EXIT_FAILURE);
    }
    
    u32_node *error_node = u32_set_avl_insert(&error_set, code);
    
    if(error_node->value == 0)
    {
        error_node->value = strdup(text);
    }
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
        snprintf(error_gettext_tmp, sizeof (error_gettext_tmp), "success (%08x)", code);
        return error_gettext_tmp;
    }

    if((code & 0xffff0000) == ERRNO_ERROR_BASE)
    {
        return strerror(code & 0xffff);
    }

    /**/
    
    u32_node *error_node;
    
    error_node = u32_set_avl_find(&error_set, code);
    if(error_node != NULL)
    {
        return (const char*)error_node->value;
    }
    
    u32 error_base = code & 0xffff0000;

    error_node = u32_set_avl_find(&error_set, error_base);
    if(error_node != NULL)
    {
        return (const char*)error_node->value;
    }

    snprintf(error_gettext_tmp, sizeof (error_gettext_tmp), "undefined error code %08x", code);

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

    if((code & 0xffff0000) == ERRNO_ERROR_BASE)
    {
        osprint(os, strerror(code & 0xffff));
        return;
    }

    /**/
    
    u32_node *error_node;
    
    error_node = u32_set_avl_find(&error_set, code);
    if(error_node != NULL)
    {
        osprint(os, (const char*)error_node->value);
        return;
    }
    
    u32 error_base = code & 0xffff0000;

    error_node = u32_set_avl_find(&error_set, error_base);
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
    error_register(SERVER_ERROR_BASE, "SERVER_ERROR_BASE");
    error_register(PARSEB16_ERROR, "PARSEB16_ERROR");
    error_register(PARSEB32_ERROR, "PARSEB32_ERROR");
    error_register(PARSEB32H_ERROR, "PARSEB32H_ERROR");
    error_register(PARSEB64_ERROR, "PARSEB64_ERROR");
    error_register(PARSEINT_ERROR, "PARSEINT_ERROR");
    error_register(PARSEDATE_ERROR, "PARSEDATE_ERROR");
    error_register(PARSEIP_ERROR, "PARSEIP_ERROR");
    
    error_register(TCP_RATE_TOO_SLOW, "TCP_RATE_TOO_SLOW");

    error_register(PARSEWORD_NOMATCH_ERROR, "PARSEWORD_NOMATCH_ERROR");
    error_register(PARSESTRING_ERROR, "PARSESTRING_ERROR");
    error_register(PARSE_BUFFER_TOO_SMALL_ERROR, "PARSE_BUFFER_TOO_SMALL_ERROR");
    error_register(PARSE_INVALID_CHARACTER, "PARSE_INVALID_CHARACTER");
    error_register(PARSE_INVALID_ARGUMENT, "PARSE_INVALID_ARGUMENT");
    
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
    error_register(UNKNOWN_NAME, "UNKNOWN_NAME");
    error_register(BIGGER_THAN_MAX_PATH, "BIGGER_THAN_MAX_PATH");
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
    error_register(CHARON_ERROR_INVALID_COMMAND, "CHARON_ERROR_INVALID_COMMAND");
    error_register(CHARON_ERROR_COMMAND_SEQ_MISMATCHED, "CHARON_ERROR_COMMAND_SEQ_MISMATCHED");

    error_register(LOGGER_CHANNEL_ALREADY_REGISTERED, "LOGGER_CHANNEL_ALREADY_REGISTERED");
    error_register(LOGGER_CHANNEL_NOT_REGISTERED, "LOGGER_CHANNEL_NOT_REGISTERED");
    error_register(LOGGER_CHANNEL_HAS_LINKS, "LOGGER_CHANNEL_HAS_LINKS");
    
    error_register(ALARM_REARM, "ALARM_REARM");

    error_register(DNS_ERROR_BASE, "DNS_ERROR_BASE");
    error_register(DOMAIN_TOO_LONG, "DOMAIN_TOO_LONG");
    error_register(INCORRECT_IPADDRESS, "INCORRECT_IPADDRESS");
    error_register(INCORRECT_RDATA, "INCORRECT_RDATA");
    error_register(ZONEFILE_UNSUPPORTED_TYPE, "ZONEFILE_UNSUPPORTED_TYPE");
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
    error_register(INVALID_MESSAGE, "INVALID_MESSAGE");
    error_register(MESSAGE_HAS_WRONG_ID, "MESSAGE_HAS_WRONG_ID");
    error_register(MESSAGE_IS_NOT_AN_ANSWER, "MESSAGE_IS_NOT_AN_ANSWER");
    error_register(MESSAGE_UNEXPECTED_ANSWER_DOMAIN, "MESSAGE_UNEXPECTED_ANSWER_DOMAIN");
    error_register(MESSAGE_UNEXPECTED_ANSWER_TYPE_CLASS, "MESSAGE_UNEXPECTED_ANSWER_TYPE_CLASS");
    error_register(MESSAGE_CONTENT_OVERFLOW, "MESSAGE_CONTENT_OVERFLOW");
    
    error_register(RRSIG_COVERED_TYPE_DIFFERS, "RRSIG_COVERED_TYPE_DIFFERS");
    error_register(RRSIG_OUTPUT_DIGEST_SIZE_TOO_BIG, "RRSIG_OUTPUT_DIGEST_SIZE_TOO_BIG");
    error_register(RRSIG_UNSUPPORTED_COVERED_TYPE, "RRSIG_UNSUPPORTED_COVERED_TYPE");
    error_register(RRSIG_VERIFICATION_FAILED, "RRSIG_VERIFICATION_FAILED");
    
    /* DNS */

    error_register(MAKE_DNSMSG_ERROR(RCODE_NOERROR), "NOERROR");
    error_register(MAKE_DNSMSG_ERROR(RCODE_FORMERR), "FORMERR");
    error_register(MAKE_DNSMSG_ERROR(RCODE_SERVFAIL), "SERVFAIL");
    error_register(MAKE_DNSMSG_ERROR(RCODE_NXDOMAIN), "NXDOMAIN");
    error_register(MAKE_DNSMSG_ERROR(RCODE_NOTIMP), "NOTIMP");
    error_register(MAKE_DNSMSG_ERROR(RCODE_REFUSED), "REFUSED");
    error_register(MAKE_DNSMSG_ERROR(RCODE_YXDOMAIN), "YXDOMAIN");
    error_register(MAKE_DNSMSG_ERROR(RCODE_YXRRSET), "YXRRSET");
    error_register(MAKE_DNSMSG_ERROR(RCODE_NXRRSET), "NXRRSET");
    error_register(MAKE_DNSMSG_ERROR(RCODE_NOTAUTH), "NOTAUTH");
    error_register(MAKE_DNSMSG_ERROR(RCODE_NOTZONE), "NOTZONE");
    
    error_register(DNSSEC_ERROR_BASE, "DNSSEC_ERROR_BASE");

    error_register(DNSSEC_ERROR_NOENGINE, "DNSSEC_ERROR_NOENGINE");
    error_register(DNSSEC_ERROR_INVALIDENGINE, "DNSSEC_ERROR_INVALIDENGINE");
    error_register(DNSSEC_ERROR_CANTPOOLTHREAD, "DNSSEC_ERROR_CANTPOOLTHREAD");

    error_register(DNSSEC_ERROR_UNSUPPORTEDKEYALGORITHM, "DNSSEC_ERROR_UNSUPPORTEDKEYALGORITHM");
    error_register(DNSSEC_ERROR_UNSUPPORTEDDIGESTALGORITHM, "DNSSEC_ERROR_UNSUPPORTEDDIGESTALGORITHM");

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

    error_register(DNSSEC_ERROR_RSASIGNATUREFAILED, "DNSSEC_ERROR_RSASIGNATUREFAILED");
    error_register(DNSSEC_ERROR_DSASIGNATUREFAILED, "DNSSEC_ERROR_DSASIGNATUREFAILED");

    error_register(DNSSEC_ERROR_NSEC3_INVALIDZONESTATE, "DNSSEC_ERROR_NSEC3_INVALIDZONESTATE");
    error_register(DNSSEC_ERROR_NSEC3_LABELTODIGESTFAILED, "DNSSEC_ERROR_NSEC3_LABELTODIGESTFAILED");
    error_register(DNSSEC_ERROR_NSEC3_DIGESTORIGINOVERFLOW, "DNSSEC_ERROR_NSEC3_DIGESTORIGINOVERFLOW");
    
    error_register(DNSSEC_ERROR_NSEC_INVALIDZONESTATE, "DNSSEC_ERROR_NSEC_INVALIDZONESTATE");

    error_register(DNSSEC_ERROR_RRSIG_NOENGINE, "DNSSEC_ERROR_RRSIG_NOENGINE");
    error_register(DNSSEC_ERROR_RRSIG_NOZONEKEYS, "DNSSEC_ERROR_RRSIG_NOZONEKEYS");
    error_register(DNSSEC_ERROR_RRSIG_NOUSABLEKEYS, "DNSSEC_ERROR_RRSIG_NOUSABLEKEYS");
    error_register(DNSSEC_ERROR_RRSIG_NOSOA, "DNSSEC_ERROR_RRSIG_NOSOA");
    error_register(DNSSEC_ERROR_RRSIG_NOSIGNINGKEY, "DNSSEC_ERROR_RRSIG_NOSIGNINGKEY");
    error_register(DNSSEC_ERROR_RRSIG_UNSUPPORTEDRECORD, "DNSSEC_ERROR_RRSIG_UNSUPPORTEDRECORD");

    parser_init_error_codes();
    config_init_error_codes();
    cmdline_init_error_codes();
}

/** @} */

/*----------------------------------------------------------------------------*/

