/*------------------------------------------------------------------------------
 *
 * Copyright (c) 2011-2025, EURid vzw. All rights reserved.
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
 * @defgroup yadifad
 * @ingroup ###
 * @brief
 *----------------------------------------------------------------------------*/

#include <dnscore/config_settings.h>
#include <dnscore/ptr_treemap.h>
#include <dnscore/dnssec_errors.h>

#include "dnssec_policy.h"
#include "server_error.h"

/*----------------------------------------------------------------------------*/
#pragma mark GLOBAL VARIABLES

#if ZDB_HAS_PRIMARY_SUPPORT

#define KEYTEMCF_TAG 0x46434d455459454b

static ptr_treemap_t      key_template_desc_set = PTR_TREEMAP_ASCIIZ_EMPTY;

static value_name_table_t dnssec_algorithm_enum[] = {{DNSKEY_ALGORITHM_RSAMD5, DNSKEY_ALGORITHM_RSAMD5_NAME},
                                                     {DNSKEY_ALGORITHM_RSAMD5, "1"},
                                                     {DNSKEY_ALGORITHM_DIFFIE_HELLMAN, DNSKEY_ALGORITHM_DIFFIE_HELLMAN_NAME},
                                                     {DNSKEY_ALGORITHM_DIFFIE_HELLMAN, "2"},
                                                     {DNSKEY_ALGORITHM_DSASHA1, DNSKEY_ALGORITHM_DSASHA1_NAME},
                                                     {DNSKEY_ALGORITHM_DSASHA1, "3"},
                                                     {DNSKEY_ALGORITHM_RSASHA1, DNSKEY_ALGORITHM_RSASHA1_NAME},
                                                     {DNSKEY_ALGORITHM_RSASHA1, "5"},
                                                     {DNSKEY_ALGORITHM_DSASHA1_NSEC3, DNSKEY_ALGORITHM_DSASHA1_NSEC3_NAME},
                                                     {DNSKEY_ALGORITHM_DSASHA1_NSEC3, DNSKEY_ALGORITHM_DSASHA1_NSEC3_NAME2},
                                                     {DNSKEY_ALGORITHM_DSASHA1_NSEC3, "6"},
                                                     {DNSKEY_ALGORITHM_RSASHA1_NSEC3, DNSKEY_ALGORITHM_RSASHA1_NSEC3_NAME},
                                                     {DNSKEY_ALGORITHM_RSASHA1_NSEC3, DNSKEY_ALGORITHM_RSASHA1_NSEC3_NAME2},
                                                     {DNSKEY_ALGORITHM_RSASHA1_NSEC3, "7"},
                                                     {DNSKEY_ALGORITHM_RSASHA256_NSEC3, DNSKEY_ALGORITHM_RSASHA256_NSEC3_NAME},
                                                     {DNSKEY_ALGORITHM_RSASHA256_NSEC3, "8"},
                                                     {DNSKEY_ALGORITHM_RSASHA512_NSEC3, DNSKEY_ALGORITHM_RSASHA512_NSEC3_NAME},
                                                     {DNSKEY_ALGORITHM_RSASHA512_NSEC3, "10"},
                                                     {DNSKEY_ALGORITHM_GOST, DNSKEY_ALGORITHM_GOST_NAME},
                                                     {DNSKEY_ALGORITHM_GOST, "12"},
                                                     {DNSKEY_ALGORITHM_ECDSAP256SHA256, DNSKEY_ALGORITHM_ECDSAP256SHA256_NAME},
                                                     {DNSKEY_ALGORITHM_ECDSAP256SHA256, "13"},
                                                     {DNSKEY_ALGORITHM_ECDSAP384SHA384, DNSKEY_ALGORITHM_ECDSAP384SHA384_NAME},
                                                     {DNSKEY_ALGORITHM_ECDSAP384SHA384, "14"},
                                                     {DNSKEY_ALGORITHM_ED25519, DNSKEY_ALGORITHM_ED25519_NAME},
                                                     {DNSKEY_ALGORITHM_ED25519, "15"},
                                                     {DNSKEY_ALGORITHM_ED448, DNSKEY_ALGORITHM_ED448_NAME},
                                                     {DNSKEY_ALGORITHM_ED448, "16"},
#if DNSCORE_HAS_OQS_SUPPORT
                                                     {DNSKEY_ALGORITHM_DILITHIUM2, DNSKEY_ALGORITHM_DILITHIUM2_NAME},
                                                     {DNSKEY_ALGORITHM_DILITHIUM2, "24"},
                                                     {DNSKEY_ALGORITHM_DILITHIUM3, DNSKEY_ALGORITHM_DILITHIUM3_NAME},
                                                     {DNSKEY_ALGORITHM_DILITHIUM3, "25"},
                                                     {DNSKEY_ALGORITHM_DILITHIUM5, DNSKEY_ALGORITHM_DILITHIUM5_NAME},
                                                     {DNSKEY_ALGORITHM_DILITHIUM5, "26"},
                                                     {DNSKEY_ALGORITHM_FALCON512, DNSKEY_ALGORITHM_FALCON512_NAME},
                                                     {DNSKEY_ALGORITHM_FALCON512, "27"},
                                                     {DNSKEY_ALGORITHM_FALCON1024, DNSKEY_ALGORITHM_FALCON1024_NAME},
                                                     {DNSKEY_ALGORITHM_FALCON1024, "28"},
                                                     {DNSKEY_ALGORITHM_FALCONPAD512, DNSKEY_ALGORITHM_FALCONPAD512_NAME},
                                                     {DNSKEY_ALGORITHM_FALCONPAD512, "29"},
                                                     {DNSKEY_ALGORITHM_FALCONPAD1024, DNSKEY_ALGORITHM_FALCONPAD1024_NAME},
                                                     {DNSKEY_ALGORITHM_FALCONPAD1024, "30"},
                                                     {DNSKEY_ALGORITHM_SPHINCSSHA2128F, DNSKEY_ALGORITHM_SPHINCSSHA2128F_NAME},
                                                     {DNSKEY_ALGORITHM_SPHINCSSHA2128F, "31"},
                                                     {DNSKEY_ALGORITHM_SPHINCSSHA2128S, DNSKEY_ALGORITHM_SPHINCSSHA2128S_NAME},
                                                     {DNSKEY_ALGORITHM_SPHINCSSHA2128S, "32"},
                                                     {DNSKEY_ALGORITHM_SPHINCSSHA2192F, DNSKEY_ALGORITHM_SPHINCSSHA2192F_NAME},
                                                     {DNSKEY_ALGORITHM_SPHINCSSHA2192F, "33"},
                                                     {DNSKEY_ALGORITHM_SPHINCSSHA2192S, DNSKEY_ALGORITHM_SPHINCSSHA2192S_NAME},
                                                     {DNSKEY_ALGORITHM_SPHINCSSHA2192S, "34"},
                                                     {DNSKEY_ALGORITHM_SPHINCSSHA2256F, DNSKEY_ALGORITHM_SPHINCSSHA2256F_NAME},
                                                     {DNSKEY_ALGORITHM_SPHINCSSHA2256F, "35"},
                                                     {DNSKEY_ALGORITHM_SPHINCSSHA2256S, DNSKEY_ALGORITHM_SPHINCSSHA2256S_NAME},
                                                     {DNSKEY_ALGORITHM_SPHINCSSHA2256S, "36"},
                                                     {DNSKEY_ALGORITHM_SPHINCSSHAKE128F, DNSKEY_ALGORITHM_SPHINCSSHAKE128F_NAME},
                                                     {DNSKEY_ALGORITHM_SPHINCSSHAKE128F, "37"},
                                                     {DNSKEY_ALGORITHM_SPHINCSSHAKE128S, DNSKEY_ALGORITHM_SPHINCSSHAKE128S_NAME},
                                                     {DNSKEY_ALGORITHM_SPHINCSSHAKE128S, "38"},
                                                     {DNSKEY_ALGORITHM_SPHINCSSHAKE192F, DNSKEY_ALGORITHM_SPHINCSSHAKE192F_NAME},
                                                     {DNSKEY_ALGORITHM_SPHINCSSHAKE192F, "39"},
                                                     {DNSKEY_ALGORITHM_SPHINCSSHAKE192S, DNSKEY_ALGORITHM_SPHINCSSHAKE192S_NAME},
                                                     {DNSKEY_ALGORITHM_SPHINCSSHAKE192S, "40"},
                                                     {DNSKEY_ALGORITHM_SPHINCSSHAKE256F, DNSKEY_ALGORITHM_SPHINCSSHAKE256F_NAME},
                                                     {DNSKEY_ALGORITHM_SPHINCSSHAKE256F, "41"},
                                                     {DNSKEY_ALGORITHM_SPHINCSSHAKE256S, DNSKEY_ALGORITHM_SPHINCSSHAKE256S_NAME},
                                                     {DNSKEY_ALGORITHM_SPHINCSSHAKE256S, "42"},
                                                     {DNSKEY_ALGORITHM_MAYO1, DNSKEY_ALGORITHM_MAYO1_NAME},
                                                     {DNSKEY_ALGORITHM_MAYO1, "43"},
                                                     {DNSKEY_ALGORITHM_MAYO2, DNSKEY_ALGORITHM_MAYO2_NAME},
                                                     {DNSKEY_ALGORITHM_MAYO2, "44"},
                                                     {DNSKEY_ALGORITHM_MAYO3, DNSKEY_ALGORITHM_MAYO3_NAME},
                                                     {DNSKEY_ALGORITHM_MAYO3, "45"},
                                                     {DNSKEY_ALGORITHM_MAYO5, DNSKEY_ALGORITHM_MAYO5_NAME},
                                                     {DNSKEY_ALGORITHM_MAYO5, "46"},
                                                     {DNSKEY_ALGORITHM_CROSS_RSDP128BALANCED, DNSKEY_ALGORITHM_CROSS_RSDP128BALANCED_NAME},
                                                     {DNSKEY_ALGORITHM_CROSS_RSDP128BALANCED, "47"},
                                                     {DNSKEY_ALGORITHM_CROSS_RSDP128FAST, DNSKEY_ALGORITHM_CROSS_RSDP128FAST_NAME},
                                                     {DNSKEY_ALGORITHM_CROSS_RSDP128FAST, "48"},
                                                     {DNSKEY_ALGORITHM_CROSS_RSDP128SMALL, DNSKEY_ALGORITHM_CROSS_RSDP128SMALL_NAME},
                                                     {DNSKEY_ALGORITHM_CROSS_RSDP128SMALL, "49"},
                                                     {DNSKEY_ALGORITHM_CROSS_RSDP192BALANCED, DNSKEY_ALGORITHM_CROSS_RSDP192BALANCED_NAME},
                                                     {DNSKEY_ALGORITHM_CROSS_RSDP192BALANCED, "50"},
                                                     {DNSKEY_ALGORITHM_CROSS_RSDP192FAST, DNSKEY_ALGORITHM_CROSS_RSDP192FAST_NAME},
                                                     {DNSKEY_ALGORITHM_CROSS_RSDP192FAST, "51"},
                                                     {DNSKEY_ALGORITHM_CROSS_RSDP192SMALL, DNSKEY_ALGORITHM_CROSS_RSDP192SMALL_NAME},
                                                     {DNSKEY_ALGORITHM_CROSS_RSDP192SMALL, "52"},
                                                     {DNSKEY_ALGORITHM_CROSS_RSDP256BALANCED, DNSKEY_ALGORITHM_CROSS_RSDP256BALANCED_NAME},
                                                     {DNSKEY_ALGORITHM_CROSS_RSDP256BALANCED, "53"},
                                                     //{DNSKEY_ALGORITHM_CROSS_RSDP256FAST, DNSKEY_ALGORITHM_CROSS_RSDP256FAST_NAME},
                                                     //{DNSKEY_ALGORITHM_CROSS_RSDP256FAST, "54"},
                                                     {DNSKEY_ALGORITHM_CROSS_RSDP256SMALL, DNSKEY_ALGORITHM_CROSS_RSDP256SMALL_NAME},
                                                     {DNSKEY_ALGORITHM_CROSS_RSDP256SMALL, "55"},
                                                     {DNSKEY_ALGORITHM_CROSS_RSDPG128BALANCED, DNSKEY_ALGORITHM_CROSS_RSDPG128BALANCED_NAME},
                                                     {DNSKEY_ALGORITHM_CROSS_RSDPG128BALANCED, "56"},
                                                     {DNSKEY_ALGORITHM_CROSS_RSDPG128FAST, DNSKEY_ALGORITHM_CROSS_RSDPG128FAST_NAME},
                                                     {DNSKEY_ALGORITHM_CROSS_RSDPG128FAST, "57"},
                                                     {DNSKEY_ALGORITHM_CROSS_RSDPG128SMALL, DNSKEY_ALGORITHM_CROSS_RSDPG128SMALL_NAME},
                                                     {DNSKEY_ALGORITHM_CROSS_RSDPG128SMALL, "58"},
                                                     {DNSKEY_ALGORITHM_CROSS_RSDPG192BALANCED, DNSKEY_ALGORITHM_CROSS_RSDPG192BALANCED_NAME},
                                                     {DNSKEY_ALGORITHM_CROSS_RSDPG192BALANCED, "59"},
                                                     {DNSKEY_ALGORITHM_CROSS_RSDPG192FAST, DNSKEY_ALGORITHM_CROSS_RSDPG192FAST_NAME},
                                                     {DNSKEY_ALGORITHM_CROSS_RSDPG192FAST, "60"},
                                                     {DNSKEY_ALGORITHM_CROSS_RSDPG192SMALL, DNSKEY_ALGORITHM_CROSS_RSDPG192SMALL_NAME},
                                                     {DNSKEY_ALGORITHM_CROSS_RSDPG192SMALL, "61"},
                                                     {DNSKEY_ALGORITHM_CROSS_RSDPG256BALANCED, DNSKEY_ALGORITHM_CROSS_RSDPG256BALANCED_NAME},
                                                     {DNSKEY_ALGORITHM_CROSS_RSDPG256BALANCED, "62"},
                                                     {DNSKEY_ALGORITHM_CROSS_RSDPG256FAST, DNSKEY_ALGORITHM_CROSS_RSDPG256FAST_NAME},
                                                     {DNSKEY_ALGORITHM_CROSS_RSDPG256FAST, "63"},
                                                     {DNSKEY_ALGORITHM_CROSS_RSDPG256SMALL, DNSKEY_ALGORITHM_CROSS_RSDPG256SMALL_NAME},
                                                     {DNSKEY_ALGORITHM_CROSS_RSDPG256SMALL, "64"},
#endif
#ifdef DNSKEY_ALGORITHM_DUMMY
                                                     {DNSKEY_ALGORITHM_DUMMY, DNSKEY_ALGORITHM_DUMMY_NAME},
                                                     {DNSKEY_ALGORITHM_DUMMY, "122"},
#endif
                                                     {DNSKEY_ALGORITHM_PRIVATEOID, DNSKEY_ALGORITHM_PRIVATEOID_NAME},
                                                     {DNSKEY_ALGORITHM_PRIVATEOID, "254"},
                                                     {0, NULL}};

#pragma mark CONFIG

// key-template container
#define CONFIG_TYPE key_template_desc_t
CONFIG_BEGIN(config_section_key_template_desc)

CONFIG_STRING(id, NULL)
CONFIG_BOOL(ksk, "0")
CONFIG_ENUM(algorithm, DNSKEY_ALGORITHM_RSASHA256_NSEC3_NAME, dnssec_algorithm_enum)
CONFIG_U16(size, "0")
CONFIG_STRING(engine, NULL)

CONFIG_END(config_section_key_template_desc)
#undef CONFIG_TYPE

#pragma mark STATIC FUNCTIONS

static ya_result config_section_key_template_set_wild(struct config_section_descriptor_s *csd, const char *key, const char *value)
{
    (void)csd;
    (void)key;
    (void)value;
    return CONFIG_UNKNOWN_SETTING;
}

static ya_result config_section_key_template_print_wild(const struct config_section_descriptor_s *csd, output_stream_t *os, const char *key, void **context)
{
    (void)csd;
    (void)os;
    (void)context;

    if(key != NULL)
    {
        return INVALID_ARGUMENT_ERROR;
    }

    return SUCCESS;
}

/**
 * @fn static ya_result config_section_key_template_init(struct config_section_descriptor_s *csd)
 *
 * @brief initializing of a section: <key-template>
 *
 * @details
 * the initializing of <key-template> section is a NOP.
 *
 * @param[in] struct config_section_description_s *csd
 *
 * @retval    ERROR or SUCCESS
 *
 * return ya_result
 */
static ya_result config_section_key_template_init(struct config_section_descriptor_s *csd)
{
    // NOP

    if(csd->base != NULL)
    {
        return INVALID_STATE_ERROR; // base SHOULD be NULL at init
    }

    return SUCCESS;
}

/**
 * @fn static ya_result config_section_key_template_start(struct config_section_descriptor_s *csd)
 *
 * @brief
 * start of a <key-temmplate> section csd->base will be initialized
 *
 * @details
 * csd->base will be initialized with key_template
 * you can not have a start of a 'section' in a 'section' --> ERROR
 *
 * @param[in] struct config_section_description_s *csd
 *
 * @retval    ERROR or SUCCESS
 *
 * return ya_result
 */
static ya_result config_section_key_template_start(struct config_section_descriptor_s *csd)
{
#if CONFIG_SETTINGS_DEBUG
    formatln("config: section: key_template: start");
#endif

    if(csd->base != NULL)
    {
        return INVALID_STATE_ERROR;
    }

    key_template_desc_t *key_template;
    MALLOC_OBJECT_OR_DIE(key_template, key_template_desc_t, KEYTEMCF_TAG);
    ZEROMEMORY(key_template, sizeof(key_template_desc_t));

    csd->base = key_template;

    return SUCCESS;
}

/**
 * @fn static ya_result config_section_key_template_stop(struct config_section_descriptor_s *csd)
 *
 * @brief
 * stop of a <key-template> section csd->base set to NULL
 *
 * put the 'key-template' in a binary tree with index key_template->id
 *
 * @details
 * 'key-template' is put in a binary tree for easy access when they need to be translated in the correct structure for
 * 'yadifad'
 *
 * @param[in] struct config_section_description_s *csd
 *
 * @retval    ERROR or SUCCESS
 *
 * return ya_result
 */
static ya_result config_section_key_template_stop(struct config_section_descriptor_s *csd)
{
#if CONFIG_SETTINGS_DEBUG
    formatln("config: section: key_template: stop");
#endif

    // NOP
    key_template_desc_t *key_template = (key_template_desc_t *)csd->base;
    csd->base = NULL;

    // 2. set 'algorithm'

    if(key_template->id == NULL)
    {
        ttylog_err("config: key-template: id not set");
        return CONFIG_SECTION_ERROR;
    }

    switch(key_template->algorithm)
    {
        case DNSKEY_ALGORITHM_RSAMD5:
        case DNSKEY_ALGORITHM_DIFFIE_HELLMAN:
        case DNSKEY_ALGORITHM_GOST:

            return DNSSEC_ERROR_UNSUPPORTEDKEYALGORITHM;
        case DNSKEY_ALGORITHM_DSASHA1:
        case DNSKEY_ALGORITHM_DSASHA1_NSEC3:

            if(key_template->size == 0)
            {
                key_template->size = 1024;
            }

            if(key_template->size != 1024)
            {
                ttylog_err(
                    "dnssec-policy: key_template: %s: unsupported key size: %i.  Only 256 bits is supported for this "
                    "algorithm.",
                    key_template->id,
                    key_template->size);

                return PARSE_INVALID_ARGUMENT;
            }

            break;
        case DNSKEY_ALGORITHM_RSASHA1:
        case DNSKEY_ALGORITHM_RSASHA1_NSEC3:
        case DNSKEY_ALGORITHM_RSASHA256_NSEC3:
        case DNSKEY_ALGORITHM_RSASHA512_NSEC3:

            if(key_template->ksk == 1)
            {
                if(key_template->size == 0)
                {
                    key_template->size = 2048;
                }
            }
            else
            {
                if(key_template->size == 0)
                {
                    key_template->size = 1024;
                }
            }

            /// @note 20160624 gve -- check if mod 256 == 0

            break;
        case DNSKEY_ALGORITHM_ECDSAP256SHA256:
            if(key_template->size == 0)
            {
                key_template->size = 256;
            }

            if(key_template->size != 256)
            {
                ttylog_err(
                    "dnssec-policy: key_template: %s: unsupported key size: %i.  Only 256 bits is supported for this "
                    "algorithm.",
                    key_template->id,
                    key_template->size);

                return PARSE_INVALID_ARGUMENT;
            }

            break;
        case DNSKEY_ALGORITHM_ECDSAP384SHA384:
            if(key_template->size == 0)
            {
                key_template->size = 384;
            }

            if(key_template->size != 384)
            {
                ttylog_err(
                    "dnssec-policy: key_template: %s: unsupported key size: %i.  Only 384 bits is supported for this "
                    "algorithm.",
                    key_template->id,
                    key_template->size);

                return PARSE_INVALID_ARGUMENT;
            }
            break;

        case DNSKEY_ALGORITHM_ED25519:
            if(key_template->size == 0)
            {
                key_template->size = 256;
            }

            if(key_template->size != 256)
            {
                ttylog_err(
                    "dnssec-policy: key_template: %s: unsupported key size: %i.  Only 256 bits is supported for this "
                    "algorithm.",
                    key_template->id,
                    key_template->size);

                return PARSE_INVALID_ARGUMENT;
            }

            break;
        case DNSKEY_ALGORITHM_ED448:
            if(key_template->size == 0)
            {
                key_template->size = 456;
            }

            if(key_template->size != 456)
            {
                ttylog_err(
                    "dnssec-policy: key_template: %s: unsupported key size: %i.  Only 384 bits is supported for this "
                    "algorithm.",
                    key_template->id,
                    key_template->size);

                return PARSE_INVALID_ARGUMENT;
            }
            break;

        default:

            return DNSSEC_ERROR_UNSUPPORTEDKEYALGORITHM;
    }

    ptr_treemap_node_t *node = ptr_treemap_insert(&key_template_desc_set, key_template->id);

    if(node->value == NULL)
    {
        node->value = key_template;

        return SUCCESS;
    }
    else
    {
        ttylog_err("config: key-template: %s: already defined", key_template->id);

        return CONFIG_SECTION_ERROR;
    }
}

/**
 * @fn static ya_result config_section_key_template_postprocess(struct config_section_descriptor_s *csd)
 *
 * @brief iterate thru binary tree and create the needed 'key-template' structures for 'yadifad'
 *
 * @details
 * no 'engine' implementend
 *
 *
 * @param[in] struct config_section_description_s *csd
 *
 * @retval    ERROR or SUCCESS
 *
 * return ya_result
 */
static ya_result config_section_key_template_postprocess(struct config_section_descriptor_s *csd, config_error_t *cfgerr)
{
    (void)csd;
    (void)cfgerr;
    ptr_treemap_iterator_t iter;
    ptr_treemap_iterator_init(&key_template_desc_set, &iter);

    while(ptr_treemap_iterator_hasnext(&iter))
    {
        ptr_treemap_node_t  *key_template_node = ptr_treemap_iterator_next_node(&iter);
        key_template_desc_t *key_template_desc = (key_template_desc_t *)key_template_node->value;

        /*dnssec_policy_key *dpk =*/dnssec_policy_key_create(key_template_desc->id, key_template_desc->algorithm, key_template_desc->size, key_template_desc->ksk,
                                                             NULL); // no engine in YADIFA 2.2.0
    }

    return SUCCESS;
}

/**
 * @fn static void key_template_free(key_template_desc_s *key_template)
 *
 * @brief free
 *
 * @details
 * just free all items of <key-template> section
 *
 *
 * @param[in] key_template_desc_s *key_template
 *
 * return --
 */
static void key_template_free(key_template_desc_t *key_template)
{
    free(key_template->id);
    free(key_template->engine);

    free(key_template);
}

/**
 * @fn static ya_result config_section_key_template_finalize(struct config_section_descriptor_s *csd)
 *
 * @brief free key_template_desc_s completely
 *
 * @details
 * empty 'dnssec_policy' key_template parameter and everything else
 * and free csd and set back to 'NULL'
 *
 * @param[in] struct config_section_description_s *csd
 *
 * @retval    ERROR or SUCCESS
 *
 * return ya_result
 */
static ya_result config_section_key_template_finalize(struct config_section_descriptor_s *csd)
{
    if(csd != NULL)
    {
        if(csd->base != NULL)
        {
            key_template_desc_t *key_template = (key_template_desc_t *)csd->base;
            key_template_free(key_template);
#if DEBUG
            csd->base = NULL;
#endif
        }

        config_section_descriptor_delete(csd);
    }

    return SUCCESS;
}

/*----------------------------------------------------------------------------*/
#pragma mark VIRTUAL TABLE

static const config_section_descriptor_vtbl_s config_section_key_template_descriptor_vtbl = {"key-template",
                                                                                             config_section_key_template_desc, // no table
                                                                                             config_section_key_template_set_wild,
                                                                                             config_section_key_template_print_wild,
                                                                                             config_section_key_template_init,
                                                                                             config_section_key_template_start,
                                                                                             config_section_key_template_stop,
                                                                                             config_section_key_template_postprocess,
                                                                                             config_section_key_template_finalize};

/*----------------------------------------------------------------------------*/
#pragma mark FUNCTIONS

/**
 * @fn ya_result config_register_key_template(const char *null_or_key_name, int32_t priority)
 *
 * @brief register all sections needed for <key-template> sections
 *
 * @details
 *
 * @param[in] const char *null_or_key_name
 * @param[in] int32_t priority
 *
 * @retval    return_code -- from other functions
 *
 * return ya_result
 */
ya_result config_register_key_template(const char *null_or_key_name, int32_t priority)
{
    // null_or_key_name = "zone";
    (void)null_or_key_name;

    config_section_descriptor_t *desc = config_section_descriptor_new_instance(&config_section_key_template_descriptor_vtbl);

    ya_result                    return_code = config_register(desc, priority);

    if(FAIL(return_code))
    {
        free(desc);
    }

    return return_code; // scan-build false positive: either it is freed, either it is stored in a global collection
}

#endif // ZDB_HAS_PRIMARY_SUPPORT
