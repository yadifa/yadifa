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

#include <strings.h>

#include <dnscore/ptr_treemap.h>
#include <dnscore/base16.h>
#include <dnscore/logger.h>
#include <dnscore/parsing.h>

#include "dnssec_policy.h"
#include "zone_desc.h"

#include "zone_signature_policy.h"
#include "server_error.h"

/*----------------------------------------------------------------------------*/
#pragma mark GLOBAL VARIABLES

#define MODULE_MSG_HANDLE g_server_logger

#define DENIALCF_TAG      0x46434c41494e4544

#if ZDB_HAS_PRIMARY_SUPPORT

static value_name_table_t dnssec_enum[] = {{ZONE_DNSSEC_FL_NSEC3, "nsec3"}, {0, NULL}};

static ptr_treemap_t      denial_desc_set = PTR_TREEMAP_ASCIIZ_EMPTY;

/*----------------------------------------------------------------------------*/
#pragma mark CONFIG

// denial container
#define CONFIG_TYPE denial_desc_t
CONFIG_BEGIN(config_section_denial_desc)
CONFIG_STRING(id, NULL)
CONFIG_ENUM(type, "nsec3", dnssec_enum)
CONFIG_U32(resalting, "0") /// @todo 20160520 gve -- does not work in version 2.2.0
CONFIG_STRING(salt, NULL)
CONFIG_STRING(algorithm, "sha1")
CONFIG_U16(iterations, "1")
CONFIG_U8(salt_length, "0")
CONFIG_BOOL(optout, "0")
CONFIG_END(config_section_denial_desc)
#undef CONFIG_TYPE

/*----------------------------------------------------------------------------*/
#pragma mark STATIC FUNCTIONS

static ya_result config_section_denial_set_wild(struct config_section_descriptor_s *csd, const char *key, const char *value)
{
    (void)csd;
    (void)key;
    (void)value;

    return CONFIG_UNKNOWN_SETTING;
}

static ya_result config_section_denial_print_wild(const struct config_section_descriptor_s *csd, output_stream_t *os, const char *key, void **context)
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
 * @fn static ya_result config_section_denial_init(struct config_section_descriptor_s *csd)
 *
 * @brief initializing of a section: <denial>
 *
 * @details
 * the initializing of <denial> section is a NOP.
 *
 * @param[in] struct config_section_description_s *csd
 *
 * @retval    ERROR or SUCCESS
 *
 * return ya_result
 */
static ya_result config_section_denial_init(struct config_section_descriptor_s *csd)
{
    // NOP

    if(csd->base != NULL)
    {
        return INVALID_STATE_ERROR; // base SHOULD be NULL at init
    }

    return SUCCESS;
}

/**
 * @fn static ya_result config_section_denial_start(struct config_section_descriptor_s *csd)
 *
 * @brief
 * start of a <denial> section csd->base will be initialized
 *
 * @details
 * csd->base will be initialized with denial
 * you can not have a start of a 'section' in a 'section' --> ERROR
 *
 * @param[in] struct config_section_description_s *csd
 *
 * @retval    ERROR or SUCCESS
 *
 * return ya_result
 */
static ya_result config_section_denial_start(struct config_section_descriptor_s *csd)
{
#if CONFIG_SETTINGS_DEBUG
    formatln("config: section: denial: start");
#endif

    if(csd->base != NULL)
    {
        return INVALID_STATE_ERROR;
    }

    denial_desc_t *denial;
    MALLOC_OBJECT_OR_DIE(denial, denial_desc_t, DENIALCF_TAG);
    ZEROMEMORY(denial, sizeof(denial_desc_t));
    csd->base = denial;

    config_error_t cfgerr;
    config_error_init(&cfgerr);
    config_set_section_default(csd, &cfgerr);
    config_error_finalise(&cfgerr);

    return SUCCESS;
}

/**
 * @fn static ya_result config_section_denial_stop(struct config_section_descriptor_s *csd)
 *
 * @brief
 * stop of a <denial> section csd->base set to NULL --> ready for the
 * next <denial> section
 * put the 'denial' in a binary tree with index denial->id
 *
 * @details
 * make sure that 'salt_length' is correct
 * 'denial' is put in a binary tree for easy access when they need to be translated in the correct structure for
 * 'yadifad'
 *
 * @param[in] struct config_section_description_s *csd
 *
 * @retval    ERROR or SUCCESS
 *
 * return ya_result
 */
static ya_result config_section_denial_stop(struct config_section_descriptor_s *csd)
{
#if CONFIG_SETTINGS_DEBUG
    formatln("config: section: denial: stop");
#endif

    // NOP
    denial_desc_t *denial = (denial_desc_t *)csd->base;
    csd->base = NULL;

    if(denial->id == NULL)
    {
        ttylog_err("config: denial: id not set");
        return CONFIG_SECTION_ERROR;
    }

    if(strcasecmp(denial->algorithm, "sha1") == 0)
    {
        denial->algorithm_val = 1;
    }
    else
    {
        uint32_t parsed_algorithm = 0;
        if(ISOK(parse_u32_check_range(denial->algorithm, &parsed_algorithm, 1, 255, 10)))
        {
            denial->algorithm_val = (uint8_t)parsed_algorithm;
        }
        else
        {
            return CONFIG_SECTION_ERROR;
        }
    }

    // Now allows empty salt.
    /*
        size_t salt_length = (denial->salt != NULL) ? strlen(denial->salt) : 0;

        if((denial->salt_length > 0) == (salt_length > 0))
        {
           return CONFIG_SECTION_ERROR;
        }
    */

    ptr_treemap_node_t *node = ptr_treemap_insert(&denial_desc_set, denial->id);

    if(node->value == NULL)
    {
        node->value = denial;

        return SUCCESS;
    }
    else
    {
        ttylog_err("config: denial: %s: already defined", denial->id);

        return CONFIG_SECTION_ERROR;
    }
}

/**
 * @fn static ya_result config_section_denial_postprocess(struct config_section_descriptor_s *csd)
 *
 * @brief create denial structure to be used by 'yadifad'
 *
 *
 * @param[in] struct config_section_description_s *csd
 *
 * @retval    ERROR or SUCCESS
 *
 * return ya_result
 */
static ya_result config_section_denial_postprocess(struct config_section_descriptor_s *csd, config_error_t *cfgerr)
{
    (void)csd;

    ya_result              salt_length;

    ptr_treemap_iterator_t iter;
    ptr_treemap_iterator_init(&denial_desc_set, &iter);

    uint8_t buffer[256];

    // go thru binary tree and check all the 'denial' sections
    while(ptr_treemap_iterator_hasnext(&iter))
    {
        ptr_treemap_node_t *denial_node = ptr_treemap_iterator_next_node(&iter);
        denial_desc_t      *denial_desc = (denial_desc_t *)denial_node->value;

        // check if there's a salt present
        if(denial_desc->salt != NULL)
        {
            if(FAIL(salt_length = base16_decode(denial_desc->salt, (uint32_t)strlen(denial_desc->salt), buffer)))
            {
                ttylog_err("config: denial: %s: could not decode salt", denial_desc->id);
#if CONFIG_SECTION_DESCRIPTOR_TRACK
                config_section_descriptor_config_error_update(cfgerr, csd, &denial_desc->salt);
#endif
                return salt_length; // is ERROR code instead
            }

            // buffer has the base16 decode 'salt'
            dnssec_policy_denial_create(denial_desc->id, denial_desc->algorithm_val, denial_desc->iterations, buffer, (uint8_t)salt_length, denial_desc->resalting, denial_desc->optout);
        }
        else
        {
            // if no salt present 'salt_length' has the correct length of the salt to be made by the system
            dnssec_policy_denial_create(denial_desc->id, denial_desc->algorithm_val, denial_desc->iterations, NULL, denial_desc->salt_length, denial_desc->resalting, denial_desc->optout);
        }
    }

    return SUCCESS;
}

/**
 * @fn static void denial_free(denial_desc_s *denial)
 *
 * @brief free all <denial> items: id, salt
 *
 * @details
 * just free all items of <denial> section
 *
 *
 * @param[in,out] denial_desc_s *denial
 *
 * return --
 */
static void denial_free(denial_desc_t *denial)
{
    free(denial->id);
    free(denial->salt);

    free(denial);
}

/**
 * @fn static ya_result config_section_denial_finalize(struct config_section_descriptor_s *csd)
 *
 * @brief free denial_desc_s completely
 *
 * @details
 * empty 'dnssec_policy' denial parameter and everything else
 * and free csd and set back to 'NULL'
 *
 * @param[in] struct config_section_description_s *csd
 *
 * @retval    ERROR or SUCCESS
 *
 * return ya_result
 */
static ya_result config_section_denial_finalize(struct config_section_descriptor_s *csd)
{
    if(csd != NULL)
    {
        if(csd->base != NULL)
        {
            denial_desc_t *denial = (denial_desc_t *)csd->base;
            denial_free(denial);
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

static const config_section_descriptor_vtbl_s config_section_denial_descriptor_vtbl = {"denial",
                                                                                       config_section_denial_desc, // no table
                                                                                       config_section_denial_set_wild,
                                                                                       config_section_denial_print_wild,
                                                                                       config_section_denial_init,
                                                                                       config_section_denial_start,
                                                                                       config_section_denial_stop,
                                                                                       config_section_denial_postprocess,
                                                                                       config_section_denial_finalize};

/*----------------------------------------------------------------------------*/
#pragma mark FUNCTIONS

/**
 * @fn ya_result config_register_denial(const char *null_or_key_name, int32_t priority)
 *
 * @brief register all sections needed for <denial> sections
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
ya_result config_register_denial(const char *null_or_key_name, int32_t priority)
{
    // null_or_key_name = "zone";
    (void)null_or_key_name;

    config_section_descriptor_t *desc = config_section_descriptor_new_instance(&config_section_denial_descriptor_vtbl);

    ya_result                    return_code = config_register(desc, priority);

    if(FAIL(return_code))
    {
        free(desc);
    }

    return return_code; // scan-build false positive: either it is freed, either it is stored in a global collection
}

#endif // ZDB_HAS_PRIMARY_SUPPORT
