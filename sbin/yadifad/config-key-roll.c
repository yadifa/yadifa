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

/** @defgroup yadifad
 *  @ingroup ###
 *  @brief
 */

#include <dnscore/config_settings.h>
#include <dnscore/ptr_set.h>

#include "dnssec-policy.h"

#include "config-key-roll-parser.h"
#include "server_error.h"


/*----------------------------------------------------------------------------*/
#pragma mark GLOBAL VARIABLES

#define KEYROLCF_TAG 0x46434c4f5259454b

static ptr_set key_roll_desc_set = PTR_SET_ASCIIZ_EMPTY;

/*----------------------------------------------------------------------------*/
#pragma mark CONFIG


// key-roll container
#define CONFIG_TYPE key_roll_desc_s
CONFIG_BEGIN(config_section_key_roll_desc)

CONFIG_STRING(id,         NULL)
CONFIG_STRING(generate,   NULL)
CONFIG_STRING(publish,    NULL)
CONFIG_STRING(activate,   NULL)
CONFIG_STRING(inactive,   NULL)
CONFIG_STRING(remove,     NULL)

#if HAS_DS_PUBLICATION_SUPPORT
CONFIG_STRING(ds_publish, NULL)
CONFIG_STRING(ds_remove,  NULL)
#endif // if HAS_DS_PUBLICATION_SUPPORT>

CONFIG_ALIAS(delete, remove)
CONFIG_ALIAS(create, generate)
CONFIG_ALIAS(created, generate)

CONFIG_END(config_section_key_roll_desc)
#undef CONFIG_TYPE

#pragma mark STATIC FUNCTIONS

static ya_result
config_section_key_roll_set_wild(struct config_section_descriptor_s *csd, const char *key, const char *value)
{
    (void)csd;
    (void)key;
    (void)value;

    return CONFIG_UNKNOWN_SETTING;
}


static ya_result
config_section_key_roll_print_wild(const struct config_section_descriptor_s *csd, output_stream *os, const char *key)
{
    (void)csd;
    (void)os;

    if(key != NULL)
    {
        return INVALID_ARGUMENT_ERROR;
    }

    return SUCCESS;
}


/**
 * @fn static ya_result config_section_key_roll_init(struct config_section_descriptor_s *csd)
 *
 * @brief initializing of a section: <key-roll>
 *
 * @details
 * the initializing of <key-roll> section is a NOP.
 *
 * @param[in] struct config_section_description_s *csd
 *
 * @retval    ERROR or SUCCESS
 *
 * return ya_result
 */
static ya_result
config_section_key_roll_init(struct config_section_descriptor_s *csd)
{
    // NOP

    if(csd->base != NULL)
    {
        return INVALID_STATE_ERROR; // base SHOULD be NULL at init
    }

    return SUCCESS;
}


/**
 * @fn static ya_result config_section_key_roll_start(struct config_section_descriptor_s *csd)
 *
 * @brief
 * start of a <key-roll> section csd->base will be initialized
 *
 * @details
 * csd->base will be initialized with key_roll
 * you can not have a start of a 'section' in a 'section' --> ERROR
 *
 * @param[in] struct config_section_description_s *csd
 *
 * @retval    ERROR or SUCCESS
 *
 * return ya_result
 */
static ya_result
config_section_key_roll_start(struct config_section_descriptor_s *csd)
{
#if CONFIG_SETTINGS_DEBUG
    formatln("config: section: key_roll: start");
#endif

    if(csd->base != NULL)
    {
        return INVALID_STATE_ERROR;
    }
    
    key_roll_desc_s *key_roll;
    MALLOC_OBJECT_OR_DIE(key_roll, key_roll_desc_s, KEYROLCF_TAG);
    ZEROMEMORY(key_roll, sizeof(key_roll_desc_s));

    csd->base = key_roll;

    return SUCCESS;
}


//#define KEY_ROLL_TOKEN_DELIMITER ""


/**
 * @fn static ya_result config_section_key_roll_stop(struct config_section_descriptor_s *csd)
 *
 * @brief
 * stop of a <key-roll> section csd->base set to NULL --> ready for 
 * parsing all <key-roll> items: generate, publish, activate, inactive, remove, ...
 * put the 'key-roll' in a binary tree with index key_roll->id
 *
 * @details
 * check if all items are there and of the correct types, otherwise give back an error
 * 'key-roll' is put in a binary tree for easy access when they need to be translated in the correct structure for 'yadifad'
 *
 * @param[in] struct config_section_description_s *csd
 *
 * @retval    ERROR or SUCCESS
 *
 * return ya_result
 */
static ya_result
config_section_key_roll_stop(struct config_section_descriptor_s *csd)
{
#if CONFIG_SETTINGS_DEBUG
    formatln("config: section: key_roll: stop");
#endif

    key_roll_desc_s *key_roll = (key_roll_desc_s *) csd->base;
    
    if(key_roll->id == NULL)
    {
        ttylog_err("config: key-roll: id not set");
        return CONFIG_SECTION_ERROR;
    }

    ya_result return_code;
    key_roll_line_s krl_generate;
    key_roll_line_s krl_publish;
    key_roll_line_s krl_activate;
    key_roll_line_s krl_inactive;
    key_roll_line_s krl_remove;
    key_roll_line_s krl_ds_publish;
    key_roll_line_s krl_ds_remove;

    if(FAIL(return_code = config_key_roll_parser_line(key_roll->generate, &krl_generate, KR_ACTION_GENERATE)))
    {
        ttylog_err("config: key-roll: %s: error in 'generate' (%r)", key_roll->id, return_code);

        return PARSE_INVALID_ARGUMENT;
    }

    if(FAIL(return_code = config_key_roll_parser_line(key_roll->publish, &krl_publish, KR_ACTION_GENERATE)))
    {
        ttylog_err("config: key-roll: %s: error in 'publish' (%r)", key_roll->id, return_code);

        return PARSE_INVALID_ARGUMENT;
    }

    if(FAIL(return_code = config_key_roll_parser_line(key_roll->activate, &krl_activate, KR_ACTION_PUBLISH)))
    {
        ttylog_err("config: key-roll: %s: error in 'activate' (%r)", key_roll->id, return_code);

        return PARSE_INVALID_ARGUMENT;
    }

    if(FAIL(return_code = config_key_roll_parser_line(key_roll->inactive, &krl_inactive, KR_ACTION_ACTIVATE)))
    {
        ttylog_err("config: key-roll: %s: error in 'inactive' (%r)", key_roll->id, return_code);

        return PARSE_INVALID_ARGUMENT;
    }

    if(FAIL(return_code = config_key_roll_parser_line(key_roll->remove, &krl_remove, KR_ACTION_INACTIVE)))
    {
        ttylog_err("config: key-roll: %s: error in 'remove' (%r)", key_roll->id, return_code);

        return PARSE_INVALID_ARGUMENT;
    }


#if HAS_DS_PUBLICATION_SUPPORT
    if(FAIL(return_code = config_key_roll_parser_line(key_roll->ds_publish, &krl_ds_publish, KR_ACTION_DS_PUBLISH)))
    {
        if(return_code != PARSE_EMPTY_ARGUMENT)
        {
            return return_code;
        }
        else
        {
            /// @todo 20160610 gve -- still needs to write code for this
        }
    }

    if(FAIL(return_code = config_key_roll_parser_line(key_roll->ds_remove, &krl_ds_remove, KR_ACTION_DS_REMOVE)))
    {
        if(return_code != PARSE_EMPTY_ARGUMENT)
        {
            return return_code;
        }
        else
        {
            /// @todo 20160610 gve -- still needs to write code for this
        }
        return return_code;
    }
#endif // if HAS_DS_PUBLICATION_SUPPORT

    /// @todo 20160603 gve -- still needs to test if they exist
    if(krl_generate.type == krl_publish.type &&
       krl_generate.type == krl_activate.type &&
       krl_generate.type == krl_inactive.type &&
#if HAS_DS_PUBLICATION_SUPPORT
       krl_generate.type == krl_remove.type &&
       krl_generate.type == krl_ds_publish.type &&
       krl_generate.type == krl_ds_remove.type)
#else
       krl_generate.type == krl_remove.type)
#endif // if HAS_DS_PUBLICATION_SUPPORT
    {


        // KER_ROLL_LINE_CRON_TYPE
        if(krl_generate.type)
        {
            return_code = zone_policy_roll_create_from_rules(key_roll->id,
                                               &krl_generate.policy.cron,
                                               &krl_publish.policy.cron,
                                               &krl_activate.policy.cron,
                                               &krl_inactive.policy.cron,
                                               &krl_remove.policy.cron,
                                               &krl_ds_publish.policy.cron,
                                               &krl_ds_remove.policy.cron);
        }
        // KER_ROLL_LINE_NON_CRON_TYPE
        else
        {
            return_code = zone_policy_roll_create_from_relatives(key_roll->id,
                                                   &krl_generate.policy.relative,
                                                   (u8) krl_generate.relative_to,
                                                   &krl_publish.policy.relative,
                                                   (u8) krl_publish.relative_to,
                                                   &krl_activate.policy.relative,
                                                   (u8) krl_activate.relative_to,
                                                   &krl_inactive.policy.relative,
                                                   (u8) krl_inactive.relative_to,
                                                   &krl_remove.policy.relative,
                                                   (u8) krl_remove.relative_to
#if HAS_DS_PUBLICATION_SUPPORT
                                                   ,
                                                   &krl_ds_publish.policy.relative,
                                                   (u8) krl_ds_publish.relative_to,
                                                   &krl_ds_remove.policy.relative,
                                                   (u8) krl_ds_remove.relative_to
#endif
                                                   );

        }
        
        if(FAIL(return_code))
        {
            ttylog_err("config: key-roll: '%s' has invalid settings", key_roll->id);
            
            return CONFIG_SECTION_ERROR;
        }
    }
    else
    {
        ttylog_err("config: key-roll: %s: different key-roll types used in section", key_roll->id);

        return CONFIG_SECTION_ERROR;
    }


    csd->base = NULL;

    ptr_node *node = ptr_set_insert(&key_roll_desc_set, key_roll->id);

    if(node->value == NULL)
    {
        node->value = key_roll;

        return SUCCESS;
    }
    else
    {
        ttylog_err("config: key-roll: %s: already registered", key_roll->id);

        return CONFIG_SECTION_ERROR;
    }
}


/**
 * @fn static ya_result config_section_key_roll_postprocess(struct config_section_descriptor_s *csd)
 *
 * @brief no postprocessing needed
 *
 * @details
 * no postprocessing
 *
 *
 * @param[in] struct config_section_description_s *csd
 *
 * @retval    ERROR or SUCCESS
 *
 * return ya_result
 */
static ya_result
config_section_key_roll_postprocess(struct config_section_descriptor_s *csd)
{
    (void)csd;
    return SUCCESS;
}


/**
 * @fn static void key_roll_free(key_roll_desc_s *key_roll)
 *
 * @brief free all <key-roll> items: generate, publish, ...
 *
 * @details
 * just free all items of <key-roll> section
 *
 *
 * @param[in,out] key_roll_desc_s *key_roll
 *
 * return --
 */
static void
key_roll_free(key_roll_desc_s *key_roll)
{
    free(key_roll->id);
    free(key_roll->generate);
    free(key_roll->publish);
    free(key_roll->activate);
    free(key_roll->inactive);
    free(key_roll->remove);
    free(key_roll->ds_publish);
    free(key_roll->ds_remove);

    free(key_roll);
}


/**
 * @fn static ya_result config_section_key_roll_finalize(struct config_section_descriptor_s *csd)
 *
 * @brief free key_roll_desc_s completely
 *
 * @details
 * empty 'dnssec_policy' key_roll parameter and everything else
 * and free csd and set back to 'NULL'
 *
 * @param[in] struct config_section_description_s *csd
 *
 * @retval    ERROR or SUCCESS
 *
 * return ya_result
 */
static ya_result
config_section_key_roll_finalize(struct config_section_descriptor_s *csd)
{
    if(csd != NULL)
    {
        if(csd->base != NULL)
        {
            key_roll_desc_s *key_roll = (key_roll_desc_s*)csd->base;
            key_roll_free(key_roll);
#if DEBUG
            csd->base = NULL;
#endif
        }

        free(csd);
    }

    return SUCCESS;
}


/*----------------------------------------------------------------------------*/
#pragma mark VIRTUAL TABLE


static const config_section_descriptor_vtbl_s config_section_key_roll_descriptor_vtbl =
{
    "key-roll",
    config_section_key_roll_desc,                               // no table
    config_section_key_roll_set_wild,
    config_section_key_roll_print_wild,
    config_section_key_roll_init,
    config_section_key_roll_start,
    config_section_key_roll_stop,
    config_section_key_roll_postprocess,
    config_section_key_roll_finalize
};


/*----------------------------------------------------------------------------*/
#pragma mark FUNCTIONS


/**
 * @fn ya_result config_register_key_roll(const char *null_or_key_name, s32 priority)
 *
 * @brief register all sections needed for <key-roll> sections
 *
 * @details
 *
 * @param[in] const char *null_or_key_name
 * @param[in] s32 priority
 *
 * @retval    return_code -- from other functions
 *
 * return ya_result
 */
ya_result
config_register_key_roll(const char *null_or_key_name, s32 priority)
{
    //null_or_key_name = "zone";
    (void)null_or_key_name;

    config_section_descriptor_s *desc;
    MALLOC_OBJECT_OR_DIE(desc, config_section_descriptor_s, CFGSDESC_TAG);
    desc->base = NULL;
    desc->vtbl = &config_section_key_roll_descriptor_vtbl;

    ya_result return_code = config_register(desc, priority);

    if(FAIL(return_code))
    {
        free(desc);
    }


    return return_code; // scan-build false positive: either it is freed, either it is stored in a global collection
}
