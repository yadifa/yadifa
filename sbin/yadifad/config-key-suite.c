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
#include <dnscore/logger.h>

#include "dnssec-policy.h"
#include "zone-signature-policy.h"
#include "server_error.h"

#include "confs.h"

/*----------------------------------------------------------------------------*/
#pragma mark GLOBAL VARIABLES

#define MODULE_MSG_HANDLE g_server_logger

#define KEYSUICF_TAG 0x464349555359454b

static ptr_set key_suite_desc_set = PTR_SET_ASCIIZ_EMPTY;

/*----------------------------------------------------------------------------*/
#pragma mark CONFIG


// key-suite container
#define CONFIG_TYPE key_suite_desc_s
CONFIG_BEGIN(config_section_key_suite_desc)

CONFIG_STRING(id, NULL)
CONFIG_STRING(key_template, NULL)
CONFIG_STRING(key_roll, NULL)

CONFIG_END(config_section_key_suite_desc)
#undef CONFIG_TYPE

#pragma mark STATIC FUNCTIONS

static ya_result
config_section_key_suite_set_wild(struct config_section_descriptor_s *csd, const char *key, const char *value)
{
    (void)csd;
    (void)key;
    (void)value;

    return CONFIG_UNKNOWN_SETTING;
}

static ya_result
config_section_key_suite_print_wild(const struct config_section_descriptor_s *csd, output_stream *os, const char *key)
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
 * @fn static ya_result config_section_key_suite_init(struct config_section_descriptor_s *csd)
 *
 * @brief initializing of a section: <key-suite>
 *
 * @details
 * the initializing of <key-suite> section is a NOP.
 *
 * @param[in] struct config_section_description_s *csd
 *
 * @retval    ERROR or SUCCESS
 *
 * return ya_result
 */
static ya_result
config_section_key_suite_init(struct config_section_descriptor_s *csd)
{
    // NOP

    if(csd->base != NULL)
    {
        return INVALID_STATE_ERROR; // base SHOULD be NULL at init
    }

    return SUCCESS;
}


/**
 * @fn static ya_result config_section_key_suite_start(struct config_section_descriptor_s *csd)
 *
 * @brief
 * start of a <key-suite> section csd->base will be initialized
 *
 * @details
 * csd->base will be initialized with key_suite
 * you can not have a start of a 'section' in a 'section' --> ERROR
 *
 * @param[in] struct config_section_description_s *csd
 *
 * @retval    ERROR or SUCCESS
 *
 * return ya_result
 */
static ya_result
config_section_key_suite_start(struct config_section_descriptor_s *csd)
{
#if CONFIG_SETTINGS_DEBUG
    formatln("config: section: key_suite: start");
#endif

    if(csd->base != NULL)
    {
        return INVALID_STATE_ERROR;
    }
    
    key_suite_desc_s *key_suite;
    MALLOC_OBJECT_OR_DIE(key_suite, key_suite_desc_s, KEYSUICF_TAG);
    ZEROMEMORY(key_suite, sizeof(key_suite_desc_s));

    csd->base = key_suite;

    return SUCCESS;
}

/**
 * @fn static ya_result config_section_key_suite_stop(struct config_section_descriptor_s *csd)
 *
 * @brief
 * stop of a <key-suite> section csd->base set to NULL -->
 * put the 'key-suite' in a binary tree with index key_suite->id
 *
 * @details
 * 'key-suite' is put in a binary tree for easy access when they need to be translated in the correct structure for 'yadifad'
 *
 * @param[in] struct config_section_description_s *csd
 *
 * @retval    ERROR or SUCCESS
 *
 * return ya_result
 */
static ya_result
config_section_key_suite_stop(struct config_section_descriptor_s *csd)
{
#if CONFIG_SETTINGS_DEBUG
    formatln("config: section: key_suite: stop");
#endif

    // NOP
    key_suite_desc_s *key_suite = (key_suite_desc_s *) csd->base;
    csd->base = NULL;

    if(key_suite->id == NULL)
    {
        ttylog_err("config: key-suite: id not set");
        return CONFIG_SECTION_ERROR;
    }
    
    ptr_node *node = ptr_set_insert(&key_suite_desc_set, key_suite->id);

    if(node->value == NULL)
    {
        node->value = key_suite;
        return SUCCESS;
    }
    else
    {
        ttylog_err("config: key-suite: %s: already defined", key_suite->id);
        return CONFIG_SECTION_ERROR;
    }
}

/**
 * @fn static ya_result config_section_key_suite_postprocess(struct config_section_descriptor_s *csd)
 *
 * @brief iterate thru binary tree and create the needed 'key-suite' structures for 'yadifad'
 *
 * @details
 * 'key-suite' needs a 'key-roll' and a 'key-template' section
 *
 * @param[in] struct config_section_description_s *csd
 *
 * @retval    ERROR or SUCCESS
 *
 * return ya_result
 */

static ya_result
config_section_key_suite_postprocess(struct config_section_descriptor_s *csd)
{
    (void)csd;
    ya_result ret = SUCCESS;

    if(g_config->check_policies)
    {
        time_t now =  time(NULL);
        ret = dnssec_policy_roll_test_all(now, 315576000 /* 10 years */, TRUE, FALSE);
        flushout();
        if(FAIL(ret))
        {
            return ret;
        }
    }

    ptr_set_iterator iter;
    ptr_set_iterator_init(&key_suite_desc_set, &iter);

    while(ptr_set_iterator_hasnext(&iter))
    {
        ptr_node *key_suite_node = ptr_set_iterator_next_node(&iter);
        key_suite_desc_s *key_suite_desc = (key_suite_desc_s *)key_suite_node->value;
        dnssec_policy_key *dpk = dnssec_policy_key_acquire_from_name(key_suite_desc->key_template);
        if(dpk != NULL)
        {
            dnssec_policy_roll *dpr = dnssec_policy_roll_acquire_from_name(key_suite_desc->key_roll);
            if(dpr != NULL)
            {
                /*dnssec_policy_key_suite *dpks =*/ dnssec_policy_key_suite_create(key_suite_desc->id,
                                                                               dpk,
                                                                               dpr);

                dnssec_policy_roll_release(dpr);
            }            
            else
            {
                ttylog_err("config: key-suite: %s: key-template %s not defined", key_suite_desc->id, key_suite_desc->key_roll);
            }
            dnssec_policy_key_release(dpk);
        }
        else
        {
            ttylog_err("config: key-suite: %s: key-template %s not defined", key_suite_desc->id, key_suite_desc->key_template);
        }
    }

    return ret;
}


/**
 * @fn static void key_suite_free(key_suite_desc_s *key_suite)
 *
 * @brief free
 *
 * @details
 * just free all items of <key-suite> section
 *
 *
 * @param[in] key_suite_desc_s *key_suite
 *
 * return --
 */
static void
key_suite_free(key_suite_desc_s *key_suite)
{
    free(key_suite->id);
    free(key_suite->key_template);
    free(key_suite->key_roll);

    free(key_suite);
}


/**
 * @fn static ya_result config_section_key_suite_finalize(struct config_section_descriptor_s *csd)
 *
 * @brief free key_template_desc_s completely
 *
 * @details
 * empty 'dnssec_policy' key_suite parameter and everything else
 * and free csd and set back to 'NULL'
 *
 * @param[in] struct config_section_description_s *csd
 *
 * @retval    ERROR or SUCCESS
 *
 * return ya_result
 */
static ya_result
config_section_key_suite_finalize(struct config_section_descriptor_s *csd)
{
    if(csd != NULL)
    {
        if(csd->base != NULL)
        {
            key_suite_desc_s *key_suite = (key_suite_desc_s*)csd->base;
            key_suite_free(key_suite);
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


static const config_section_descriptor_vtbl_s config_section_key_suite_descriptor_vtbl =
{
    "key-suite",
    config_section_key_suite_desc,                               // no table
    config_section_key_suite_set_wild,
    config_section_key_suite_print_wild,
    config_section_key_suite_init,
    config_section_key_suite_start,
    config_section_key_suite_stop,
    config_section_key_suite_postprocess,
    config_section_key_suite_finalize
};


/*----------------------------------------------------------------------------*/
#pragma mark FUNCTIONS


/**
 * @fn ya_result config_register_key_suite(const char *null_or_key_name, s32 priority)
 *
 * @brief register all sections needed for <key-template> sections
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
config_register_key_suite(const char *null_or_key_name, s32 priority)
{
    //null_or_key_name = "zone";
    (void)null_or_key_name;

    config_section_descriptor_s *desc;
    MALLOC_OBJECT_OR_DIE(desc, config_section_descriptor_s, CFGSDESC_TAG);
    desc->base = NULL;
    desc->vtbl = &config_section_key_suite_descriptor_vtbl;

    ya_result return_code = config_register(desc, priority);

    if(FAIL(return_code))
    {
        free(desc);
    }

    return return_code; // scan-build false positive: either it is freed, either it is stored in a global collection
}

