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
 * @ingroup configuration
 * @brief
 *----------------------------------------------------------------------------*/

#include <dnscore/config_settings.h>
#include <dnscore/ptr_treemap.h>
#include <dnscore/dnskey.h>

#include "config_dnssec_policy.h"
#include "dnssec_policy.h"
#include "server_error.h"

/*----------------------------------------------------------------------------*/
#pragma mark DEFINES

#define DP_FLAGS_WEAKER_KEY   0x01
#define DP_FLAGS_STRONGER_KEY 0x02
#define DP_KEY_SUITE_SIZE     4

/*----------------------------------------------------------------------------*/
#pragma mark GLOBAL VARIABLES

#define MODULE_MSG_HANDLE g_server_logger

#define POLICYCF_TAG      0x46435943494c4f50

#if DNSCORE_HAS_PRIMARY_SUPPORT && DNSCORE_HAS_DNSSEC_SUPPORT

static ptr_treemap_t dnssec_policy_desc_set = PTR_TREEMAP_ASCIIZ_EMPTY;

/*----------------------------------------------------------------------------*/
#pragma mark CONFIG

// dnssec-policy container
#define CONFIG_TYPE dnssec_policy_desc_t
CONFIG_BEGIN(config_section_dnssec_policy_desc)
CONFIG_STRING(id, NULL)
CONFIG_STRING(description, NULL)
CONFIG_STRING(denial, "nsec")
CONFIG_STRING_ARRAY(key_suite, NULL, DP_KEY_SUITE_SIZE)
CONFIG_U32_RANGE(ds_ttl, "3600", 0, INT32_MAX)
CONFIG_FLAG8(weaker_key_removal, "0", flags, DP_FLAGS_WEAKER_KEY)
CONFIG_FLAG8(stronger_key_removal, "0", flags, DP_FLAGS_STRONGER_KEY)
CONFIG_U8(max_key, "2") // it's the number of key suites
CONFIG_ALIAS(max_keys, max_key)

CONFIG_END(config_section_dnssec_policy_desc)
#undef CONFIG_TYPE

/*----------------------------------------------------------------------------*/
#pragma mark STATIC FUNCTIONS

static ya_result config_section_dnssec_policy_set_wild(struct config_section_descriptor_s *csd, const char *key, const char *value)
{
    (void)csd;
    (void)key;
    (void)value;

    return CONFIG_UNKNOWN_SETTING;
}

static ya_result config_section_dnssec_policy_print_wild(const struct config_section_descriptor_s *csd, output_stream_t *os, const char *key, void **context)
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
 * @fn static ya_result config_section_dnssec_policy_init(struct config_section_descriptor_s *csd)
 *
 * @brief initializing of a section: <dnssec-policy>
 *
 * @details
 * the initializing of <dnssec-policy> section is a NOP.
 *
 * @param[in] struct config_section_description_s *csd
 *
 * @retval    ERROR or SUCCESS
 *
 * return ya_result
 */
static ya_result config_section_dnssec_policy_init(struct config_section_descriptor_s *csd)
{
    // NOP

    if(csd->base != NULL)
    {
        return INVALID_STATE_ERROR; // base SHOULD be NULL at init
    }

    return SUCCESS;
}

/**
 * @fn static ya_result config_section_dnssec_policy_start(struct config_section_descriptor_s *csd)
 *
 * @brief
 * start of a <dnssec-policy> section csd->base will be initialized
 *
 * @details
 * csd->base will be initialized with a new ptr_vector_t for key-suites
 *
 * @param[in] struct config_section_description_s *csd
 *
 * @retval    ERROR or SUCCESS
 *
 * return ya_result
 */
static ya_result config_section_dnssec_policy_start(struct config_section_descriptor_s *csd)
{
#if CONFIG_SETTINGS_DEBUG
    formatln("config: section: dnssec-policy: start");
#endif
    if(csd->base != NULL)
    {
        return INVALID_STATE_ERROR;
    }

    dnssec_policy_desc_t *dnssec_policy;
    MALLOC_OBJECT_OR_DIE(dnssec_policy, dnssec_policy_desc_t, POLICYCF_TAG);
    ZEROMEMORY(dnssec_policy, sizeof(dnssec_policy_desc_t));
    ptr_vector_init(&dnssec_policy->key_suite);
    csd->base = dnssec_policy;

    return SUCCESS;
}

/**
 * @fn static ya_result config_section_dnssec_policy_stop(struct config_section_descriptor_s *csd)
 *
 * @brief
 * stop of a <dnssec-policy> section csd->base set to NULL --> ready for the
 * next <dnssec-policy> section
 *
 * @details
 * global variable dnssec_policy_desc_set will have a new node (node->value = dnssec_policy) for a
 * new id (node->id)
 * 'dnssec-policy' is put in a binary tree for easy access when they need to be translated in the correct structure for
 * 'yadifad'
 *
 * @param[in] struct config_section_description_s *csd
 *
 * @retval    ERROR or SUCCESS
 *
 * return ya_result
 */
static ya_result config_section_dnssec_policy_stop(struct config_section_descriptor_s *csd)
{
#if CONFIG_SETTINGS_DEBUG
    formatln("config: section: dnssec-policy: stop");
#endif

    // NOP
    dnssec_policy_desc_t *dnssec_policy = (dnssec_policy_desc_t *)csd->base;
    csd->base = NULL;

    if(dnssec_policy->id == NULL)
    {
        ttylog_err("config: dnssec-policy: id not set");
        return CONFIG_SECTION_ERROR;
    }

    if(dnssec_policy->denial == NULL)
    {
        ttylog_err("config: dnssec-policy: %s: denial not set", dnssec_policy->id);
        return CONFIG_SECTION_ERROR;
    }

    if(strcmp(dnssec_policy->denial, "nsec") != 0)
    {
        dnssec_denial *denial = dnssec_policy_denial_acquire(dnssec_policy->denial);
        if(denial == NULL)
        {
            ttylog_err("config: dnssec-policy: denial '%s' is undefined", dnssec_policy->denial);
            return CONFIG_SECTION_ERROR;
        }
        dnssec_policy_denial_release(denial);
    }

    if(ptr_vector_size(&dnssec_policy->key_suite) < 1)
    {
        ttylog_err("config: dnssec-policy: %s: no key-suite has been set", dnssec_policy->id);
        return CONFIG_SECTION_ERROR;
    }

    if(ptr_vector_size(&dnssec_policy->key_suite) > dnssec_policy->max_key)
    {
        ttylog_err("config: dnssec-policy: %s: too many key-suite have been set", dnssec_policy->id);
        return CONFIG_SECTION_ERROR;
    }

    ptr_treemap_node_t *node = ptr_treemap_insert(&dnssec_policy_desc_set, dnssec_policy->id);

    if(node->value == NULL)
    {
        node->value = dnssec_policy;
        return SUCCESS;
    }
    else
    {
        ttylog_err("config: dnssec-policy: %s: already defined", dnssec_policy->id);
        return CONFIG_SECTION_ERROR;
    }
}

/**
 * @fn static ya_result config_section_dnssec_policy_postprocess(struct config_section_descriptor_s *csd)
 *
 * @brief create dnssec-policies structure to be used by 'yadifad'
 *
 * @details
 * check for a dnssec-policy node that all 'key_suites' are present and 'denial' is present
 * if they are present add them to the global struct
 *
 *
 * @param[in] struct config_section_description_s *csd
 *
 * @retval    ERROR or SUCCESS
 *
 * return ya_result
 */
static ya_result config_section_dnssec_policy_postprocess(struct config_section_descriptor_s *csd, config_error_t *cfgerr)
{
    (void)csd;

#if CONFIG_SETTINGS_DEBUG
    formatln("config: section: dnssec-policy: postprocess");
#endif
    ptr_treemap_iterator_t iter;
    ptr_treemap_iterator_init(&dnssec_policy_desc_set, &iter);

    while(ptr_treemap_iterator_hasnext(&iter))
    {
        ptr_treemap_node_t   *dnssec_policy_node = ptr_treemap_iterator_next_node(&iter);
        dnssec_policy_desc_t *dnssec_policy_desc = (dnssec_policy_desc_t *)dnssec_policy_node->value;

        if((ptr_vector_size(&dnssec_policy_desc->key_suite) < 1) || (ptr_vector_size(&dnssec_policy_desc->key_suite) > 2))
        {
            log_warn("config: dnssec-policy: %s: the dnssec-policy should have one (ZSK) or two (KSK and ZSK) key suites", dnssec_policy_desc->id);
        }

        // get the <denial> section from <dnssec-policy> configuration
        dnssec_denial *dd = dnssec_policy_denial_acquire(dnssec_policy_desc->denial); // note that dd is allowed to be NULL

        bool           has_zsk = false;

        // get all <key-suite> sections for <dnssec-policy> configuration
        // and put it in 'key_suites'
        ptr_vector_t key_suites = PTR_VECTOR_EMPTY;
        for(int_fast32_t i = 0; i <= ptr_vector_last_index(&dnssec_policy_desc->key_suite); ++i)
        {
            // get 'key-suite' name and check if it exists, if not return 'ERROR'
            const char              *key_suite_name = (char *)ptr_vector_get(&dnssec_policy_desc->key_suite, i);
            dnssec_policy_key_suite *dpks = dnssec_policy_key_suite_acquire_from_name(key_suite_name);

            if(dpks != NULL)
            {
                if((dpks->key->flags & DNSKEY_FLAGS_KSK) == DNSKEY_FLAGS_ZSK)
                {
                    has_zsk = true;
                }

                ptr_vector_append(&key_suites, dpks);
            }
            else
            {
                ttylog_err("config: dnssec-policy: %s: key suite '%s' not defined", dnssec_policy_desc->id, key_suite_name);
#if CONFIG_SECTION_DESCRIPTOR_TRACK
                config_section_descriptor_config_error_update(cfgerr, csd, &dnssec_policy_desc->key_suite);
#endif
                return POLICY_KEY_SUITE_UNDEFINED;
            }
        }

        if(!has_zsk)
        {
            ttylog_err("config: dnssec-policy: %s: at least one key suite with a ZSK is required", dnssec_policy_desc->id);
#if CONFIG_SECTION_DESCRIPTOR_TRACK
            config_section_descriptor_config_error_update(cfgerr, csd, &dnssec_policy_desc->id);
#endif
            return CONFIG_SECTION_ERROR;
        }

        // set the dnssec-policy structure for 'dnssec_policy_desc->id' with 'dd' and 'key_suites'

        // the value returned by dnssec_policy_create is also added to key_suites

        dnssec_policy_create(dnssec_policy_desc->id, dd, &key_suites);

        // if done remove everything <denial> and <key-suite> for '<dnssec-policy> with 'dnssec_policy_desc->id'
        for(int_fast32_t i = 0; i <= ptr_vector_last_index(&key_suites); ++i)
        {
            dnssec_policy_key_suite *dpks = (dnssec_policy_key_suite *)ptr_vector_get(&key_suites, i);
            dnssec_policy_key_suite_release(dpks);
        }

        if(dd != NULL)
        {
            dnssec_policy_denial_release(dd);
        }

        ptr_vector_finalise(&key_suites);
    }

    return SUCCESS;
}

/**
 * @fn static void dnssec_policy_free(dnssec_policy_desc_s *dnssec_policy)
 *
 * @brief free dnssec_policy_desc_s completely
 *
 * @details
 * empty 'dnssec_policy' key_suite parameter and everything else
 *
 * @param[in,out] dnssec_policy_desc_s *dnssec_policy
 *
 * return --
 */
static void dnssec_policy_free(dnssec_policy_desc_t *dnssec_policy)
{
    free(dnssec_policy->id);
    free(dnssec_policy->description);
    free(dnssec_policy->denial);
    ptr_vector_callback_and_clear(&dnssec_policy->key_suite, free);

    free(dnssec_policy);
}

/**
 * @fn static ya_result config_section_dnssec_policy_finalize(struct config_section_descriptor_s *csd)
 *
 * @brief free dnssec_policy_desc_s completely
 *
 * @details
 * empty 'dnssec_policy'
 * and free csd and set back to 'NULL'
 *
 * @param[in] struct config_section_description_s *csd
 *
 * @retval    ERROR or SUCCESS
 *
 * return ya_result
 */
static ya_result config_section_dnssec_policy_finalize(struct config_section_descriptor_s *csd)
{
    if(csd != NULL)
    {
        if(csd->base != NULL)
        {
            dnssec_policy_desc_t *dnssec_policy = (dnssec_policy_desc_t *)csd->base;
            dnssec_policy_free(dnssec_policy);
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

static const config_section_descriptor_vtbl_s config_section_dnssec_policy_descriptor_vtbl = {"dnssec-policy",
                                                                                              config_section_dnssec_policy_desc, // no table
                                                                                              config_section_dnssec_policy_set_wild,
                                                                                              config_section_dnssec_policy_print_wild,
                                                                                              config_section_dnssec_policy_init,
                                                                                              config_section_dnssec_policy_start,
                                                                                              config_section_dnssec_policy_stop,
                                                                                              config_section_dnssec_policy_postprocess,
                                                                                              config_section_dnssec_policy_finalize};

/*----------------------------------------------------------------------------*/
#pragma mark FUNCTIONS

/**
 * @fn ya_result config_register_dnssec_policy(const char *null_or_key_name, int32_t priority)
 *
 * @brief register all sections needed for <dnssec-policy> sections
 *
 * @details
 * <key-roll>, <key-template>, <denial> and <key-suite> are needed for <dnssec-policy>
 * get all of them before registering all <dnssec-policy> sections
 *
 * @param[in] const char *null_or_key_name
 * @param[in] int32_t priority
 *
 * @retval    return_code -- from other functions
 *
 * return ya_result
 */
ya_result config_register_dnssec_policy(const char *null_or_key_name, int32_t priority)
{
    (void)null_or_key_name;

    // get all sections <key-roll>, <denial>, <key-template> and <key-suite>
    config_register_key_roll(NULL, priority);
    priority++;
    config_register_denial(NULL, priority);
    priority++;
    config_register_key_template(NULL, priority);
    priority++;
    config_register_key_suite(NULL, priority);
    priority++;

    // get the correct virtual table and register <dnssec-policy> section from
    // the configuration
    config_section_descriptor_t *desc = config_section_descriptor_new_instance(&config_section_dnssec_policy_descriptor_vtbl);

    ya_result                    return_code = config_register(desc, priority);

    if(FAIL(return_code))
    {
        free(desc);
    }

    return return_code; // scan-build false positive: either it is freed, either it is stored in a global collection
}

#endif
