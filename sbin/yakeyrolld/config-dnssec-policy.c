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
 *  @ingroup configuration
 *  @brief
 */

#include <dnscore/config_settings.h>
#include <dnscore/ptr_set.h>
#include <dnscore/dnskey.h>
#include <dnscore/format.h>

#include "dnssec-policy.h"
#include "config-dnssec-policy.h"


/*----------------------------------------------------------------------------*/
#pragma mark DEFINES

#define DP_FLAGS_WEAKER_KEY       0x01
#define DP_FLAGS_STRONGER_KEY     0x02
#define DP_KEY_SUITE_SIZE            4

/*----------------------------------------------------------------------------*/
#pragma mark GLOBAL VARIABLES


#define POLICYCF_TAG 0x46435943494c4f50

static ptr_set dnssec_policy_desc_set = PTR_SET_ASCIIZ_EMPTY;

/*----------------------------------------------------------------------------*/
#pragma mark CONFIG


// dnssec-policy container
#define CONFIG_TYPE dnssec_policy_desc_s
CONFIG_BEGIN(config_section_dnssec_policy_desc)

CONFIG_STRING(        id,                   NULL                                )
CONFIG_STRING(        description,          NULL                                )
CONFIG_STRING_ARRAY(  key_suite,            NULL,   DP_KEY_SUITE_SIZE           )
CONFIG_U32_RANGE(     ds_ttl,               "3600", 0, MAX_S32                  )
CONFIG_FLAG8(         weaker_key_removal,   "0",    flags, DP_FLAGS_WEAKER_KEY  )
CONFIG_FLAG8(         stronger_key_removal, "0",    flags, DP_FLAGS_STRONGER_KEY)
CONFIG_U8(            max_key,              "2"                                 ) /// @todo 20160520 gve -- check if this per key or key_suite

         /*           alias,                aliased */
CONFIG_ALIAS(         max_keys,             max_key                             )

CONFIG_END(config_section_dnssec_policy_desc)
#undef CONFIG_TYPE


/*----------------------------------------------------------------------------*/
#pragma mark STATIC FUNCTIONS


static ya_result
config_section_dnssec_policy_set_wild(struct config_section_descriptor_s *csd, const char *key, const char *value)
{
    (void)csd;
    (void)key;
    (void)value;
    
    return CONFIG_UNKNOWN_SETTING;
}


static ya_result
config_section_dnssec_policy_print_wild(const struct config_section_descriptor_s *csd, output_stream *os, const char *key)
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
static ya_result
config_section_dnssec_policy_init(struct config_section_descriptor_s *csd)
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
 * csd->base will be initialized with a new ptr_vector for key-suites
 *
 * @param[in] struct config_section_description_s *csd
 *
 * @retval    ERROR or SUCCESS
 *
 * return ya_result
 */
static ya_result
config_section_dnssec_policy_start(struct config_section_descriptor_s *csd)
{
#if CONFIG_SETTINGS_DEBUG
    formatln("config: section: dnssec-policy: start");
#endif
    if(csd->base != NULL)
    {
        return INVALID_STATE_ERROR;
    }
    
    dnssec_policy_desc_s *dnssec_policy;
    MALLOC_OBJECT_OR_DIE(dnssec_policy, dnssec_policy_desc_s, POLICYCF_TAG);
    ZEROMEMORY(dnssec_policy, sizeof(dnssec_policy_desc_s));
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
 * 'dnssec-policy' is put in a binary tree for easy access when they need to be translated in the correct structure for 'yadifad'
 *
 * @param[in] struct config_section_description_s *csd
 *
 * @retval    ERROR or SUCCESS
 *
 * return ya_result
 */
static ya_result
config_section_dnssec_policy_stop(struct config_section_descriptor_s *csd)
{
#if CONFIG_SETTINGS_DEBUG
    formatln("config: section: dnssec-policy: stop");
#endif

    // NOP
    dnssec_policy_desc_s *dnssec_policy = (dnssec_policy_desc_s *) csd->base;
    csd->base = NULL;
    
    if(dnssec_policy->id == NULL)
    {
        formatln("config: dnssec-policy: id not set");
        return CONFIG_SECTION_ERROR;
    }

    if(ptr_vector_size(&dnssec_policy->key_suite) < 1)
    {
        formatln("config: dnssec-policy: %s: no key-suite has been set", dnssec_policy->id);
        return CONFIG_SECTION_ERROR;
    }
    
    ptr_node *node = ptr_set_insert(&dnssec_policy_desc_set, dnssec_policy->id);

    if(node->value == NULL)
    {
        node->value = dnssec_policy;
        return SUCCESS;
    }
    else
    {
        formatln("config: dnssec-policy: %s: already defined", dnssec_policy->id);
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
static ya_result
config_section_dnssec_policy_postprocess(struct config_section_descriptor_s *csd)
{
    (void)csd;

#if CONFIG_SETTINGS_DEBUG
    formatln("config: section: dnssec-policy: postprocess");
#endif
    ptr_set_iterator iter;
    ptr_set_iterator_init(&dnssec_policy_desc_set, &iter);

    while(ptr_set_iterator_hasnext(&iter))
    {
        ptr_node *dnssec_policy_node = ptr_set_iterator_next_node(&iter);
        dnssec_policy_desc_s *dnssec_policy_desc = (dnssec_policy_desc_s *)dnssec_policy_node->value;
        
        if((ptr_vector_size(&dnssec_policy_desc->key_suite) < 1) || (ptr_vector_size(&dnssec_policy_desc->key_suite) > 2))
        {
            formatln("config: dnssec-policy: %s: the dnssec-policy should have one (ZSK) or two (KSK and ZSK) key suites", dnssec_policy_desc->id);
        }

        bool has_zsk = FALSE;
                
        // get all <key-suite> sections for <dnssec-policy> configuration
        // and put it in 'key_suites'
        ptr_vector key_suites = PTR_VECTOR_EMPTY;
        for(int i = 0; i <= ptr_vector_last_index(&dnssec_policy_desc->key_suite); ++i)
        {
            // get 'key-suite' name and check if it exists, if not return 'ERROR'
            const char *key_suite_name = (char*)ptr_vector_get(&dnssec_policy_desc->key_suite, i);
            dnssec_policy_key_suite *dpks = dnssec_policy_key_suite_acquire_from_name(key_suite_name);
            
            if(dpks != NULL)
            {
                if((dpks->key->flags & DNSKEY_FLAGS_KSK) == DNSKEY_FLAGS_ZSK)
                {
                    has_zsk = TRUE;
                }
                
                ptr_vector_append(&key_suites, dpks);
            }
            else
            {
                formatln("config: dnssec-policy: %s: key suite '%s' not defined", dnssec_policy_desc->id, key_suite_name);

                return POLICY_KEY_SUITE_UNDEFINED;
            }
        }

        if(!has_zsk)
        {
            formatln("config: dnssec-policy: %s: at least one key suite with a ZSK is required", dnssec_policy_desc->id);
            return CONFIG_SECTION_ERROR;
        }

        // set the dnssec-policy structure for 'dnssec_policy_desc->id' with 'dd' and 'key_suites'

        // the value returned by dnssec_policy_create is also added to key_suites


        dnssec_policy_create(dnssec_policy_desc->id, &key_suites);

        // if done remove everything <denial> and <key-suite> for '<dnssec-policy> with 'dnssec_policy_desc->id'
        for(int i = 0; i <= ptr_vector_last_index(&key_suites); ++i)
        {
            dnssec_policy_key_suite *dpks = (dnssec_policy_key_suite*)ptr_vector_get(&key_suites, i);
            dnssec_policy_key_suite_release(dpks);
        }

        ptr_vector_destroy(&key_suites);
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
static void
dnssec_policy_free(dnssec_policy_desc_s *dnssec_policy)
{
    free(dnssec_policy->id);
    free(dnssec_policy->description);

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
static ya_result
config_section_dnssec_policy_finalize(struct config_section_descriptor_s *csd)
{
    if(csd != NULL)
    {
        if(csd->base != NULL)
        {
            dnssec_policy_desc_s *dnssec_policy = (dnssec_policy_desc_s*)csd->base;
            dnssec_policy_free(dnssec_policy);
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


static const config_section_descriptor_vtbl_s config_section_dnssec_policy_descriptor_vtbl =
{
    "dnssec-policy",
    config_section_dnssec_policy_desc,                               // no table
    config_section_dnssec_policy_set_wild,
    config_section_dnssec_policy_print_wild,
    config_section_dnssec_policy_init,
    config_section_dnssec_policy_start,
    config_section_dnssec_policy_stop,
    config_section_dnssec_policy_postprocess,
    config_section_dnssec_policy_finalize
};


/*----------------------------------------------------------------------------*/
#pragma mark FUNCTIONS


/**
 * @fn ya_result config_register_dnssec_policy(const char *null_or_key_name, s32 priority)
 *
 * @brief register all sections needed for <dnssec-policy> sections
 *
 * @details
 * <key-roll>, <key-template>, <denial> and <key-suite> are needed for <dnssec-policy>
 * get all of them before registering all <dnssec-policy> sections
 *
 * @param[in] const char *null_or_key_name
 * @param[in] s32 priority
 *
 * @retval    return_code -- from other functions
 *
 * return ya_result
 */
ya_result
config_register_dnssec_policy(const char *null_or_key_name, s32 priority)
{
    (void)null_or_key_name;

    // get all sections <key-roll>, <denial>, <key-template> and <key-suite>
    config_register_key_roll(NULL, priority);
    priority++;
    config_register_key_template(NULL, priority);
    priority++;
    config_register_key_suite(NULL, priority);
    priority++;


    // get the correct virtual table and register <dnssec-policy> section from
    // the configuration
    config_section_descriptor_s *desc;
    MALLOC_OBJECT_OR_DIE(desc, config_section_descriptor_s, CFGSDESC_TAG);
    desc->base = NULL;
    desc->vtbl = &config_section_dnssec_policy_descriptor_vtbl;

    ya_result return_code = config_register(desc, priority);

    if(FAIL(return_code))
    {
        free(desc);
    }

    return return_code; // scan-build false positive: either it is freed, either it is stored in a global collection
}
