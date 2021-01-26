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
#include <dnscore/dnssec_errors.h>
#include <dnscore/format.h>

#include "config-dnssec-policy.h"
#include "dnssec-policy.h"

/*----------------------------------------------------------------------------*/
#pragma mark GLOBAL VARIABLES

#define KEYTEMCF_TAG 0x46434d455459454b

static ptr_set key_template_desc_set = PTR_SET_ASCIIZ_EMPTY;


static value_name_table dnssec_algorithm_enum[] =
{
    {DNSKEY_ALGORITHM_RSAMD5         , DNSKEY_ALGORITHM_RSAMD5_NAME         },
    {DNSKEY_ALGORITHM_RSAMD5         , "1"                                  },
    {DNSKEY_ALGORITHM_DIFFIE_HELLMAN , DNSKEY_ALGORITHM_DIFFIE_HELLMAN_NAME },
    {DNSKEY_ALGORITHM_DIFFIE_HELLMAN , "2"                                  },
    {DNSKEY_ALGORITHM_DSASHA1        , DNSKEY_ALGORITHM_DSASHA1_NAME        },
    {DNSKEY_ALGORITHM_DSASHA1        , "3"                                  },
    {DNSKEY_ALGORITHM_RSASHA1        , DNSKEY_ALGORITHM_RSASHA1_NAME        },
    {DNSKEY_ALGORITHM_RSASHA1        , "5"                                  },
    {DNSKEY_ALGORITHM_DSASHA1_NSEC3  , DNSKEY_ALGORITHM_DSASHA1_NSEC3_NAME  },
    {DNSKEY_ALGORITHM_DSASHA1_NSEC3  , DNSKEY_ALGORITHM_DSASHA1_NSEC3_NAME2 },
    {DNSKEY_ALGORITHM_DSASHA1_NSEC3  , "6"                                  },
    {DNSKEY_ALGORITHM_RSASHA1_NSEC3  , DNSKEY_ALGORITHM_RSASHA1_NSEC3_NAME  },
    {DNSKEY_ALGORITHM_RSASHA1_NSEC3  , DNSKEY_ALGORITHM_RSASHA1_NSEC3_NAME2 },
    {DNSKEY_ALGORITHM_RSASHA1_NSEC3  , "7"                                  },
    {DNSKEY_ALGORITHM_RSASHA256_NSEC3, DNSKEY_ALGORITHM_RSASHA256_NSEC3_NAME},
    {DNSKEY_ALGORITHM_RSASHA256_NSEC3, "8"                                  },
    {DNSKEY_ALGORITHM_RSASHA512_NSEC3, DNSKEY_ALGORITHM_RSASHA512_NSEC3_NAME},
    {DNSKEY_ALGORITHM_RSASHA512_NSEC3, "10"                                 },
    {DNSKEY_ALGORITHM_GOST           , DNSKEY_ALGORITHM_GOST_NAME           },
    {DNSKEY_ALGORITHM_GOST           , "12"                                 },
    {DNSKEY_ALGORITHM_ECDSAP256SHA256, DNSKEY_ALGORITHM_ECDSAP256SHA256_NAME},
    {DNSKEY_ALGORITHM_ECDSAP256SHA256, "13"                                 },
    {DNSKEY_ALGORITHM_ECDSAP384SHA384, DNSKEY_ALGORITHM_ECDSAP384SHA384_NAME},
    {DNSKEY_ALGORITHM_ECDSAP384SHA384, "14"                                 },
    {DNSKEY_ALGORITHM_ED25519        , DNSKEY_ALGORITHM_ED25519_NAME        },
    {DNSKEY_ALGORITHM_ED25519        , "15"                                 },
    {DNSKEY_ALGORITHM_ED448          , DNSKEY_ALGORITHM_ED448_NAME          },
    {DNSKEY_ALGORITHM_ED448          , "16"                                 },
#ifdef DNSKEY_ALGORITHM_DUMMY
    {DNSKEY_ALGORITHM_DUMMY          , DNSKEY_ALGORITHM_DUMMY_NAME},
    {DNSKEY_ALGORITHM_DUMMY          , "254"},
#endif
    {0, NULL}
};


/*----------------------------------------------------------------------------*/
#pragma mark CONFIG


// key-template container
#define CONFIG_TYPE key_template_desc_s
CONFIG_BEGIN(config_section_key_template_desc)

CONFIG_STRING(    id,        NULL                                                      )
CONFIG_BOOL(      ksk,       "0"                                                       )
CONFIG_ENUM(      algorithm, DNSKEY_ALGORITHM_RSASHA256_NSEC3_NAME, dnssec_algorithm_enum)
CONFIG_U16(       size,      "0"                                                       )
CONFIG_STRING(    engine,    NULL                                                      )

CONFIG_END(config_section_key_template_desc)
#undef CONFIG_TYPE

#pragma mark STATIC FUNCTIONS

static ya_result
config_section_key_template_set_wild(struct config_section_descriptor_s *csd, const char *key, const char *value)
{
    (void)csd;
    (void)key;
    (void)value;
    return CONFIG_UNKNOWN_SETTING;
}


static ya_result
config_section_key_template_print_wild(const struct config_section_descriptor_s *csd, output_stream *os, const char *key)
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
static ya_result
config_section_key_template_init(struct config_section_descriptor_s *csd)
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
static ya_result
config_section_key_template_start(struct config_section_descriptor_s *csd)
{
#if CONFIG_SETTINGS_DEBUG
    formatln("config: section: key_template: start");
#endif

    if(csd->base != NULL)
    {
        return INVALID_STATE_ERROR;
    }
    
    key_template_desc_s *key_template;
    MALLOC_OBJECT_OR_DIE(key_template, key_template_desc_s, KEYTEMCF_TAG);
    ZEROMEMORY(key_template, sizeof(key_template_desc_s));

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
 * 'key-template' is put in a binary tree for easy access when they need to be translated in the correct structure for 'yadifad'
 *
 * @param[in] struct config_section_description_s *csd
 *
 * @retval    ERROR or SUCCESS
 *
 * return ya_result
 */
static ya_result
config_section_key_template_stop(struct config_section_descriptor_s *csd)
{
#if CONFIG_SETTINGS_DEBUG
    formatln("config: section: key_template: stop");
#endif

    // NOP
    key_template_desc_s *key_template = (key_template_desc_s *) csd->base;
    csd->base = NULL;

    // 2. set 'algorithm'

    
    if(key_template->id == NULL)
    {
        formatln("config: key-template: id not set");
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
                formatln("dnssec-policy: key_template: %s: unsupported key size: %i.  Only 256 bits is supported for this algorithm.", key_template->id, key_template->size);

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
                formatln("dnssec-policy: key_template: %s: unsupported key size: %i.  Only 256 bits is supported for this algorithm.", key_template->id, key_template->size);

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
                formatln("dnssec-policy: key_template: %s: unsupported key size: %i.  Only 384 bits is supported for this algorithm.", key_template->id, key_template->size);

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
                formatln("dnssec-policy: key_template: %s: unsupported key size: %i.  Only 256 bits is supported for this algorithm.", key_template->id, key_template->size);

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
                formatln("dnssec-policy: key_template: %s: unsupported key size: %i.  Only 384 bits is supported for this algorithm.", key_template->id, key_template->size);

                return PARSE_INVALID_ARGUMENT;
            }
            break;
#ifdef DNSKEY_ALGORITHM_DUMMY
        case DNSKEY_ALGORITHM_DUMMY:
            key_template->size = 16;
            break;
#endif
        default:
            return DNSSEC_ERROR_UNSUPPORTEDKEYALGORITHM;
    }

    ptr_node *node = ptr_set_insert(&key_template_desc_set, key_template->id);

    if(node->value == NULL)
    {
        node->value = key_template;

        return SUCCESS;
    }
    else
    {
        formatln("config: key-template: %s: already defined", key_template->id);

        return CONFIG_SECTION_ERROR;
    }
}


/**
 * @fn static ya_result config_section_key_template_postprocess(struct config_section_descriptor_s *csd)
 *
 * @brief iterate thru binary tree and create the needed 'key-template' structures for 'yadifad'
 *
 * @details
 * no 'engine' implemented
 *
 *
 * @param[in] struct config_section_description_s *csd
 *
 * @retval    ERROR or SUCCESS
 *
 * return ya_result
 */
static ya_result
config_section_key_template_postprocess(struct config_section_descriptor_s *csd)
{
    (void)csd;
    ptr_set_iterator iter;
    ptr_set_iterator_init(&key_template_desc_set, &iter);

    while(ptr_set_iterator_hasnext(&iter))
    {
        ptr_node *key_template_node = ptr_set_iterator_next_node(&iter);
        key_template_desc_s *key_template_desc = (key_template_desc_s *)key_template_node->value;

        /*dnssec_policy_key *dpk =*/ dnssec_policy_key_create(key_template_desc->id,
                                                        key_template_desc->algorithm,
                                                        key_template_desc->size,
                                                        key_template_desc->ksk,
                                                        NULL);   // no engine in YADIFA 2.2.0
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
static void
key_template_free(key_template_desc_s *key_template)
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
static ya_result
config_section_key_template_finalize(struct config_section_descriptor_s *csd)
{
    if(csd != NULL)
    {
        if(csd->base != NULL)
        {
            key_template_desc_s *key_template = (key_template_desc_s*)csd->base;
            key_template_free(key_template);
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


static const config_section_descriptor_vtbl_s config_section_key_template_descriptor_vtbl =
{
    "key-template",
    config_section_key_template_desc,                               // no table
    config_section_key_template_set_wild,
    config_section_key_template_print_wild,
    config_section_key_template_init,
    config_section_key_template_start,
    config_section_key_template_stop,
    config_section_key_template_postprocess,
    config_section_key_template_finalize
};


/*----------------------------------------------------------------------------*/
#pragma mark FUNCTIONS


/**
 * @fn ya_result config_register_key_template(const char *null_or_key_name, s32 priority)
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
config_register_key_template(const char *null_or_key_name, s32 priority)
{
    //null_or_key_name = "zone";
    (void)null_or_key_name;

    config_section_descriptor_s *desc;
    MALLOC_OBJECT_OR_DIE(desc, config_section_descriptor_s, CFGSDESC_TAG);
    desc->base = NULL;
    desc->vtbl = &config_section_key_template_descriptor_vtbl;

    ya_result return_code = config_register(desc, priority);

    if(FAIL(return_code))
    {
        free(desc);
    }


    return return_code; // scan-build false positive: either it is freed, either it is stored in a global collection
}

