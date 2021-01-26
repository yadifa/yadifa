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

/** @defgroup 
 *  @ingroup 
 *  @brief 
 *
 * @{
 */

#pragma once

#include <stddef.h>

#include <dnscore/output_stream.h>
#include <dnscore/input_stream.h>
#include <dnscore/host_address.h>
#include <dnscore/ptr_vector.h>
#include <dnscore/cmdline.h>

/*
 Each section/container descriptor is registered.
 
   config section descriptor -------> target base (ie: g_config)
              |
              V
  config table descriptor vtbl -----> callbacks (init, start, stop, finalise, ...)
              |
              V
      table descriptor (BEGIN/END, names, offsets in target base, setters)
*/

#define CONFIG_ERROR_BASE                       0x800C0000
#define CONFIG_ERROR_CODE(code_)                ((s32)(CONFIG_ERROR_BASE+(code_)))

// Bugs in the program
#define CONFIG_SECTION_ALREADY_REGISTERED       CONFIG_ERROR_CODE(0xff01)
#define CONFIG_ALIAS_CHAIN_TOO_BIG              CONFIG_ERROR_CODE(0xff02)
// Parsing issues
#define CONFIG_PARSE_SECTION_TAG_NOT_CLOSED     CONFIG_ERROR_CODE(0x0001)
#define CONFIG_PARSE_UNEXPECTED_SECTION_OPEN    CONFIG_ERROR_CODE(0x0002)
#define CONFIG_PARSE_UNEXPECTED_SECTION_CLOSE   CONFIG_ERROR_CODE(0x0003)
#define CONFIG_PARSE_CLOSED_WRONG_SECTION       CONFIG_ERROR_CODE(0x0004)
#define CONFIG_PARSE_SECTION_TAG_TOO_SMALL      CONFIG_ERROR_CODE(0x0005)
#define CONFIG_PARSE_INCLUDE_EXPECTED_FILE_PATH CONFIG_ERROR_CODE(0x0006)
#define CONFIG_PARSE_UNKNOWN_KEYWORD            CONFIG_ERROR_CODE(0x0007)
#define CONFIG_PARSE_EXPECTED_VALUE             CONFIG_ERROR_CODE(0x0008)
// Content issues
#define CONFIG_UNKNOWN_SETTING                  CONFIG_ERROR_CODE(0x0011)
#define CONFIG_VALUE_OUT_OF_RANGE               CONFIG_ERROR_CODE(0x0012)
#define CONFIG_FILE_PATH_TOO_BIG                CONFIG_ERROR_CODE(0x0013)
#define CONFIG_BAD_UID                          CONFIG_ERROR_CODE(0x0014)
#define CONFIG_BAD_GID                          CONFIG_ERROR_CODE(0x0015)
#define CONFIG_TEXT_LENGHT_TOO_BIG              CONFIG_ERROR_CODE(0x0016)
#define CONFIG_ARRAY_SIZE_TOO_BIG               CONFIG_ERROR_CODE(0x0017)

// Logger config specific issues
#define CONFIG_LOGGER_HANDLE_ALREADY_DEFINED    CONFIG_ERROR_CODE(0x1001)
#define CONFIG_LOGGER_INVALID_DEBUGLEVEL        CONFIG_ERROR_CODE(0x1002)

// TSIG key config specific issues
#define CONFIG_KEY_INCOMPLETE_KEY               CONFIG_ERROR_CODE(0x2001)
#define CONFIG_KEY_UNSUPPORTED_ALGORITHM        CONFIG_ERROR_CODE(0x2002)

/*
#define CONFIG_LOGGER_INVALID_DEBUGLEVEL              CONFIG_ERROR_CODE(0x0001)
*/

#define CONFIG_TABLE_SOURCE_NONE                0
#define CONFIG_TABLE_SOURCE_DEFAULT             1
#define CONFIG_TABLE_SOURCE_CONFIGURATION_FILE  2
#define CONFIG_TABLE_SOURCE_COMMAND_LINE        3

#define CONFIG_HOST_LIST_FLAGS_IPV4             0x01
#define CONFIG_HOST_LIST_FLAGS_IPV6             0x02
#define CONFIG_HOST_LIST_FLAGS_FQDN             0x04
#define CONFIG_HOST_LIST_FLAGS_PORT             0x08
#define CONFIG_HOST_LIST_FLAGS_TSIG             0x10
#define CONFIG_HOST_LIST_FLAGS_APPEND           0x20

#define CONFIG_HOST_LIST_FLAGS_DEFAULT          (CONFIG_HOST_LIST_FLAGS_IPV4 | CONFIG_HOST_LIST_FLAGS_IPV6 | CONFIG_HOST_LIST_FLAGS_PORT | CONFIG_HOST_LIST_FLAGS_TSIG)

#define CONFIG_FLAG_ON  "1"
#define CONFIG_FLAG_OFF "0"

#define CONFIG_SOURCE_NONE    0
#define CONFIG_SOURCE_DEFAULT 1
#define CONFIG_SOURCE_FILE    128
#define CONFIG_SOURCE_CMDLINE 250
#define CONFIG_SOURCE_HIGHEST 255

#define CONFIG_SETTINGS_DEBUG 0

#define CONFIG_FIELD_ALLOCATION_DIRECT  0       // direct value 
#define CONFIG_FIELD_ALLOCATION_MALLOC  1       // mallocated value
#define CONFIG_FIELD_ALLOCATION_ZALLOC  2       // zallocated value

/**
 * This union covers 64 bits
 * Meant to be used to store different parameters
 */

union anytype_u
{
    /* DO NOT ADD THIS : bool    _bool; */
    intptr  _intptr;
    u8      _u8;
    u16     _u16;
    u32     _u32;
    u64     _u64;
    u8      _8u8[8];
    u16     _4u16[4];
    u32     _2u32[2];
    s8      _s8;
    s16     _s16;
    s32     _s32;
    s64     _s64;
    s8      _8s8[8];
    s16     _4s16[4];
    s32     _2s32[2];
    callback_function *void_callback;
    result_callback_function *result_callback;
    void*   _voidp;
    char*   _charp;
    u8*     _u8p;
};

typedef union anytype_u anytype;



typedef ya_result config_set_field_function(const char*, void*, const anytype);

struct config_section_descriptor_s;

/**
 * name is the name of the key, expected in the config file
 * field_offset is the offset of the value from the beginning of the target struct
 * setter is the function able to parse the value of the key and store it at target + offset
 * default_value_string is the string containing the default value for the key
 * function_specific is a parameter given to the setter.  The meaning is different for each setter.
 * source is the level that wrote the current value in the table
 */

struct config_table_descriptor_item_s
{
    const char *name;
    size_t field_offset;
    config_set_field_function *setter;
    const char *default_value_string;
    anytype function_specific;
    size_t expected_size;
    size_t field_size;
    u8 source;
    u8 allocation_mode;
    // help text
};

typedef struct config_table_descriptor_item_s config_table_descriptor_item_s;

typedef ya_result config_section_set_wild_method(struct config_section_descriptor_s *, const char *key, const char *value);
typedef ya_result config_section_print_wild_method(const struct config_section_descriptor_s *, output_stream *os, const char *key);

typedef ya_result config_section_init_method(struct config_section_descriptor_s *);
typedef ya_result config_section_start_method(struct config_section_descriptor_s *);
typedef ya_result config_section_stop_method(struct config_section_descriptor_s *);
typedef ya_result config_section_postprocess_method(struct config_section_descriptor_s *);
typedef ya_result config_section_finalize_method(struct config_section_descriptor_s *);

#define CFGSVTBL_TAG 0x42545653474643

struct config_section_descriptor_vtbl_s
{
    /// section name
    const char                                 *name; // the table name
    config_table_descriptor_item_s            *table; // the descriptor for the table (static fields)
    
    config_section_set_wild_method         *set_wild; // sets an undefined (dynamic) field
    config_section_print_wild_method     *print_wild; // prints an undefined (dynamic) field

    config_section_init_method                 *init; // initialises
    config_section_start_method               *start; // called when a section starts
    config_section_stop_method                 *stop; // called when a section stops
    config_section_postprocess_method   *postprocess; // called after the section has been processed
    config_section_finalize_method         *finalise; // finishes, deletes all memory for this section, this vtbl included (if needed)
};

typedef struct config_section_descriptor_vtbl_s config_section_descriptor_vtbl_s;

#define CFGSDESC_TAG 0x4353454453474643

struct config_section_descriptor_s
{
    void *base; // base of the structure to fill up
    const config_section_descriptor_vtbl_s *vtbl;
};

typedef struct config_section_descriptor_s config_section_descriptor_s;

/**
 * Here are the helper macro used to define the fields in the structure
 * 
 * The definition of the table always be done like this:
 * 
 * struct my_struct_type
 * {
 *      u32 field_name_in_my_struct_type;
 * };
 * 
 * typedef struct my_struct_type my_struct_type;
 * 
 * #define CONFIG_TYPE my_struct_type
 * CONFIG_BEGIN(my_struct_type_table_desc)
 * CONFIG_U32(field_name_in_my_struct_type,default_value_in_text_form)
 * CONFIG_END(my_struct_type_table_desc)
 * #undef CONFIG_TYPE
 * 
 * 
 */

#undef CONFIG_TYPE /* please_define_me */   

#define CONFIG_BEGIN(name_) static /* DO NOT const */ config_table_descriptor_item_s name_[] = {
#define CONFIG_BOOL(fieldname_,defaultvalue_) {#fieldname_,offsetof(CONFIG_TYPE, fieldname_), (config_set_field_function*)config_set_bool, defaultvalue_,{._intptr=0}, sizeof(bool), sizeof(((CONFIG_TYPE*)0)->fieldname_), CONFIG_TABLE_SOURCE_NONE, CONFIG_FIELD_ALLOCATION_DIRECT },
#define CONFIG_FLAG8(fieldname_,defaultvalue_, realfieldname_, mask_) {#fieldname_,offsetof(CONFIG_TYPE, realfieldname_), (config_set_field_function*)config_set_flag8, defaultvalue_,{(u8)(mask_)}, sizeof(u8), sizeof(u8), CONFIG_TABLE_SOURCE_NONE, CONFIG_FIELD_ALLOCATION_DIRECT },
#define CONFIG_FLAG16(fieldname_,defaultvalue_, realfieldname_,mask_) {#fieldname_,offsetof(CONFIG_TYPE, realfieldname_), (config_set_field_function*)config_set_flag16, defaultvalue_,{(u16)(mask_)}, sizeof(u16), sizeof(u16), CONFIG_TABLE_SOURCE_NONE, CONFIG_FIELD_ALLOCATION_DIRECT },
#define CONFIG_FLAG32(fieldname_,defaultvalue_, realfieldname_,mask_) {#fieldname_,offsetof(CONFIG_TYPE, realfieldname_), (config_set_field_function*)config_set_flag32, defaultvalue_,{(u32)(mask_)}, sizeof(u32), sizeof(u32), CONFIG_TABLE_SOURCE_NONE, CONFIG_FIELD_ALLOCATION_DIRECT },
#define CONFIG_FLAG64(fieldname_,defaultvalue_, realfieldname_,mask_) {#fieldname_,offsetof(CONFIG_TYPE, realfieldname_), (config_set_field_function*)config_set_flag64, defaultvalue_,{(u64)(mask_)}, sizeof(u64), sizeof(u64), CONFIG_TABLE_SOURCE_NONE, CONFIG_FIELD_ALLOCATION_DIRECT },
#define CONFIG_U64(fieldname_,defaultvalue_)                 {#fieldname_,offsetof(CONFIG_TYPE, fieldname_), (config_set_field_function*)config_set_u64,       defaultvalue_,{._intptr=0}, sizeof(u64), sizeof(((CONFIG_TYPE*)0)->fieldname_), CONFIG_TABLE_SOURCE_NONE, CONFIG_FIELD_ALLOCATION_DIRECT },
#define CONFIG_U32(fieldname_,defaultvalue_)                 {#fieldname_,offsetof(CONFIG_TYPE, fieldname_), (config_set_field_function*)config_set_u32,       defaultvalue_,{._intptr=0}, sizeof(u32), sizeof(((CONFIG_TYPE*)0)->fieldname_), CONFIG_TABLE_SOURCE_NONE, CONFIG_FIELD_ALLOCATION_DIRECT },
#define CONFIG_S32(fieldname_,defaultvalue_)                 {#fieldname_,offsetof(CONFIG_TYPE, fieldname_), (config_set_field_function*)config_set_s32,       defaultvalue_,{._intptr=0}, sizeof(u32), sizeof(((CONFIG_TYPE*)0)->fieldname_), CONFIG_TABLE_SOURCE_NONE, CONFIG_FIELD_ALLOCATION_DIRECT },
#define CONFIG_U32_RANGE(fieldname_,defaultvalue_,min_,max_) {#fieldname_,offsetof(CONFIG_TYPE, fieldname_), (config_set_field_function*)config_set_u32_range, defaultvalue_,{._2u32={(min_),(max_)}}, sizeof(u32), sizeof(((CONFIG_TYPE*)0)->fieldname_), CONFIG_TABLE_SOURCE_NONE, CONFIG_FIELD_ALLOCATION_DIRECT },
#define CONFIG_U32_CLAMP(fieldname_,defaultvalue_,min_,max_) {#fieldname_,offsetof(CONFIG_TYPE, fieldname_), (config_set_field_function*)config_set_u32_clamp, defaultvalue_,{._2u32={(min_),(max_)}}, sizeof(u32), sizeof(((CONFIG_TYPE*)0)->fieldname_), CONFIG_TABLE_SOURCE_NONE, CONFIG_FIELD_ALLOCATION_DIRECT },
#define CONFIG_U16(fieldname_,defaultvalue_) {#fieldname_,offsetof(CONFIG_TYPE, fieldname_), (config_set_field_function*)config_set_u16, defaultvalue_,{._intptr=0}, sizeof(u16), sizeof(((CONFIG_TYPE*)0)->fieldname_), CONFIG_TABLE_SOURCE_NONE, CONFIG_FIELD_ALLOCATION_DIRECT },
#define CONFIG_DNS_TYPE(fieldname_,defaultvalue_) {#fieldname_,offsetof(CONFIG_TYPE, fieldname_), (config_set_field_function*)config_set_dnstype, defaultvalue_,{._intptr=0}, sizeof(u16), sizeof(((CONFIG_TYPE*)0)->fieldname_), CONFIG_TABLE_SOURCE_NONE, CONFIG_FIELD_ALLOCATION_DIRECT },
#define CONFIG_DNS_CLASS(fieldname_,defaultvalue_) {#fieldname_,offsetof(CONFIG_TYPE, fieldname_), (config_set_field_function*)config_set_dnsclass, defaultvalue_,{._intptr=0}, sizeof(u16), sizeof(((CONFIG_TYPE*)0)->fieldname_), CONFIG_TABLE_SOURCE_NONE, CONFIG_FIELD_ALLOCATION_DIRECT },
#define CONFIG_U8(fieldname_,defaultvalue_) {#fieldname_,offsetof(CONFIG_TYPE, fieldname_), (config_set_field_function*)config_set_u8, defaultvalue_,{._intptr=0}, sizeof(u8), sizeof(((CONFIG_TYPE*)0)->fieldname_), CONFIG_TABLE_SOURCE_NONE, CONFIG_FIELD_ALLOCATION_DIRECT },
#define CONFIG_DNSKEY_ALGORITHM(fieldname_,defaultvalue_) {#fieldname_,offsetof(CONFIG_TYPE, fieldname_), (config_set_field_function*)config_set_dnskey_algorithm, defaultvalue_,{._intptr=0}, sizeof(u8), sizeof(((CONFIG_TYPE*)0)->fieldname_), CONFIG_TABLE_SOURCE_NONE, CONFIG_FIELD_ALLOCATION_DIRECT },
#define CONFIG_U8_INC(fieldname_) {#fieldname_,offsetof(CONFIG_TYPE, fieldname_), (config_set_field_function*)config_inc_u8, 0,{._intptr=0}, sizeof(u8), sizeof(((CONFIG_TYPE*)0)->fieldname_), CONFIG_TABLE_SOURCE_NONE, CONFIG_FIELD_ALLOCATION_DIRECT },
#define CONFIG_STRING(fieldname_,defaultvalue_) {#fieldname_,offsetof(CONFIG_TYPE, fieldname_), (config_set_field_function*)config_set_string, defaultvalue_,{._intptr=0}, sizeof(char*), sizeof(((CONFIG_TYPE*)0)->fieldname_), CONFIG_TABLE_SOURCE_NONE, CONFIG_FIELD_ALLOCATION_DIRECT },
#define CONFIG_STRING_COPY(fieldname_,defaultvalue_) {#fieldname_,offsetof(CONFIG_TYPE, fieldname_), (config_set_field_function*)config_set_string_copy, defaultvalue_,{._u32=(sizeof(((CONFIG_TYPE*)NULL)->fieldname_))}, sizeof(((CONFIG_TYPE*)NULL)->fieldname_), sizeof(((CONFIG_TYPE*)0)->fieldname_), CONFIG_TABLE_SOURCE_NONE, CONFIG_FIELD_ALLOCATION_DIRECT },
#define CONFIG_STRING_ARRAY(fieldname_,default_value_,max_size_) {#fieldname_,offsetof(CONFIG_TYPE, fieldname_), (config_set_field_function*)config_append_string_array_item, default_value_,{._u32=(max_size_)}, sizeof(ptr_vector), sizeof(((CONFIG_TYPE*)0)->fieldname_), CONFIG_TABLE_SOURCE_NONE, CONFIG_FIELD_ALLOCATION_DIRECT },
#define CONFIG_PASSWORD(fieldname_,defaultvalue_) {#fieldname_,offsetof(CONFIG_TYPE, fieldname_), (config_set_field_function*)config_set_password, defaultvalue_,{._intptr=0}, sizeof(char*), sizeof(((CONFIG_TYPE*)0)->fieldname_), CONFIG_TABLE_SOURCE_NONE, CONFIG_FIELD_ALLOCATION_DIRECT },
#define CONFIG_FQDN(fieldname_,defaultvalue_) {#fieldname_,offsetof(CONFIG_TYPE, fieldname_), (config_set_field_function*)config_set_fqdn, defaultvalue_,{._intptr=0}, sizeof(u8*), sizeof(((CONFIG_TYPE*)0)->fieldname_), CONFIG_TABLE_SOURCE_NONE, CONFIG_FIELD_ALLOCATION_MALLOC },
#define CONFIG_PATH(fieldname_,defaultvalue_) {#fieldname_,offsetof(CONFIG_TYPE, fieldname_), (config_set_field_function*)config_set_path, defaultvalue_,{._intptr=0}, sizeof(char*), sizeof(((CONFIG_TYPE*)0)->fieldname_), CONFIG_TABLE_SOURCE_NONE, CONFIG_FIELD_ALLOCATION_DIRECT },
#define CONFIG_CHROOT(fieldname_,defaultvalue_) {#fieldname_,offsetof(CONFIG_TYPE, fieldname_), (config_set_field_function*)config_set_chroot, defaultvalue_,{._intptr=0}, sizeof(char*), sizeof(((CONFIG_TYPE*)0)->fieldname_), CONFIG_TABLE_SOURCE_NONE, CONFIG_FIELD_ALLOCATION_DIRECT },
#define CONFIG_LOGPATH(fieldname_,defaultvalue_) {#fieldname_,offsetof(CONFIG_TYPE, fieldname_), (config_set_field_function*)config_set_logpath, defaultvalue_,{._intptr=0}, sizeof(char*), sizeof(((CONFIG_TYPE*)0)->fieldname_), CONFIG_TABLE_SOURCE_NONE, CONFIG_FIELD_ALLOCATION_DIRECT },
#define CONFIG_FILE(fieldname_,defaultvalue_) {#fieldname_,offsetof(CONFIG_TYPE, fieldname_), (config_set_field_function*)config_set_file, defaultvalue_,{._intptr=0}, sizeof(char*), sizeof(((CONFIG_TYPE*)0)->fieldname_), CONFIG_TABLE_SOURCE_NONE, CONFIG_FIELD_ALLOCATION_DIRECT },
#define CONFIG_UID(fieldname_,defaultvalue_) {#fieldname_,offsetof(CONFIG_TYPE, fieldname_), (config_set_field_function*)config_set_uid_t, defaultvalue_,{._intptr=0}, sizeof(uid_t), sizeof(((CONFIG_TYPE*)0)->fieldname_), CONFIG_TABLE_SOURCE_NONE, CONFIG_FIELD_ALLOCATION_DIRECT },
#define CONFIG_GID(fieldname_,defaultvalue_) {#fieldname_,offsetof(CONFIG_TYPE, fieldname_), (config_set_field_function*)config_set_gid_t, defaultvalue_,{._intptr=0}, sizeof(gid_t), sizeof(((CONFIG_TYPE*)0)->fieldname_), CONFIG_TABLE_SOURCE_NONE, CONFIG_FIELD_ALLOCATION_DIRECT },
//#define CONFIG_ACL(fieldname_,defaultvalue_) {#fieldname_,offsetof(CONFIG_TYPE, ac) + offsetof(access_control,fieldname_), (config_set_field_function*)config_set_acl_item, defaultvalue_,{._intptr=0}, sizeof(), sizeof(((CONFIG_TYPE*)0)->fieldname_), CONFIG_TABLE_SOURCE_NONE, CONFIG_FIELD_ALLOCATION_DIRECT },
//#define CONFIG_ACL_FILTER(fieldname_,defaultvalue_) {#fieldname_,offsetof(CONFIG_TYPE, fieldname_), (config_set_field_function*)config_set_acl_item, defaultvalue_,{._intptr=0}, sizeof(), sizeof(((CONFIG_TYPE*)0)->fieldname_), CONFIG_TABLE_SOURCE_NONE, CONFIG_FIELD_ALLOCATION_DIRECT },
//#define CONFIG_LIST_ITEM(fieldname_,defaultvalue_) {#fieldname_,offsetof(CONFIG_TYPE, fieldname_), (config_set_field_function*)config_add_list_item, defaultvalue_,{._intptr=0}, sizeof(), sizeof(((CONFIG_TYPE*)0)->fieldname_), CONFIG_TABLE_SOURCE_NONE, CONFIG_FIELD_ALLOCATION_DIRECT },
#define CONFIG_ENUM(fieldname_,defaultvalue_,enumtable_) {#fieldname_,offsetof(CONFIG_TYPE, fieldname_), (config_set_field_function*)config_set_enum_value, defaultvalue_, {(intptr)(enumtable_)}, sizeof(u32), sizeof(((CONFIG_TYPE*)0)->fieldname_), CONFIG_TABLE_SOURCE_NONE, CONFIG_FIELD_ALLOCATION_DIRECT },
//#define CONFIG_ENUM8(fieldname_,defaultvalue_,enumtable_) {#fieldname_,offsetof(CONFIG_TYPE, fieldname_), (config_set_field_function*)config_set_enum8_value, defaultvalue_, {(intptr)enumtable_}, sizeof(u8), sizeof(((CONFIG_TYPE*)0)->fieldname_), CONFIG_TABLE_SOURCE_NONE, CONFIG_FIELD_ALLOCATION_DIRECT },
#define CONFIG_HOST_LIST(fieldname_,defaultvalue_) {#fieldname_, offsetof(CONFIG_TYPE, fieldname_), (config_set_field_function*)config_set_host_list, defaultvalue_,{._8u8={CONFIG_HOST_LIST_FLAGS_DEFAULT,255,0,0,0,0,0,0}}, sizeof(host_address*), sizeof(((CONFIG_TYPE*)0)->fieldname_), CONFIG_TABLE_SOURCE_NONE, CONFIG_FIELD_ALLOCATION_DIRECT },
#define CONFIG_HOST_LIST_EX(fieldname_,defaultvalue_,flags_,host_list_max_) {#fieldname_, offsetof(CONFIG_TYPE, fieldname_), (config_set_field_function*)config_set_host_list, defaultvalue_,{._8u8={(flags_),(host_list_max_),0,0,0,0,0,0}}, sizeof(host_address*), sizeof(((CONFIG_TYPE*)0)->fieldname_), CONFIG_TABLE_SOURCE_NONE, CONFIG_FIELD_ALLOCATION_DIRECT },
#define CONFIG_BYTES(fieldname_,defaultvalue_,maxsize_) {#fieldname_, offsetof(CONFIG_TYPE, fieldname_), (config_set_field_function*)config_set_bytes, defaultvalue_, {maxsize_}, maxsize_, sizeof(((CONFIG_TYPE*)0)->fieldname_), CONFIG_TABLE_SOURCE_NONE, CONFIG_FIELD_ALLOCATION_DIRECT },
//#define CONFIG_DNSSEC(fieldname_,defaultvalue_) {#fieldname_,offsetof(CONFIG_TYPE, fieldname_), (config_set_field_function*)config_set_dnssec, defaultvalue_,{._intptr=0}, sizeof(), sizeof(((CONFIG_TYPE*)0)->fieldname_), CONFIG_TABLE_SOURCE_NONE, CONFIG_FIELD_ALLOCATION_DIRECT },
#define CONFIG_TSIG_ITEM(fieldname_,defaultvalue_) {#fieldname_, offsetof(CONFIG_TYPE, fieldname_), (config_set_field_function*)config_set_tsig_item, defaultvalue_, {._intptr=0}, sizeof(struct tsig_item*), sizeof(((CONFIG_TYPE*)0)->fieldname_), CONFIG_TABLE_SOURCE_NONE, CONFIG_FIELD_ALLOCATION_DIRECT },
#define CONFIG_OBSOLETE(fieldname_) {#fieldname_,0, (config_set_field_function*)config_set_obsolete, NULL,{._intptr=0}, 0, 0, CONFIG_TABLE_SOURCE_NONE, CONFIG_FIELD_ALLOCATION_DIRECT },

#define CONFIG_ALIAS(fieldname_, aliasedname_) {#fieldname_, 0, NULL, #aliasedname_, {._intptr=0}, 0, 0, CONFIG_TABLE_SOURCE_NONE, CONFIG_FIELD_ALLOCATION_DIRECT},
    /*#define CONFIG_CATEGORY(fieldname_, category_) {#fieldname_, 0, NULL, NULL, #category},*/

#define CONFIG_END(name_) {NULL,0,NULL,NULL, {._intptr=0}, 0, 0, CONFIG_TABLE_SOURCE_NONE, CONFIG_FIELD_ALLOCATION_DIRECT} }; // name_

struct tsig_item;

ya_result config_set_bool(const char *value, bool *dest, const anytype notused);
ya_result config_set_flag8(const char *value, u8 *dest, const anytype mask8);
ya_result config_set_flag16(const char *value, u16 *dest, const anytype mask16);
ya_result config_set_flag32(const char *value, u32 *dest, const anytype mask32);
ya_result config_set_flag64(const char *value, u64 *dest, const anytype mask64);
ya_result config_set_u64(const char *value,u64 *dest, const anytype notused);
ya_result config_set_u32(const char *value,u32 *dest, const anytype notused);
ya_result config_set_s32(const char *value,s32 *dest, const anytype notused);
ya_result config_set_u32_range(const char *value,u32 *dest, const anytype min_max);
ya_result config_set_u16(const char *value,u16 *dest, const anytype notused);
ya_result config_set_u8(const char *value,u8 *dest, const anytype notused);
ya_result config_inc_u8(const char *value_notused,u8 *dest, const anytype notused);
ya_result config_set_dnskey_algorithm(const char *value, u8 *dest, const anytype notused);
ya_result config_set_string(const char *value, char **dest, const anytype notused);
ya_result config_set_string_copy(const char *value, char *dest, const anytype maxlen);
ya_result config_append_string_array_item(const char *value, ptr_vector *dest, const anytype maxsize);
ya_result config_set_password(const char *value, char **dest, const anytype notused);
ya_result config_set_fqdn(const char *value, u8 **dest, const anytype notused);
ya_result config_set_path(const char *value, char **dest, const anytype notused);
ya_result config_set_chroot(const char *value, char **dest, const anytype notused);
ya_result config_set_logpath(const char *value, char **dest, const anytype notused);
ya_result config_set_file(const char *value, char **dest, const anytype notused);
ya_result config_set_uid_t(const char *value, uid_t *dest, const anytype notused);
ya_result config_set_gid_t(const char *value, gid_t *dest, const anytype notused);
ya_result config_set_dnstype(const char *value, u16 *dest, const anytype notused);
ya_result config_set_dnsclass(const char *value, u16 *dest, const anytype notused);
ya_result config_set_enum_value(const char *value, u32 *dest, const anytype enum_value_name_table);
ya_result config_set_enum8_value(const char *value, u8 *dest, const anytype enum_value_name_table);
ya_result config_set_host_list(const char *value, host_address **dest, const anytype notused);
ya_result config_set_bytes(const char *value, void *dest, const anytype sizeoftarget);
ya_result config_set_tsig_item(const char *value, struct tsig_item **dest, const anytype notused);
ya_result config_set_obsolete(const char *value, void *dest, const anytype sizeoftarget);

// life of the config processing

void config_init_error_codes();

struct config_error_s
{
    const char *variable_name;
    u32 line_number;
    bool has_content;
    char line[256];
    char file[PATH_MAX];
};

typedef struct config_error_s config_error_s;

static inline void config_error_reset(config_error_s* cfgerr)
{
    if(cfgerr != NULL)
    {
        cfgerr->variable_name = "";
        cfgerr->line_number = 0;
        cfgerr->has_content = FALSE;
        cfgerr->line[0] = '\0';
        cfgerr->file[0] = '\0';
    }
}

#define CONFIG_ERROR_INITIALISER { NULL, 0, "?", "?"}

struct config_source_s;

typedef ya_result config_source_provider_callback_function(struct config_source_s *source, input_stream *out_source, config_error_s *cfgerr);

struct config_source_file_name_s
{
    const char* name;
};

struct config_source_buffer_s
{
    const char* text;
    u32 size;
};

/**
 * An help tool to register many sources at once
 */

struct config_source_s
{
    config_source_provider_callback_function *get_source;
    const char *name;
    const char *__class__;
    union
    {
        struct config_source_file_name_s file_name;
        struct config_source_buffer_s buffer;
    } source;
    u8 level;
};

#ifdef TODO
struct config_s
{
    u32_set section_descriptor_set = U32_SET_EMPTY;
}:
#endif

ya_result config_init();

/**
 * Configuration:
 * 
 * priority : the lowest value, the fastest to be parsed 
 *            negative value : choose
 *
 * level    : ex: 0 for none, 1 for default, 2 for config, 3 for command line
 *           command line has priority on everything else
 */

/**
 * Gets the current source level
 * @return the current source level
 */

u8 config_get_source();

/**
 * Sets the current source level
 * 
 * @param l the current source level
 */

void config_set_source(u8 l);

/**
 * If the source level has been parsed, automatically fill the default values
 * for fields that are not set yet.
 * 
 * @return after what level do we automatically set the default values in the container
 */

u8 config_get_autodefault_after_source();

/**
 * If the source level has been parsed, automatically fill the default values
 * for fields that are not set yet.
 * 
 * @param l after what level do we automatically set the default values in the container ?
 */

void config_set_autodefault_after_source(u8 l); // if a configuration is read at this level, the default is automatically applied after

/**
 * Gets the default source level
 * 
 * @return the default source level
 */

u8 config_get_default_source();

/**
 * Sets the default source level (default = 1)
 * 
 * @param l the default source level
 */

void config_set_default_source(u8 l);           // this level is meant for default (1)

#define CONFIG_CALLBACK_RESULT_CONTINUE 0
#define CONFIG_CALLBACK_RESULT_STOP     1

typedef ya_result config_callback_function(const char *section_name, int section_index);

/**
 * Adds a callback called when a section has been read
 * 
 * @param section_name the name of the section
 * @param on_section_read the function to call
 *
 *  * @return continue, stop or an error code to fail
 */

ya_result config_add_on_section_read_callback(const char *section_name, config_callback_function *on_section_read);

/**
 * Removes a callback called when a section has been read
 * 
 * @param section_name the name of the section
 * @param on_section_read the function to call
 *
 * @return continue, stop or an error code to fail
 */

ya_result config_remove_on_section_read_callback(const char *section_name, config_callback_function *on_section_read);

/**
 * Registers a descriptor at the given priority
 * 
 * @param section_descritor config descriptor
 * @param priority config priority
 * 
 * @return an error code
 */

ya_result config_register(config_section_descriptor_s *section_descritor, s32 priority);

ya_result config_register_const(const config_section_descriptor_s *section_descriptor, s32 priority);

ya_result config_unregister(config_section_descriptor_s *section_descriptor);

config_section_descriptor_s *config_unregister_by_name(const char *name);

/**
 * 
 * Reads matching section/containers from a file on disk
 * 
 * @param configuration_file_path the file path
 * @param cfgerr error handling structure (can be NULL)
 * @param section_name the name to match, or if NULL : all sections
 * 
 * @return an error code
 */

ya_result config_read_section(const char *configuration_file_path, config_error_s *cfgerr, const char *section_name);

/**
 * Reads all sections/containers from a file
 * 
 * @param configuration_file_path the file path
 * @param cfgerr if not NULL, the error reporting structure
 * 
 * @return an error code
 */

ya_result config_read(const char *configuration_file_path, config_error_s *cfgerr);

/**
 * Reads all sections/containers from a buffer
 * 
 * @param buffer the text buffer
 * @param buffer_len the text buffer length
 * @param buffer_name the name of the buffer for error reporting
 * @param cfgerr if not NULL, the error reporting structure
 * 
 * @return an error code
 */

ya_result config_read_from_buffer(const char *buffer, u32 buffer_len, const char *buffer_name, config_error_s *cfgerr);

/**
 * Sets a text buffer in a source
 * 
 * @param source the source struct to initialise
 * @param name the name of the source
 * @param level the level of the source
 * @param buffer text for the source
 * @param buffer_len text length for the source
 */

void config_source_set_buffer(struct config_source_s *source, const char *name, u8 level, const char *buffer, u32 buffer_len);

/**
 * Sets a file in a source
 * 
 * @param source the source struct to initialise
 * @param name the name of the file
 * @param level the level of the source
 */

void config_source_set_file(struct config_source_s *source, const char *name, u8 level);

ya_result config_source_set_commandline(struct config_source_s *source, const cmdline_desc_s *cmdline, int argc, char **argv);

/**
 * Read all sources from a table
 * 
 * @param sources a pointer to the first source
 * @param sources_count the number of sources
 * @param cfgerr if not NULL, the error reporting structure
 * 
 * @return an error code
 */

ya_result config_read_from_sources(struct config_source_s *sources, u32 sources_count, config_error_s *cfgerr);

/**
 * Applies default values to uninitialised fields. * @param cfgerr
 * 
 * @param cfgerr if not NULL, the error reporting structure
 * 
 * @return an error code
 */

ya_result config_set_default(config_error_s *cfgerr);

/**
 * Gets the section descriptor for the section/container name
 * 
 * @param name the name of the section descriptor
 * 
 * @return a pointer to the section descriptor or NULL if not found
 */

config_section_descriptor_s *config_section_get_descriptor(const char *name);

/**
 * Sets the table default values
 * 
 * @param section_descriptor the descriptor to use (points to the table)
 * @param cfgerr if not NULL, the error reporting structure
 * 
 * @return an error code
 */

ya_result config_set_section_default(config_section_descriptor_s *section_descriptor, config_error_s *cfgerr);


/**
 * Sets the key to a value
 * Source level is taken into account.
 * ie: config_value_set(&yadifa_config_main_desc, "daemon", "on");
 * 
 * @param section_descriptor the descriptor pointing to the table
 * @param key the key to set
 * @param value to value to set it to
 * @param cfgerr a structure that contains details about an error
 * 
 * @return an error code
 */

ya_result config_value_set(config_section_descriptor_s *section_descriptor, const char *key, const char *value, config_error_s *cfgerr);

ya_result config_source_set_by_target(config_section_descriptor_s *section_descriptor, void *target_ptr);

/**
 * 
 * Sets the key of the section/container to its default value
 * 
 * @param section_name name of the section
 * @param name key of the value
 * @param cfgerr if not NULL, the error reporting structure
 * 
 * @return an error code
 */

ya_result config_value_set_to_default(const char *section_name, const char *name, config_error_s *cfgerr);

/**
 *
 * Returns the source of a value from the given section/container
 *
 * Look at CONFIG_SOURCE_* defines above for the predefined sources.
 *
 * @param section_name name of the section
 * @param name key of the value
 *
 * @return the source index or an error code
 */

ya_result config_value_get_source(const char *section_name, const char *name);

typedef bool config_section_struct_type_handler(output_stream *os, const char *name, void *ptr);

bool config_section_struct_register_type_handler(config_set_field_function* setter, config_section_struct_type_handler *handler);

/**
 * 
 * Prints the content of every supported types of the table using the descriptor
 * 
 * @param section_descriptor the descriptor
 * @param os where to print to
 */

void config_section_print(const config_section_descriptor_s *section_descriptor, output_stream *os);

/**
 * 
 * Prints the content of every supported types of the table using the given descriptor on the given struct
 * 
 * @param section_descriptor the descriptor
 * @param a pointer to the config struct base
 * @param os where to print to
 */

void config_section_struct_print(const config_section_descriptor_s *section_descriptor, const void* configbase, output_stream *os);

/**
 * 
 * Gets the index of the key on the table
 * 
 * @param table a config table
 * @param name the field key name
 *
 * @return an error code
 */

ya_result config_item_index_get(const config_table_descriptor_item_s *table, const char *name);

/**
 * Prints the config to the output stream
 * 
 * @param os the output stream
 */

void config_print(output_stream *os);

/**
 * Call the postproces callback on the registered tables
 */

ya_result config_postprocess();

/**
 * Call the finalise callback on the registered tables
 * 
 */

ya_result config_finalize();

// helpers

typedef void *config_section_struct_collection_get_next_method(void *previous_data_struct);

/**
 * 
 * Registers a struct with its descriptor and name, for configuration.
 * 
 * @param name name of the struct
 * @param table table describing the struct
 * @param data_struct pointer to the struct
 * @param priority priority level (order of read)
 * 
 * @return an error code
 */

ya_result config_register_struct(const char *name, config_table_descriptor_item_s *table, void *data_struct, s32 priority);

void* config_unregister_struct(const char *name, const config_table_descriptor_item_s *table);

/**
 * 
 * Registers the logger configuration.
 * 
 * @note logger_handle_create("handle-name",logger_handle_for_handle_name_ptr_ptr) MUST be called
 *        before the config_read is done
 * 
 * @param null_or_channels_name
 * @param null_or_loggers_name
 * @param priority
 * 
 * @return an error code
 */

ya_result config_register_logger(const char *null_or_channels_name, const char *null_or_loggers_name, s32 priority);

/**
 * Returns TRUE iff any logging section has been found.
 * 
 * @return TRUE iff any logging section has been found.
 */

bool config_logger_isconfigured();

/**
 * Clears the logger-configured flag
 */

void config_logger_clearconfigured();

/**
 * Sets the base path for the logger
 * 
 * @param null_or_key_name
 * @param priority
 * @return 
 */

void config_set_log_base_path(const char *path);

/**
 * Registers the key configuration (TSIG)
 * 
 * @param null_or_key_name
 * @param priority
 * @return 
 */
ya_result config_register_key(const char *null_or_key_name, s32 priority);

/** @} */
