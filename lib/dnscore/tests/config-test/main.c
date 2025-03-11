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

#include "yatest.h"
#include "yatest_stream.h"
#include "dnscore/format.h"
#include <dnscore/dnscore.h>
#include <dnscore/config_settings.h>
#include <dnscore/config_cmdline.h>
#include <dnscore/tsig.h>

#define TEST_DIR             "/tmp/config-test"
#define TEST_CONFIG_FILE     TEST_DIR "/config.conf"
#define TEST_CONFIG2_FILE    TEST_DIR "/config2.conf"
#define STRING_VALUE         "Hello World"
#define STRING_COPY_VALUE    "Hello World too"
#define STRING_ARRAY_0_VALUE "First"
#define STRING_ARRAY_1_VALUE "Second"
#define PASSWORD_VALUE       "mypassword"
#define FQDN_VALUE           "www.yadifa.eu"
#define PATH_VALUE           TEST_DIR
#define CHROOT_VALUE         TEST_DIR "/chroot"
#define LOGPATH_VALUE        TEST_DIR "/log"
#define UID_VALUE            "root"
#define UID_VALUE_INT        0
#if !__FreeBSD__
#define GID_VALUE "root"
#else
#define GID_VALUE "wheel"
#endif
#define GID_VALUE_INT                      0
#define FILE_VALUE                         TEST_CONFIG_FILE
#define FILE2_VALUE                        TEST_CONFIG2_FILE
#define TEST_INCLUDED_CONFIG_FILE          TEST_DIR "/config-included.conf"
#define TEST_INCLUDED_CONFIG_FILE_RELATIVE "config-included.conf"

#define MYKEY_NAME                         (const uint8_t *)"\005mykey"
#define NOTMYKEY_NAME                      (const uint8_t *)"\010notmykey"

struct kv_s
{
    char *key;
    char *value;
};

typedef struct kv_s  kv_t;

static ya_result     kv_config_set_field_function(const char *value, kv_t *dest, anytype notused);

static const uint8_t mykey_mac[] = {0x81, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
static const uint8_t notmykey_mac[] = {0x91, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};

struct config_test_s
{
    bool            _bool;
    uint8_t         _flag8;
    uint16_t        _flag16;
    uint32_t        _flag32;
    uint64_t        _flag64;
    uint64_t        _u64;
    uint32_t        _u32;
    uint16_t        _u16;
    uint8_t         _u8;
    int32_t         _s32;
    uint32_t        _u32_range;
    uint32_t        _u32_clamp;
    uint16_t        _dns_type;
    uint16_t        _dns_class;
    uint8_t         _dnskey_algorithm;
    uint8_t         _u8_inc;
    char           *_string;
    char            _string_copy[64];
    ptr_vector_t    _string_array;
    char           *_password;
    uint8_t        *_fqdn;
    char           *_path;
    char           *_chroot;
    char           *_logpath;
    char           *_file;
    uid_t           _uid;
    gid_t           _gid;
    int             _enum;
    uint8_t         _enum8;
    host_address_t *_host_list;
    host_address_t *_host_list_append;
    host_address_t *_host_list_fqdn;
    host_address_t *_host_list_v4;
    host_address_t *_host_list_v6;
    host_address_t *_host_list_ex;
    uint8_t         _bytes[64];
    tsig_key_t     *_tsig_item;
    kv_t            _kv;
    uint64_t        _included_u64;
};

typedef struct config_test_s config_test_t;

static value_name_table_t    test_enum[] = {{0, "zero"}, {1, "one"}, {2, "two"}, {0, NULL}};

#define FLAG_0      1
#define FLAG_1      2

#define CONFIG_TYPE config_test_t

CONFIG_BEGIN(config_test_desc)
CONFIG_BOOL(_bool, "0")
CONFIG_FLAG8(bit0, "0", _flag8, FLAG_0)
CONFIG_FLAG16(bit1, "0", _flag16, FLAG_0)
CONFIG_FLAG32(bit2, "0", _flag32, FLAG_0)
CONFIG_FLAG64(bit3, "0", _flag64, FLAG_0)
CONFIG_U64(_u64, "0")
CONFIG_U32(_u32, "0")
CONFIG_U16(_u16, "0")
CONFIG_U8(_u8, "0")
CONFIG_S32(_s32, "0")
CONFIG_U32_RANGE(_u32_range, "1", 1, 254)
CONFIG_U32_CLAMP(_u32_clamp, "1", 1, 254)
CONFIG_DNS_TYPE(_dns_type, "A")
CONFIG_DNS_CLASS(_dns_class, "IN")
CONFIG_DNSKEY_ALGORITHM(_dnskey_algorithm, "RSASHA512")
CONFIG_U8_INC(_u8_inc)
CONFIG_STRING(_string, "0")
CONFIG_STRING_COPY(_string_copy, "0")
CONFIG_STRING_ARRAY(_string_array, NULL, 4)
CONFIG_PASSWORD(_password, "0")
CONFIG_FQDN(_fqdn, "0")
CONFIG_PATH(_path, "0")
CONFIG_CHROOT(_chroot, "/tmp")
CONFIG_LOGPATH(_logpath, "/tmp")
CONFIG_FILE(_file, TEST_CONFIG2_FILE)
CONFIG_UID(_uid, "1000")
CONFIG_GID(_gid, "1000")
CONFIG_ENUM(_enum, "zero", test_enum)
CONFIG_ENUM8(_enum8, "zero", test_enum)
CONFIG_HOST_LIST(_host_list, "127.0.0.1")
CONFIG_HOST_LIST_EX(_host_list_append, "", CONFIG_HOST_LIST_FLAGS_DEFAULT | CONFIG_HOST_LIST_FLAGS_APPEND, 4)
CONFIG_HOST_LIST_EX(_host_list_fqdn, "", CONFIG_HOST_LIST_FLAGS_DEFAULT | CONFIG_HOST_LIST_FLAGS_FQDN, 4)
CONFIG_HOST_LIST_EX(_host_list_v4, "", CONFIG_HOST_LIST_FLAGS_IPV4, 4)
CONFIG_HOST_LIST_EX(_host_list_v6, "", CONFIG_HOST_LIST_FLAGS_IPV6, 4)
CONFIG_HOST_LIST_EX(_host_list_ex, "127.0.1.0", CONFIG_HOST_LIST_FLAGS_DEFAULT, 4)
CONFIG_BYTES(_bytes, "SGVsbG8gV29ybGQgZGVmYXVsdAo=", sizeof(((config_test_t *)NULL)->_bytes))
CONFIG_TSIG_ITEM(_tsig_item, NULL)
CONFIG_CUSTOM_HANDLER(_kv, "(0,0)", kv_t, kv_config_set_field_function)
CONFIG_U64(_included_u64, "87654321")
CONFIG_OBSOLETE(_obsolete)
CONFIG_END(config_test_desc)

CONFIG_BEGIN(config_test_error_desc)
CONFIG_BOOL(_u64, "1") // fails because the size of _u64 doesn't match the size of a bool
CONFIG_END(config_test_error_desc)

CONFIG_BEGIN(config_test_bad_defaultdesc)
CONFIG_BOOL(_bool, "azerty")   // fails because can't be parsed as a bool
CONFIG_U64(_u64, "notanumber") // fails because can't be parsed as an unsigned 64 bits integer
CONFIG_END(config_test_bad_defaultdesc)

static char config_test_conf[] =
    "#\n"
    "# configuration file for lib/dnscore/tests/config-test \n"
    "#\n"
    "<config>\n"
    "# config section with a sample of every base type\n"
    "_bool 1\n"
    "bit0 1\n"
    "bit1 1\n"
    "bit2 1\n"
    "bit3 1\n"
    "_u64 1\n"
    "_u32 1\n"
    "_u16 1\n"
    "_u8 1\n"
    "_s32 1\n"
    "_u32_range 16\n"
    "_u32_clamp 16\n"
    "_dns_type AAAA\n"
    "_dns_class CH\n"
    "_dnskey_algorithm RSASHA256\n"
    "_u8_inc 1\n"
    "_string '" STRING_VALUE
    "'\n"
    "_string_copy '" STRING_COPY_VALUE
    "'\n"
    "_string_array '" STRING_ARRAY_0_VALUE
    "'\n"
    "_string_array '" STRING_ARRAY_1_VALUE
    "'\n"
    "_password '" PASSWORD_VALUE
    "'\n"
    "_fqdn '" FQDN_VALUE
    "'\n"
    "_path " PATH_VALUE
    "\n"
    "_chroot " CHROOT_VALUE
    "\n"
    "_logpath " LOGPATH_VALUE
    "\n"
    "_file " FILE_VALUE
    "\n"
    "_uid " UID_VALUE
    "\n"
    "_gid " GID_VALUE
    "\n"
    "_enum one\n"
    "_enum8 one\n"
    "_host_list 127.0.0.2\n"
    "_host_list_ex 127.0.0.3;127.0.0.4\n"
    "_bytes SGVsbG8gV29ybGQK\n"
    // tsig_key_t *_tsig_item;
    "</config>\n"
    "include " TEST_INCLUDED_CONFIG_FILE_RELATIVE "\n";

static char config_test_conf_absolute[] =
    "<config>\n"
    "_bool 1\n"
    "bit0 1\n"
    "bit1 1\n"
    "bit2 1\n"
    "bit3 1\n"
    "_u64 1\n"
    "_u32 1\n"
    "_u16 1\n"
    "_u8 1\n"
    "_s32 1\n"
    "_u32_range 16\n"
    "_u32_clamp 16\n"
    "_dns_type AAAA\n"
    "_dns_class CH\n"
    "_dnskey_algorithm RSASHA256\n"
    "_u8_inc 1\n"
    "_string '" STRING_VALUE
    "'\n"
    "_string_copy '" STRING_COPY_VALUE
    "'\n"
    "_string_array '" STRING_ARRAY_0_VALUE
    "'\n"
    "_string_array '" STRING_ARRAY_1_VALUE
    "'\n"
    "_password '" PASSWORD_VALUE
    "'\n"
    "_fqdn '" FQDN_VALUE
    "'\n"
    "_path " PATH_VALUE
    "\n"
    "_chroot " CHROOT_VALUE
    "\n"
    "_logpath " LOGPATH_VALUE
    "\n"
    "_file " FILE_VALUE
    "\n"
    "_uid " UID_VALUE
    "\n"
    "_gid " GID_VALUE
    "\n"
    "_enum one\n"
    "_enum8 one\n"
    "_host_list 127.0.0.2\n"
    "_host_list_ex 127.0.0.3;127.0.0.4\n"
    "_bytes SGVsbG8gV29ybGQK\n"
    // tsig_key_t *_tsig_item;
    "</config>\n"
    "include " TEST_INCLUDED_CONFIG_FILE "\n";

static char config_test_include_conf[] =
    "<config>\n"
    "_included_u64 12345678\n"
    "</config>";

static char config_test_2_conf[] =
    "<config>\n"
    "_u64 2\n"
    "_u32 2\n"
    "</config>\n";

static char config_test_empty_tag_begin_conf[] = "<>\n";

static char config_test_empty_tag_end_conf[] =
    "<config>\n"
    "_u64 3\n"
    "<>\n";

static char config_test_tag_notclosed_conf[] = "<notclosed\n";

static char config_test_tag_nested_conf[] =
    "<config>\n"
    "<nested>\n"
    "</config>\n";

static char config_test_no_open_close_conf[] = "</config>\n";

static char config_test_wrong_close_conf[] =
    "<config>\n"
    "</notconfig>\n";

static char config_test_tag_toobig_begin_conf[] =
    "<"
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" // 64
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" // 128
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" // 194
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" // 256
    "-overflow"
    ">\n"
    "</"
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" // 64
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" // 128
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" // 194
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" // 256
    "-overflow"
    ">\n";

static char config_test_tag_toobig_end_conf[] =
    "<"
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" // 64
    ">\n"
    "</"
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" // 64
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" // 128
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" // 194
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" // 256
    "-overflow"
    ">\n";

static char config_test_include_nopath_conf[] = "include\n";

CMDLINE_BEGIN(config_cmdline)
CMDLINE_SECTION("config")
CMDLINE_OPT("u64", 'u', "_u64")
CMDLINE_HELP("", "sets the value of the _u64 field")
CMDLINE_VERSION_HELP(config_cmdline)
CMDLINE_END(config_cmdline)

static char         *config_test_argv[] = {"/tmp/myprogram", "--u64", "3", NULL};

static char         *config_test_argv_bad[] = {"/tmp/myprogram", "--no-such-argument", "whatever", NULL};

static char         *config_test_argv_help[] = {"/tmp/myprogram", "--help", "--version", NULL};

static const int     config_test_argc = 3;

static config_test_t g_config;

static void          tsig_init()
{
    int ret;
    ret = tsig_register(MYKEY_NAME, mykey_mac, sizeof(mykey_mac), HMAC_SHA1);
    if(FAIL(ret))
    {
        yatest_err("xfr_query_tsig_enable failed with %i/%08x (mykey)", ret, ret);
        exit(1);
    }
    ret = tsig_register(NOTMYKEY_NAME, notmykey_mac, sizeof(notmykey_mac), HMAC_SHA1);
    if(FAIL(ret))
    {
        yatest_err("xfr_query_tsig_enable failed with %i/%08x (notmykey)", ret, ret);
        exit(1);
    }
}

static void filedir_init()
{
    yatest_mkdir(TEST_DIR);
    yatest_mkdir(CHROOT_VALUE);
    yatest_mkdir(LOGPATH_VALUE);
    // note: the -1 is important else the NUL char is written at the end, which breaks the parser
    yatest_file_create_with(TEST_CONFIG_FILE, config_test_conf, sizeof(config_test_conf) - 1);
    yatest_file_create_with(TEST_CONFIG2_FILE, config_test_conf, sizeof(config_test_conf) - 1);
    yatest_file_create_with(TEST_INCLUDED_CONFIG_FILE, config_test_include_conf, sizeof(config_test_include_conf) - 1);
}

static void init()
{
    int ret;
    dnscore_init();
    config_init();
    tsig_init();

    memset(&g_config, 0, sizeof(config_test_t));
    ptr_vector_init_empty(&g_config._string_array);

    int priority = 0;

    if(FAIL(ret = config_register_cmdline(priority++))) // without this line, the help will not work
    {
        yatest_err("config_register_cmdline failed with %s", error_gettext(ret));
        exit(1);
    }

    ret = config_register_struct("config", config_test_desc, &g_config, priority++);
    if(FAIL(ret))
    {
        yatest_err("config_register_struct failed with %s", error_gettext(ret));
        exit(1);
    }

    filedir_init();
}

static void finalise()
{
    config_finalize();
    config_unregister_by_name("config");
    dnscore_finalize();
}

static void finalise2()
{
    config_finalize();
    config_unregister_struct("config", config_test_desc);
    dnscore_finalize();
}

static void finalise3()
{
    config_section_descriptor_t *desc = config_section_get_descriptor("config");
    config_unregister(desc);
    dnscore_finalize();
}

static int file_read_test()
{
    int ret;
    init();
    config_error_t cerr;
    config_error_init(&cerr);
    ret = config_read(TEST_CONFIG_FILE, &cerr);
    if(FAIL(ret))
    {
        yatest_err("error: file: %s:%i", cerr.file, cerr.line_number);
        yatest_err("error: variable: %s", config_error_get_variable_name(&cerr));
        yatest_err("error: line: %s", cerr.line);
        yatest_err("config_read failed with %s", error_gettext(ret));
        return 1;
    }
    if(!g_config._bool)
    {
        yatest_err("_bool is false");
        return 1;
    }
    if(g_config._flag8 != FLAG_0)
    {
        yatest_err("_flag8 has an unexpected value");
        return 1;
    }
    if(g_config._flag16 != FLAG_0)
    {
        yatest_err("_flag16 has an unexpected value");
        return 1;
    }
    if(g_config._flag32 != FLAG_0)
    {
        yatest_err("_flag32 has an unexpected value");
        return 1;
    }
    if(g_config._flag64 != FLAG_0)
    {
        yatest_err("_flag64 has an unexpected value");
        return 1;
    }
    if(g_config._u64 != 1)
    {
        yatest_err("_u64 has an unexpected value");
        return 1;
    }
    if(g_config._u32 != 1)
    {
        yatest_err("_u32 has an unexpected value");
        return 1;
    }
    if(g_config._u16 != 1)
    {
        yatest_err("_u16 has an unexpected value");
        return 1;
    }
    if(g_config._u8 != 1)
    {
        yatest_err("_u8 has an unexpected value");
        return 1;
    }
    if(g_config._s32 != 1)
    {
        yatest_err("_s32 has an unexpected value");
        return 1;
    }
    if(g_config._u32_range != 16)
    {
        yatest_err("_u32_range has an unexpected value");
        return 1;
    }
    if(g_config._u32_clamp != 16)
    {
        yatest_err("_u32_clamp has an unexpected value");
        return 1;
    }
    if(g_config._dns_type != ntohs(TYPE_AAAA))
    {
        yatest_err("_dns_type has an unexpected value");
        return 1;
    }
    if(g_config._dns_class != ntohs(CLASS_CH))
    {
        yatest_err("_dns_class has an unexpected value");
        return 1;
    }
    if(g_config._dnskey_algorithm != DNSKEY_ALGORITHM_RSASHA256_NSEC3)
    {
        yatest_err("_dnskey_algorithm has an unexpected value");
        return 1;
    }
    if(g_config._u8_inc != 1)
    {
        yatest_err("_u8_inc has an unexpected value");
        return 1;
    }
    if(strcmp(g_config._string, STRING_VALUE) != 0)
    {
        yatest_err("_string has an unexpected value");
        return 1;
    }
    if(strcmp(g_config._string_copy, STRING_COPY_VALUE) != 0)
    {
        yatest_err("_string has an unexpected value");
        return 1;
    }
    if(ptr_vector_size(&g_config._string_array) != 2)
    {
        yatest_err("_string_array has an unexpected size");
        return 1;
    }
    if(strcmp((char *)ptr_vector_get(&g_config._string_array, 0), STRING_ARRAY_0_VALUE) != 0)
    {
        yatest_err("_string_array[0] has an unexpected value");
        return 1;
    }
    if(strcmp((char *)ptr_vector_get(&g_config._string_array, 1), STRING_ARRAY_1_VALUE) != 0)
    {
        yatest_err("_string_array[1] has an unexpected value");
        return 1;
    }
    if(strcmp(g_config._password, PASSWORD_VALUE) != 0)
    {
        yatest_err("_password has an unexpected value");
        return 1;
    }
    uint8_t fqdn_value[64];
    dnsname_init_with_cstr(fqdn_value, FQDN_VALUE);
    if(!dnsname_equals(g_config._fqdn, fqdn_value))
    {
        yatest_err("_fqdn has an unexpected value");
        return 1;
    }
    if(strcmp(g_config._path, PATH_VALUE "/") != 0)
    {
        yatest_err("_path has an unexpected value");
        return 1;
    }
    if(strcmp(g_config._chroot, CHROOT_VALUE "/") != 0)
    {
        yatest_err("_chroot has an unexpected value");
        return 1;
    }
    if(strcmp(g_config._logpath, LOGPATH_VALUE "/") != 0)
    {
        yatest_err("_logpath has an unexpected value");
        return 1;
    }
    if(strcmp(g_config._file, FILE_VALUE) != 0)
    {
        yatest_err("_file has an unexpected value");
        return 1;
    }
    if(g_config._uid != UID_VALUE_INT)
    {
        yatest_err("_uid has an unexpected value");
        return 1;
    }
    if(g_config._gid != GID_VALUE_INT)
    {
        yatest_err("_gid has an unexpected value");
        return 1;
    }
    if(strcmp((char *)g_config._bytes, "Hello World\n") != 0)
    {
        yatest_err("_bytes has an unexpected value");
        return 1;
    }

    finalise();
    return 0;
}

static int buffer_read_test()
{
    int ret;
    init();
    config_error_t cerr;
    config_error_init(&cerr);
    ret = config_read_from_buffer(config_test_conf_absolute, sizeof(config_test_conf_absolute) - 1, "ram-file", &cerr);
    if(FAIL(ret))
    {
        yatest_err("error: file: %s:%i", cerr.file, cerr.line_number);
        yatest_err("error: variable: %s", config_error_get_variable_name(&cerr));
        yatest_err("error: line: %s", cerr.line);
        yatest_err("config_read failed with %s", error_gettext(ret));
        return 1;
    }
    if(!g_config._bool)
    {
        yatest_err("_bool is false");
        return 1;
    }
    if(g_config._flag8 != FLAG_0)
    {
        yatest_err("_flag8 has an unexpected value");
        return 1;
    }
    if(g_config._flag16 != FLAG_0)
    {
        yatest_err("_flag16 has an unexpected value");
        return 1;
    }
    if(g_config._flag32 != FLAG_0)
    {
        yatest_err("_flag32 has an unexpected value");
        return 1;
    }
    if(g_config._flag64 != FLAG_0)
    {
        yatest_err("_flag64 has an unexpected value");
        return 1;
    }
    if(g_config._u64 != 1)
    {
        yatest_err("_u64 has an unexpected value");
        return 1;
    }
    if(g_config._u32 != 1)
    {
        yatest_err("_u32 has an unexpected value");
        return 1;
    }
    if(g_config._u16 != 1)
    {
        yatest_err("_u16 has an unexpected value");
        return 1;
    }
    if(g_config._u8 != 1)
    {
        yatest_err("_u8 has an unexpected value");
        return 1;
    }
    if(g_config._s32 != 1)
    {
        yatest_err("_s32 has an unexpected value");
        return 1;
    }
    if(g_config._u32_range != 16)
    {
        yatest_err("_u32_range has an unexpected value");
        return 1;
    }
    if(g_config._u32_clamp != 16)
    {
        yatest_err("_u32_clamp has an unexpected value");
        return 1;
    }
    if(g_config._dns_type != ntohs(TYPE_AAAA))
    {
        yatest_err("_dns_type has an unexpected value");
        return 1;
    }
    if(g_config._dns_class != ntohs(CLASS_CH))
    {
        yatest_err("_dns_class has an unexpected value");
        return 1;
    }
    if(g_config._dnskey_algorithm != DNSKEY_ALGORITHM_RSASHA256_NSEC3)
    {
        yatest_err("_dnskey_algorithm has an unexpected value");
        return 1;
    }
    if(g_config._u8_inc != 1)
    {
        yatest_err("_u8_inc has an unexpected value");
        return 1;
    }
    if(strcmp(g_config._string, STRING_VALUE) != 0)
    {
        yatest_err("_string has an unexpected value");
        return 1;
    }
    if(strcmp(g_config._string_copy, STRING_COPY_VALUE) != 0)
    {
        yatest_err("_string has an unexpected value");
        return 1;
    }
    if(ptr_vector_size(&g_config._string_array) != 2)
    {
        yatest_err("_string_array has an unexpected size");
        return 1;
    }
    if(strcmp((char *)ptr_vector_get(&g_config._string_array, 0), STRING_ARRAY_0_VALUE) != 0)
    {
        yatest_err("_string_array[0] has an unexpected value");
        return 1;
    }
    if(strcmp((char *)ptr_vector_get(&g_config._string_array, 1), STRING_ARRAY_1_VALUE) != 0)
    {
        yatest_err("_string_array[1] has an unexpected value");
        return 1;
    }
    if(strcmp(g_config._password, PASSWORD_VALUE) != 0)
    {
        yatest_err("_password has an unexpected value");
        return 1;
    }
    uint8_t fqdn_value[64];
    dnsname_init_with_cstr(fqdn_value, FQDN_VALUE);
    if(!dnsname_equals(g_config._fqdn, fqdn_value))
    {
        yatest_err("_fqdn has an unexpected value");
        return 1;
    }
    if(strcmp(g_config._path, PATH_VALUE "/") != 0)
    {
        yatest_err("_path has an unexpected value");
        return 1;
    }
    if(strcmp(g_config._chroot, CHROOT_VALUE "/") != 0)
    {
        yatest_err("_chroot has an unexpected value");
        return 1;
    }
    if(strcmp(g_config._logpath, LOGPATH_VALUE "/") != 0)
    {
        yatest_err("_logpath has an unexpected value");
        return 1;
    }
    if(strcmp(g_config._file, FILE_VALUE) != 0)
    {
        yatest_err("_file has an unexpected value");
        return 1;
    }
    if(g_config._uid != UID_VALUE_INT)
    {
        yatest_err("_uid has an unexpected value");
        return 1;
    }
    if(g_config._gid != GID_VALUE_INT)
    {
        yatest_err("_gid has an unexpected value");
        return 1;
    }
    if(strcmp((char *)g_config._bytes, "Hello World\n") != 0)
    {
        yatest_err("_bytes has an unexpected value");
        return 1;
    }

    finalise();
    return 0;
}

static int sources_read_test()
{
    int ret;
    init();
    config_error_t cerr;
    config_error_init(&cerr);

    struct config_source_s sources[3];
    // needs to be sorted by decreasing source level
    // level = CONFIG_SOURCE_CMDLINE = 250
    config_source_set_commandline(&sources[0], config_cmdline, config_test_argc, config_test_argv);
    config_source_set_buffer(&sources[1], "local", 3, config_test_2_conf, sizeof(config_test_2_conf) - 1);
    config_source_set_file(&sources[2], TEST_CONFIG_FILE, 2);

    config_set_autodefault_after_source(CONFIG_SOURCE_FILE);

    ret = config_read_from_sources(sources, 3, &cerr);

    if(FAIL(ret))
    {
        yatest_err("config_read_from_sources failed with %s", error_gettext(ret));
        return 1;
    }

    ret = config_postprocess();

    if(FAIL(ret))
    {
        yatest_err("config_postprocess failed with %s", error_gettext(ret));
        return 1;
    }

    if(g_config._u64 != 3)
    {
        yatest_err("_u64 != 3: got %llu", g_config._u64);
        return 1;
    }

    if(g_config._u32 != 2)
    {
        yatest_err("_u32 != 2: got %u", g_config._u32);
        return 1;
    }

    if(g_config._u16 != 1)
    {
        yatest_err("_u32 != 2: got %u", g_config._u16);
        return 1;
    }

    finalise3();
    return 0;
}

static int sources_file_error_test()
{
    int ret;
    init();
    config_error_t cerr;
    config_error_init(&cerr);

    struct config_source_s sources[3];
    // needs to be sorted by decreasing source level
    // level = CONFIG_SOURCE_CMDLINE = 250
    config_source_set_commandline(&sources[0], config_cmdline, config_test_argc, config_test_argv);
    config_source_set_buffer(&sources[1], "local", 3, config_test_2_conf, sizeof(config_test_2_conf) - 1);
    config_source_set_file(&sources[2], TEST_CONFIG_FILE "-no-such-file", 2);

    config_set_autodefault_after_source(CONFIG_SOURCE_FILE);

    ret = config_read_from_sources(sources, 3, &cerr);

    if(ISOK(ret))
    {
        yatest_err("config_read_from_sources should have failed");
        return 1;
    }

    yatest_log("%s:%i : '%s'", cerr.file, cerr.line_number, cerr.line);

    finalise3();
    return 0;
}

static int sources_cmdline_error_test()
{
    int ret;
    init();
    config_error_t cerr;
    config_error_init(&cerr);

    struct config_source_s sources[3];
    // needs to be sorted by decreasing source level
    // level = CONFIG_SOURCE_CMDLINE = 250
    if(ISOK(ret = config_source_set_commandline(&sources[0], config_cmdline, config_test_argc, config_test_argv_bad)))
    {
        yatest_err("config_read_from_sources should have failed");
        /*
        config_source_set_buffer(&sources[1], "local", 3, config_test_2_conf, sizeof(config_test_2_conf) - 1);
        config_source_set_file(&sources[2], TEST_CONFIG_FILE, 2);
        config_set_autodefault_after_source(CONFIG_SOURCE_FILE);

        ret = config_read_from_sources(sources, 3, &cerr);
        */
        return 1;
    }
    else
    {
        yatest_log("config_source_set_commandline failed with %08x", ret);
    }

    finalise3();
    return 0;
}

static int parse_error_empty_tag_begin_test()
{
    int ret;
    init();
    config_error_t cerr;
    config_error_init(&cerr);
    ret = config_read_from_buffer(config_test_empty_tag_begin_conf, sizeof(config_test_empty_tag_begin_conf) - 1, "empty-tag-begin", &cerr);
    if(ret != CONFIG_PARSE_SECTION_TAG_TOO_SMALL)
    {
        yatest_err("config_read_from_buffer expected to fail with CONFIG_PARSE_SECTION_TAG_TOO_SMALL, got %s instead", error_gettext(ret));
        return 1;
    }
    finalise();
    return 0;
}

static int parse_error_empty_tag_end_test()
{
    int ret;
    init();
    config_error_t cerr;
    config_error_init(&cerr);
    ret = config_read_from_buffer(config_test_empty_tag_end_conf, sizeof(config_test_empty_tag_end_conf) - 1, "empty-tag-end", &cerr);
    if(ret != CONFIG_PARSE_SECTION_TAG_TOO_SMALL)
    {
        yatest_err("config_read_from_buffer expected to fail with CONFIG_PARSE_SECTION_TAG_TOO_SMALL, got %s instead", error_gettext(ret));
        return 1;
    }
    finalise();
    return 0;
}

static int parse_error_tag_notclosed_test()
{
    int ret;
    init();
    config_error_t cerr;
    config_error_init(&cerr);
    ret = config_read_from_buffer(config_test_tag_notclosed_conf, sizeof(config_test_tag_notclosed_conf) - 1, "empty-tag-end", &cerr);
    if(ret != CONFIG_PARSE_SECTION_TAG_NOT_CLOSED)
    {
        yatest_err("config_read_from_buffer expected to fail with CONFIG_PARSE_SECTION_TAG_NOT_CLOSED, got %s instead", error_gettext(ret));
        return 1;
    }
    finalise();
    return 0;
}

static int parse_error_tag_nested_test()
{
    int ret;
    init();
    config_error_t cerr;
    config_error_init(&cerr);
    ret = config_read_from_buffer(config_test_tag_nested_conf, sizeof(config_test_tag_nested_conf) - 1, "empty-tag-end", &cerr);
    if(ret != CONFIG_PARSE_UNEXPECTED_SECTION_OPEN)
    {
        yatest_err("config_read_from_buffer expected to fail with CONFIG_PARSE_UNEXPECTED_SECTION_OPEN, got %s instead", error_gettext(ret));
        return 1;
    }
    finalise();
    return 0;
}

static int parse_error_tag_toobig_test()
{
    int ret;
    init();
    config_error_t cerr;
    config_error_init(&cerr);
    ret = config_read_from_buffer(config_test_tag_toobig_begin_conf, sizeof(config_test_tag_toobig_begin_conf) - 1, "big-tag-begin", &cerr);
    if(ret != CONFIG_PARSE_SECTION_TAG_NOT_CLOSED)
    {
        yatest_err("config_read_from_buffer expected to fail with CONFIG_PARSE_SECTION_TAG_NOT_CLOSED, got %s instead", error_gettext(ret));
        return 1;
    }
    finalise();
    return 0;
}

static int parse_error_tag_toobig_end_test()
{
    int ret;
    init();
    config_error_t cerr;
    config_error_init(&cerr);
    ret = config_read_from_buffer(config_test_tag_toobig_end_conf, sizeof(config_test_tag_toobig_end_conf) - 1, "big-tag-end", &cerr);
    if(ret != CONFIG_PARSE_CLOSED_WRONG_SECTION)
    {
        yatest_err("config_read_from_buffer expected to fail with CONFIG_PARSE_CLOSED_WRONG_SECTION, got %s instead", error_gettext(ret));
        return 1;
    }
    finalise();
    return 0;
}

static int parse_error_tag_no_open_close_test()
{
    int ret;
    init();
    config_error_t cerr;
    config_error_init(&cerr);
    ret = config_read_from_buffer(config_test_no_open_close_conf, sizeof(config_test_no_open_close_conf) - 1, "no-open-close", &cerr);
    if(ret != CONFIG_PARSE_UNEXPECTED_SECTION_CLOSE)
    {
        yatest_err("config_read_from_buffer expected to fail with CONFIG_PARSE_UNEXPECTED_SECTION_CLOSE, got %s instead", error_gettext(ret));
        return 1;
    }
    finalise();
    return 0;
}

static int parse_error_tag_wrong_close_test()
{
    int ret;
    init();
    config_error_t cerr;
    config_error_init(&cerr);
    ret = config_read_from_buffer(config_test_wrong_close_conf, sizeof(config_test_wrong_close_conf) - 1, "wrong-close", &cerr);
    if(ret != CONFIG_PARSE_CLOSED_WRONG_SECTION)
    {
        yatest_err("config_read_from_buffer expected to fail with CONFIG_PARSE_SECTION_TAG_TOO_SMALL, got %s instead", error_gettext(ret));
        return 1;
    }
    finalise();
    return 0;
}

static int parse_error_path_max_0_test()
{
    int ret;
    init();
    config_error_t cerr;
    config_error_init(&cerr);

    char *config_test_include_path_max_0_conf = (char *)malloc(PATH_MAX * 2);
    strcpy(config_test_include_path_max_0_conf, "include /tmp/config-test/");
    size_t pos = strlen(config_test_include_path_max_0_conf);
    int    word_len = PATH_MAX;
    for(int i = 0; i < word_len; ++i)
    {
        config_test_include_path_max_0_conf[pos + i] = 'a';
    }
    strcpy(&config_test_include_path_max_0_conf[pos + word_len], ".conf\n");

    ret = config_read_from_buffer(config_test_include_path_max_0_conf, strlen(config_test_include_path_max_0_conf), "/tmp/config-test", &cerr);
    if(ret != CONFIG_FILE_PATH_TOO_BIG)
    {
        yatest_err("config_read_from_buffer expected to fail with CONFIG_FILE_PATH_TOO_BIG, got %s instead", error_gettext(ret));
        return 1;
    }

    finalise();
    free(config_test_include_path_max_0_conf);
    return 0;
}

static int parse_error_include_nopath_conf_test()
{
    int ret;
    init();
    config_error_t cerr;
    config_error_init(&cerr);
    ret = config_read_from_buffer(config_test_include_nopath_conf, sizeof(config_test_include_nopath_conf) - 1, "/tmp/config-test", &cerr);
    if(ret != CONFIG_PARSE_INCLUDE_EXPECTED_FILE_PATH)
    {
        yatest_err("config_read_from_buffer expected to fail with CONFIG_PARSE_INCLUDE_EXPECTED_FILE_PATH, got %s instead", error_gettext(ret));
        return 1;
    }
    finalise();
    return 0;
}

static int parse_error_include_not_found_0_test()
{
    int ret;
    init();
    config_error_t cerr;
    config_error_init(&cerr);
    const char *config = "include does-not-exist";
    ret = config_read_from_buffer(config, strlen(config), "tmp", &cerr);
    if(ret != CANNOT_OPEN_FILE)
    {
        yatest_err("config_read_from_buffer expected to fail with CANNOT_OPEN_FILE, got %s instead", error_gettext(ret));
        return 1;
    }
    finalise();
    return 0;
}

static int parse_error_unknown_keyword_test()
{
    int ret;
    init();
    config_error_t cerr;
    config_error_init(&cerr);
    const char *config = "does-not-exist";
    ret = config_read_from_buffer(config, strlen(config), "tmp", &cerr);
    if(ret != CONFIG_PARSE_UNKNOWN_KEYWORD)
    {
        yatest_err("config_read_from_buffer expected to fail with CONFIG_PARSE_UNKNOWN_KEYWORD, got %s instead", error_gettext(ret));
        return 1;
    }
    finalise();
    return 0;
}

static ya_result section_read_callback_error_test_cb(const char *section_name, int section_index)
{
    yatest_log("section_read_callback_error_test_cb(%s, %i)", section_name, section_index);
    return ERROR;
}

static int sources_callback_error_test()
{
    int ret;
    init();
    config_error_t cerr;
    config_error_init(&cerr);

    struct config_source_s sources[3];
    // needs to be sorted by decreasing source level
    // level = CONFIG_SOURCE_CMDLINE = 250
    config_source_set_commandline(&sources[0], config_cmdline, config_test_argc, config_test_argv);
    config_source_set_buffer(&sources[1], "local", 3, config_test_2_conf, sizeof(config_test_2_conf) - 1);
    config_source_set_file(&sources[2], TEST_CONFIG_FILE, 2);
    ret = config_add_on_section_read_callback("config", section_read_callback_error_test_cb);
    if(FAIL(ret))
    {
        yatest_err("config_add_on_section_read_callback failed with %s", error_gettext(ret));
        return 1;
    }
    config_set_autodefault_after_source(CONFIG_SOURCE_FILE);

    ret = config_read_from_sources(sources, 3, &cerr);

    if(ISOK(ret))
    {
        yatest_err("config_read_from_sources should have failed");
        return 1;
    }

    yatest_log("%s:%i : '%s' (%i)", cerr.file, cerr.line_number, cerr.line, ret);

    finalise3();
    return 0;
}

static ya_result config_register_const_test_init(struct config_section_descriptor_s *csd)
{
    // NOP
    yatest_log("config_register_const_test_init(%p)", csd);
    return SUCCESS;
}

static ya_result config_register_const_test_start(struct config_section_descriptor_s *csd)
{
    // NOP
    yatest_log("config_register_const_test_start(%p)", csd);
    return SUCCESS;
}

static ya_result config_register_const_test_stop(struct config_section_descriptor_s *csd)
{
    // NOP
    yatest_log("config_register_const_test_stop(%p)", csd);
    return SUCCESS;
}

static ya_result config_register_const_test_postprocess(struct config_section_descriptor_s *csd, config_error_t *cfgerr)
{
    // NOP
    (void)cfgerr;
    yatest_log("config_register_const_test_postprocess(%p)", csd);
    return SUCCESS;
}

static ya_result config_register_const_test_finalize(struct config_section_descriptor_s *csd)
{
    yatest_log("config_register_const_test_finalize(%p)", csd);

    if(csd != NULL)
    {
        if(csd->vtbl != NULL)
        {
            free((char *)csd->vtbl->name);
            free((config_section_descriptor_vtbl_s *)csd->vtbl);
        }

        config_section_descriptor_delete(csd);
    }

    return SUCCESS;
}

static ya_result config_register_const_test_set_wild(struct config_section_descriptor_s *csd, const char *key, const char *value)
{
    yatest_log("config_register_const_test_set_wild(%p, %p, %p)", csd, key, value);
    return CONFIG_UNKNOWN_SETTING;
}

static ya_result config_register_const_test_print_wild(const struct config_section_descriptor_s *csd, output_stream_t *os, const char *key, void **context)
{
    yatest_log("config_register_const_test_set_wild(%p, %p, %p, %p)", csd, os, key, context);
    return CONFIG_UNKNOWN_SETTING;
}

static const config_section_descriptor_vtbl_s config_register_const_test_descriptor = {NULL,
                                                                                       NULL,
                                                                                       config_register_const_test_set_wild,
                                                                                       config_register_const_test_print_wild,
                                                                                       config_register_const_test_init,
                                                                                       config_register_const_test_start,
                                                                                       config_register_const_test_stop,
                                                                                       config_register_const_test_postprocess,
                                                                                       config_register_const_test_finalize};

static int                                    register_const_test()
{
    int ret;
    dnscore_init();
    config_init();
    tsig_init();

    memset(&g_config, 0, sizeof(config_test_t));
    ptr_vector_init_empty(&g_config._string_array);

    config_section_descriptor_vtbl_s *vtbl;
    MALLOC_OBJECT_OR_DIE(vtbl, config_section_descriptor_vtbl_s, CFGSVTBL_TAG);
    memcpy(vtbl, &config_register_const_test_descriptor, sizeof(config_section_descriptor_vtbl_s));
    vtbl->name = strdup("config");
    vtbl->table = config_test_desc;
    yatest_log("vtbl=%p: name='%s'@%p, table=%p", vtbl, vtbl->name, vtbl->name, vtbl->table);

    yatest_log("config_section_set_wild_method=%p", vtbl->set_wild);
    yatest_log("config_section_print_wild_method=%p", vtbl->print_wild);
    yatest_log("config_section_init_method=%p", vtbl->init);
    yatest_log("config_section_start_method=%p", vtbl->start);
    yatest_log("config_section_stop_method=%p", vtbl->stop);
    yatest_log("config_section_postprocess_method=%p", vtbl->postprocess);
    yatest_log("config_section_finalize_method=%p", vtbl->finalise);

    config_section_descriptor_t *desc = config_section_descriptor_new_instance_ex(vtbl, &g_config);
    yatest_log("desc=%p", desc);
    ret = config_register_const(desc, 1);
    if(ret != 0)
    {
        yatest_err("config_register failed with %s", error_gettext(ret));
        return 1;
    }

    config_section_descriptor_vtbl_s *vtbl2;
    MALLOC_OBJECT_OR_DIE(vtbl2, config_section_descriptor_vtbl_s, CFGSVTBL_TAG);
    memcpy(vtbl2, &config_register_const_test_descriptor, sizeof(config_section_descriptor_vtbl_s));
    vtbl2->name = strdup("config2");
    vtbl2->table = NULL;
    yatest_log("vtbl2=%p: name='%s'@%p, table=%p", vtbl2, vtbl2->name, vtbl2->name, vtbl2->table);
    config_section_descriptor_t *desc_nobase = config_section_descriptor_new_instance(vtbl2);
    yatest_log("desc_nobase=%p", desc_nobase);
    ret = config_register_const(desc_nobase, 2);
    if(ret != 0)
    {
        yatest_err("config_register failed with %s (null)", error_gettext(ret));
        return 1;
    }
    ret = config_unregister(desc_nobase);
    if(FAIL(ret))
    {
        yatest_err("config_unregister failed with %s", error_gettext(ret));
        return 1;
    }
    ret = config_unregister(desc_nobase);
    if(ISOK(ret))
    {
        yatest_err("config_unregister should have failed");
        return 1;
    }
    finalise();
    return 0;
}

static int default_test()
{
    int ret;
    init();
    config_error_t cerr;
    config_error_init(&cerr);
    ret = config_set_default(&cerr);

    if(FAIL(ret))
    {
        yatest_err("error: file: %s:%i", cerr.file, cerr.line_number);
        yatest_err("error: variable: %s", config_error_get_variable_name(&cerr));
        yatest_err("error: line: %s", cerr.line);
        yatest_err("config_read failed with %s", error_gettext(ret));
        return 1;
    }
    if(g_config._bool)
    {
        yatest_err("_bool is true");
        return 1;
    }
    if(g_config._flag8 != 0)
    {
        yatest_err("_flag8 has an unexpected value");
        return 1;
    }
    if(g_config._flag16 != 0)
    {
        yatest_err("_flag16 has an unexpected value");
        return 1;
    }
    if(g_config._flag32 != 0)
    {
        yatest_err("_flag32 has an unexpected value");
        return 1;
    }
    if(g_config._flag64 != 0)
    {
        yatest_err("_flag64 has an unexpected value");
        return 1;
    }
    if(g_config._u64 != 0)
    {
        yatest_err("_u64 has an unexpected value");
        return 1;
    }
    if(g_config._u32 != 0)
    {
        yatest_err("_u32 has an unexpected value");
        return 1;
    }
    if(g_config._u16 != 0)
    {
        yatest_err("_u16 has an unexpected value");
        return 1;
    }
    if(g_config._u8 != 0)
    {
        yatest_err("_u8 has an unexpected value");
        return 1;
    }
    if(g_config._s32 != 0)
    {
        yatest_err("_s32 has an unexpected value");
        return 1;
    }
    if(g_config._u32_range != 1)
    {
        yatest_err("_u32_range has an unexpected value");
        return 1;
    }
    if(g_config._u32_clamp != 1)
    {
        yatest_err("_u32_clamp has an unexpected value");
        return 1;
    }
    if(g_config._dns_type != ntohs(TYPE_A))
    {
        yatest_err("_dns_type has an unexpected value");
        return 1;
    }
    if(g_config._dns_class != ntohs(CLASS_IN))
    {
        yatest_err("_dns_class has an unexpected value");
        return 1;
    }
    if(g_config._dnskey_algorithm != DNSKEY_ALGORITHM_RSASHA512_NSEC3)
    {
        yatest_err("_dnskey_algorithm has an unexpected value");
        return 1;
    }
    if(g_config._u8_inc != 0)
    {
        yatest_err("_u8_inc has an unexpected value");
        return 1;
    }
    if(strcmp(g_config._string, "0") != 0)
    {
        yatest_err("_string has an unexpected value");
        return 1;
    }
    if(strcmp(g_config._string_copy, "0") != 0)
    {
        yatest_err("_string has an unexpected value");
        return 1;
    }
    if(ptr_vector_size(&g_config._string_array) != 0)
    {
        yatest_err("_string_array has an unexpected size");
        return 1;
    }
    if(strcmp(g_config._password, "0") != 0)
    {
        yatest_err("_password has an unexpected value");
        return 1;
    }
    uint8_t fqdn_value[64];
    dnsname_init_with_cstr(fqdn_value, "0");
    if(!dnsname_equals(g_config._fqdn, fqdn_value))
    {
        yatest_err("_fqdn has an unexpected value");
        return 1;
    }
    if(strcmp(g_config._path, "0/") != 0)
    {
        yatest_err("_path has an unexpected value");
        return 1;
    }
    if(strcmp(g_config._chroot, "/tmp/") != 0)
    {
        yatest_err("_chroot has an unexpected value");
        return 1;
    }
    if(strcmp(g_config._logpath, "/tmp/") != 0)
    {
        yatest_err("_logpath has an unexpected value");
        return 1;
    }
    if(strcmp(g_config._file, FILE2_VALUE) != 0)
    {
        yatest_err("_file has an unexpected value");
        return 1;
    }
    if(g_config._uid != 1000)
    {
        yatest_err("_uid has an unexpected value");
        return 1;
    }
    if(g_config._gid != 1000)
    {
        yatest_err("_gid has an unexpected value");
        return 1;
    }
    if(strcmp((char *)g_config._bytes, "Hello World default\n") != 0)
    {
        yatest_err("_bytes has an unexpected value");
        return 1;
    }

    config_print(termout);
    flushout();

    finalise2();
    return 0;
}

static int bool_test()
{
    int ret;
    init();
    config_error_t cerr;
    config_error_init(&cerr);
    config_section_descriptor_t *desc = config_section_get_descriptor("config");

    ret = desc->vtbl->set_wild(desc, "_bool", "1");
    if(ret != CONFIG_UNKNOWN_SETTING)
    {
        yatest_err("set_wild should have failed with CONFIG_UNKNOWN_SETTING, instead gave %s", error_gettext(ret));
        return 1;
    }

    void *iterator_context = NULL;
    ret = desc->vtbl->print_wild(desc, termout, "_bool", &iterator_context);
    if(ret != CONFIG_UNKNOWN_SETTING)
    {
        yatest_err("print_wild should have failed with CONFIG_UNKNOWN_SETTING, instead gave %s", error_gettext(ret));
        return 1;
    }

    ret = config_value_set(desc, "_bool", "1", &cerr);
    if(FAIL(ret))
    {
        yatest_err("config_value_set failed with %s", error_gettext(ret));
        return 1;
    }
    if(!g_config._bool)
    {
        yatest_err("_bool is false (1)");
        return 1;
    }
    ret = config_value_set(desc, "_bool", "0", &cerr);
    if(FAIL(ret))
    {
        yatest_err("config_value_set failed with %s", error_gettext(ret));
        return 1;
    }
    if(g_config._bool)
    {
        yatest_err("_bool is true (0)");
        return 1;
    }
    ret = config_value_set(desc, "_bool", "true", &cerr);
    if(FAIL(ret))
    {
        yatest_err("config_value_set failed with %s", error_gettext(ret));
        return 1;
    }
    if(!g_config._bool)
    {
        yatest_err("_bool is false (true)");
        return 1;
    }
    ret = config_value_set(desc, "_bool", "false", &cerr);
    if(FAIL(ret))
    {
        yatest_err("config_value_set failed with %s", error_gettext(ret));
        return 1;
    }
    if(g_config._bool)
    {
        yatest_err("_bool is true (false)");
        return 1;
    }
    ret = config_value_set(desc, "_bool", "yes", &cerr);
    if(FAIL(ret))
    {
        yatest_err("config_value_set failed with %s", error_gettext(ret));
        return 1;
    }
    if(!g_config._bool)
    {
        yatest_err("_bool is false (yes)");
        return 1;
    }
    ret = config_value_set(desc, "_bool", "no", &cerr);
    if(FAIL(ret))
    {
        yatest_err("config_value_set failed with %s", error_gettext(ret));
        return 1;
    }
    if(g_config._bool)
    {
        yatest_err("_bool is true (no)");
        return 1;
    }
    finalise3();
    return 0;
}

static config_section_descriptor_t *type_test_init(config_error_t *cerrp)
{
    init();
    config_error_init(cerrp);
    return config_section_get_descriptor("config");
}

static int u64_test()
{
    int                          ret;
    config_error_t               cerr;
    config_section_descriptor_t *desc = type_test_init(&cerr);

    ret = config_value_set(desc, "_u64", " 18446744073709551615", &cerr);
    if(FAIL(ret))
    {
        yatest_err("config_value_set failed with %s", error_gettext(ret));
        return 1;
    }
    if(g_config._u64 != 18446744073709551615ULL)
    {
        yatest_err("_u64 is not 18446744073709551615");
        return 1;
    }
    ret = config_value_set(desc, "_u64", "0", &cerr);
    if(FAIL(ret))
    {
        yatest_err("config_value_set failed with %s", error_gettext(ret));
        return 1;
    }
    if(g_config._u64 != 0)
    {
        yatest_err("_u64 is not 0");
        return 1;
    }
    ret = config_value_set(desc, "_u64", "x", &cerr);
    if(ISOK(ret))
    {
        yatest_err("config_value_set should have failed (x)");
        return 1;
    }
    ret = config_value_set(desc, "_u64", "-1", &cerr);
    if(ISOK(ret))
    {
        yatest_err("config_value_set should have failed (<0)");
        return 1;
    }
    ret = config_value_set(desc, "_u64", "184467440737095516150", &cerr);
    if(ISOK(ret))
    {
        yatest_err("config_value_set should have failed (range)");
        return 1;
    }

    finalise3();
    return 0;
}

static int u32_test()
{
    int                          ret;
    config_error_t               cerr;
    config_section_descriptor_t *desc = type_test_init(&cerr);

    ret = config_value_set(desc, "_u32", " 4294967295", &cerr);
    if(FAIL(ret))
    {
        yatest_err("config_value_set failed with %s", error_gettext(ret));
        return 1;
    }
    if(g_config._u32 != 4294967295)
    {
        yatest_err("_u32 is not 4294967295");
        return 1;
    }
    ret = config_value_set(desc, "_u32", "0", &cerr);
    if(FAIL(ret))
    {
        yatest_err("config_value_set failed with %s", error_gettext(ret));
        return 1;
    }
    if(g_config._u32 != 0)
    {
        yatest_err("_u32 is not 0");
        return 1;
    }
    ret = config_value_set(desc, "_u32", "x", &cerr);
    if(ISOK(ret))
    {
        yatest_err("config_value_set should have failed (x)");
        return 1;
    }
    ret = config_value_set(desc, "_u32", "-1", &cerr);
    if(ISOK(ret))
    {
        yatest_err("config_value_set should have failed (<0)");
        return 1;
    }
    ret = config_value_set(desc, "_u32", "42949672950", &cerr);
    if(ISOK(ret))
    {
        yatest_err("config_value_set should have failed (range)");
        return 1;
    }

    finalise3();
    return 0;
}

static int s32_test()
{
    int                          ret;
    config_error_t               cerr;
    config_section_descriptor_t *desc = type_test_init(&cerr);

    ret = config_value_set(desc, "_s32", " 2147483647", &cerr);
    if(FAIL(ret))
    {
        yatest_err("config_value_set failed with %s", error_gettext(ret));
        return 1;
    }
    if(g_config._s32 != 2147483647)
    {
        yatest_err("_s32 is not 2147483647");
        return 1;
    }
    ret = config_value_set(desc, "_s32", "-2147483648", &cerr);
    if(FAIL(ret))
    {
        yatest_err("config_value_set failed with %s", error_gettext(ret));
        return 1;
    }
    if(g_config._s32 != -2147483648)
    {
        yatest_err("_s32 is not -2147483648");
        return 1;
    }
    ret = config_value_set(desc, "_s32", "x", &cerr);
    if(ISOK(ret))
    {
        yatest_err("config_value_set should have failed (x)");
        return 1;
    }
    ret = config_value_set(desc, "_s32", "21474836470", &cerr);
    if(ISOK(ret))
    {
        yatest_err("config_value_set should have failed (<range)");
        return 1;
    }
    ret = config_value_set(desc, "_s32", "-21474836480", &cerr);
    if(ISOK(ret))
    {
        yatest_err("config_value_set should have failed (>range)");
        return 1;
    }

    finalise3();
    return 0;
}

static int u32_range_test() // 1 254
{
    int                          ret;
    config_error_t               cerr;
    config_section_descriptor_t *desc = type_test_init(&cerr);

    ret = config_value_set(desc, "_u32_range", " 254", &cerr);
    if(FAIL(ret))
    {
        yatest_err("config_value_set failed with %s", error_gettext(ret));
        return 1;
    }
    if(g_config._u32_range != 254)
    {
        yatest_err("_u32_range is not 254");
        return 1;
    }
    ret = config_value_set(desc, "_u32_range", "1", &cerr);
    if(FAIL(ret))
    {
        yatest_err("config_value_set failed with %s", error_gettext(ret));
        return 1;
    }
    if(g_config._u32_range != 1)
    {
        yatest_err("_u32_range is not 1");
        return 1;
    }
    ret = config_value_set(desc, "_u32_range", "x", &cerr);
    if(ISOK(ret))
    {
        yatest_err("config_value_set should have failed (x)");
        return 1;
    }
    ret = config_value_set(desc, "_u32_range", "-1", &cerr);
    if(ISOK(ret))
    {
        yatest_err("config_value_set should have failed (<0)");
        return 1;
    }
    ret = config_value_set(desc, "_u32_range", "0", &cerr);
    if(ISOK(ret))
    {
        yatest_err("config_value_set should have failed (<1)");
        return 1;
    }
    ret = config_value_set(desc, "_u32_range", "255", &cerr);
    if(ISOK(ret))
    {
        yatest_err("config_value_set should have failed (>254)");
        return 1;
    }
    ret = config_value_set(desc, "_u32_range", "42949672950", &cerr);
    if(ISOK(ret))
    {
        yatest_err("config_value_set should have failed (range)");
        return 1;
    }

    finalise3();
    return 0;
}

static int u32_clamp_test() // 1 254
{
    int                          ret;
    config_error_t               cerr;
    config_section_descriptor_t *desc = type_test_init(&cerr);

    ret = config_value_set(desc, "_u32_clamp", " 254", &cerr);
    if(FAIL(ret))
    {
        yatest_err("config_value_set failed with %s", error_gettext(ret));
        return 1;
    }
    if(g_config._u32_clamp != 254)
    {
        yatest_err("_u32_clamp is not 254");
        return 1;
    }
    ret = config_value_set(desc, "_u32_clamp", "1", &cerr);
    if(FAIL(ret))
    {
        yatest_err("config_value_set failed with %s", error_gettext(ret));
        return 1;
    }
    if(g_config._u32_clamp != 1)
    {
        yatest_err("_u32_clamp is not 1");
        return 1;
    }
    ret = config_value_set(desc, "_u32_clamp", "x", &cerr);
    if(ISOK(ret))
    {
        yatest_err("config_value_set should have failed (x)");
        return 1;
    }
    ret = config_value_set(desc, "_u32_clamp", "-1", &cerr);
    if(FAIL(ret))
    {
        yatest_err("config_value_set failed with %s", error_gettext(ret));
        return 1;
    }
    if(g_config._u32_clamp != 1)
    {
        yatest_err("_u32_clamp is not 1");
        return 1;
    }
    ret = config_value_set(desc, "_u32_clamp", "0", &cerr);
    if(FAIL(ret))
    {
        yatest_err("config_value_set failed with %s", error_gettext(ret));
        return 1;
    }
    if(g_config._u32_clamp != 1)
    {
        yatest_err("_u32_clamp is not 1");
        return 1;
    }
    ret = config_value_set(desc, "_u32_clamp", "255", &cerr);
    if(FAIL(ret))
    {
        yatest_err("config_value_set failed with %s", error_gettext(ret));
        return 1;
    }
    if(g_config._u32_clamp != 254)
    {
        yatest_err("_u32_clamp is not 254");
        return 1;
    }
    ret = config_value_set(desc, "_u32_clamp", "42949672950", &cerr);
    if(FAIL(ret))
    {
        yatest_err("config_value_set failed with %s", error_gettext(ret));
        return 1;
    }
    if(g_config._u32_clamp != 254)
    {
        yatest_err("_u32_clamp is not 254");
        return 1;
    }

    finalise3();
    return 0;
}

static int u16_test()
{
    int                          ret;
    config_error_t               cerr;
    config_section_descriptor_t *desc = type_test_init(&cerr);

    ret = config_value_set(desc, "_u16", " 65535", &cerr);
    if(FAIL(ret))
    {
        yatest_err("config_value_set failed with %s", error_gettext(ret));
        return 1;
    }
    if(g_config._u16 != 65535)
    {
        yatest_err("_u16 is not 65535");
        return 1;
    }
    ret = config_value_set(desc, "_u16", "0", &cerr);
    if(FAIL(ret))
    {
        yatest_err("config_value_set failed with %s", error_gettext(ret));
        return 1;
    }
    if(g_config._u16 != 0)
    {
        yatest_err("_u16 is not 0");
        return 1;
    }
    ret = config_value_set(desc, "_u16", "x", &cerr);
    if(ISOK(ret))
    {
        yatest_err("config_value_set should have failed (x)");
        return 1;
    }
    ret = config_value_set(desc, "_u16", "-1", &cerr);
    if(ISOK(ret))
    {
        yatest_err("config_value_set should have failed (<0)");
        return 1;
    }
    ret = config_value_set(desc, "_u16", "655350", &cerr);
    if(ISOK(ret))
    {
        yatest_err("config_value_set should have failed (range)");
        return 1;
    }

    finalise3();
    return 0;
}

static int u8_test()
{
    int                          ret;
    config_error_t               cerr;
    config_section_descriptor_t *desc = type_test_init(&cerr);

    ret = config_value_set(desc, "_u8", " 255", &cerr);
    if(FAIL(ret))
    {
        yatest_err("config_value_set failed with %s", error_gettext(ret));
        return 1;
    }
    if(g_config._u8 != 255)
    {
        yatest_err("_u8 is not 255");
        return 1;
    }
    ret = config_value_set(desc, "_u8", "0", &cerr);
    if(FAIL(ret))
    {
        yatest_err("config_value_set failed with %s", error_gettext(ret));
        return 1;
    }
    if(g_config._u8 != 0)
    {
        yatest_err("_u8 is not 0");
        return 1;
    }
    ret = config_value_set(desc, "_u8", "x", &cerr);
    if(ISOK(ret))
    {
        yatest_err("config_value_set should have failed (x)");
        return 1;
    }
    ret = config_value_set(desc, "_u8", "-1", &cerr);
    if(ISOK(ret))
    {
        yatest_err("config_value_set should have failed (<0)");
        return 1;
    }
    ret = config_value_set(desc, "_u8", "2550", &cerr);
    if(ISOK(ret))
    {
        yatest_err("config_value_set should have failed (range)");
        return 1;
    }

    finalise3();
    return 0;
}

static int dnskey_algorithm_test()
{
    int                          ret;
    config_error_t               cerr;
    config_section_descriptor_t *desc = type_test_init(&cerr);

    ret = config_value_set(desc, "_dnskey_algorithm", "10", &cerr);
    if(FAIL(ret))
    {
        yatest_err("config_value_set failed with %s", error_gettext(ret));
        return 1;
    }
    if(g_config._dnskey_algorithm != 10)
    {
        yatest_err("_dnskey_algorithm is not 10");
        return 1;
    }
    ret = config_value_set(desc, "_dnskey_algorithm", "ED25519", &cerr);
    if(FAIL(ret))
    {
        yatest_err("config_value_set failed with %s", error_gettext(ret));
        return 1;
    }
    if(g_config._dnskey_algorithm != DNSKEY_ALGORITHM_ED25519)
    {
        yatest_err("_dnskey_algorithm is not 15");
        return 1;
    }
    ret = config_value_set(desc, "_dnskey_algorithm", "x", &cerr);
    if(ISOK(ret))
    {
        yatest_err("config_value_set should have failed (x)");
        return 1;
    }

    finalise3();
    return 0;
}

static int string_test()
{
    int                          ret;
    config_error_t               cerr;
    config_section_descriptor_t *desc = type_test_init(&cerr);

    ret = config_value_set(desc, "_string", "text", &cerr);
    if(FAIL(ret))
    {
        yatest_err("config_value_set failed with %s", error_gettext(ret));
        return 1;
    }
    if(strcmp(g_config._string, "text") != 0)
    {
        yatest_err("_string is not 'text'");
        return 1;
    }
    ret = config_value_set(desc, "_string", "text", &cerr);
    if(FAIL(ret))
    {
        yatest_err("config_value_set failed with %s", error_gettext(ret));
        return 1;
    }
    if(strcmp(g_config._string, "text") != 0)
    {
        yatest_err("_string is not 'text'");
        return 1;
    }
    ret = config_value_set(desc, "_string", "text2", &cerr);
    if(FAIL(ret))
    {
        yatest_err("config_value_set failed with %s", error_gettext(ret));
        return 1;
    }
    if(strcmp(g_config._string, "text2") != 0)
    {
        yatest_err("_string is not 'text2'");
        return 1;
    }

    finalise3();
    return 0;
}

static int string_copy_test()
{
    int                          ret;
    config_error_t               cerr;
    config_section_descriptor_t *desc = type_test_init(&cerr);

    ret = config_value_set(desc, "_string_copy", "text", &cerr);
    if(FAIL(ret))
    {
        yatest_err("config_value_set failed with %s", error_gettext(ret));
        return 1;
    }
    if(strcmp(g_config._string_copy, "text") != 0)
    {
        yatest_err("_string_copy is not 'text'");
        return 1;
    }
    ret = config_value_set(desc, "_string_copy", "text", &cerr);
    if(FAIL(ret))
    {
        yatest_err("config_value_set failed with %s", error_gettext(ret));
        return 1;
    }
    ret = config_value_set(desc, "_string_copy", "0123456789012345678901234567890123456789012345678901234567890123456789", &cerr);
    if(ISOK(ret))
    {
        yatest_err("config_value_set should have failed");
        return 1;
    }

    finalise3();
    return 0;
}

static int string_array_test()
{
    int                          ret;
    config_error_t               cerr;
    config_section_descriptor_t *desc = type_test_init(&cerr);

    ret = config_value_set(desc, "_string_array", "item0", &cerr);
    if(FAIL(ret))
    {
        yatest_err("config_value_set failed with %s", error_gettext(ret));
        return 1;
    }
    if(ptr_vector_size(&g_config._string_array) != 1)
    {
        yatest_err("_string_array size = %i != %i", ptr_vector_size(&g_config._string_array), 1);
        return 1;
    }
    ret = config_value_set(desc, "_string_array", "item1", &cerr);
    if(FAIL(ret))
    {
        yatest_err("config_value_set failed with %s", error_gettext(ret));
        return 1;
    }
    if(ptr_vector_size(&g_config._string_array) != 2)
    {
        yatest_err("_string_array size = %i != %i", ptr_vector_size(&g_config._string_array), 2);
        return 1;
    }
    ret = config_value_set(desc, "_string_array", "item2", &cerr);
    if(FAIL(ret))
    {
        yatest_err("config_value_set failed with %s", error_gettext(ret));
        return 1;
    }
    if(ptr_vector_size(&g_config._string_array) != 3)
    {
        yatest_err("_string_array size = %i != %i", ptr_vector_size(&g_config._string_array), 3);
        return 1;
    }
    ret = config_value_set(desc, "_string_array", "item3", &cerr);
    if(FAIL(ret))
    {
        yatest_err("config_value_set failed with %s", error_gettext(ret));
        return 1;
    }
    if(ptr_vector_size(&g_config._string_array) != 4)
    {
        yatest_err("_string_array size = %i != %i", ptr_vector_size(&g_config._string_array), 4);
        return 1;
    }
    ret = config_value_set(desc, "_string_array", "item4", &cerr);
    if(ISOK(ret))
    {
        yatest_err("config_value_set should have failed");
        return 1;
    }
    if(ptr_vector_size(&g_config._string_array) != 4)
    {
        yatest_err("_string_array size = %i != %i", ptr_vector_size(&g_config._string_array), 4);
        return 1;
    }

    finalise3();
    return 0;
}

static int password_test()
{
    int                          ret;
    config_error_t               cerr;
    config_section_descriptor_t *desc = type_test_init(&cerr);

    ret = config_value_set(desc, "_password", "text", &cerr);
    if(FAIL(ret))
    {
        yatest_err("config_value_set failed with %s", error_gettext(ret));
        return 1;
    }
    if(strcmp(g_config._password, "text") != 0)
    {
        yatest_err("_password is not 'text'");
        return 1;
    }
    ret = config_value_set(desc, "_password", "text", &cerr);
    if(FAIL(ret))
    {
        yatest_err("config_value_set failed with %s", error_gettext(ret));
        return 1;
    }
    if(strcmp(g_config._password, "text") != 0)
    {
        yatest_err("_password is not 'text'");
        return 1;
    }
    ret = config_value_set(desc, "_password", "text2", &cerr);
    if(FAIL(ret))
    {
        yatest_err("config_value_set failed with %s", error_gettext(ret));
        return 1;
    }
    if(strcmp(g_config._password, "text2") != 0)
    {
        yatest_err("_password is not 'text2'");
        return 1;
    }

    finalise3();
    return 0;
}

static int fqdn_test()
{
    int                          ret;
    config_error_t               cerr;
    config_section_descriptor_t *desc = type_test_init(&cerr);

    ret = config_value_set(desc, "_fqdn", "yadifa.eu", &cerr);
    if(FAIL(ret))
    {
        yatest_err("config_value_set failed with %s", error_gettext(ret));
        return 1;
    }
    if(!dnsname_equals(g_config._fqdn, (const uint8_t *)"\006yadifa\002eu"))
    {
        yatest_err("_fqdn is not 'yadifa.eu'");
        return 1;
    }
    ret = config_value_set(desc, "_fqdn", "yadifa.eu", &cerr);
    if(FAIL(ret))
    {
        yatest_err("config_value_set failed with %s", error_gettext(ret));
        return 1;
    }
    if(!dnsname_equals(g_config._fqdn, (const uint8_t *)"\006yadifa\002eu"))
    {
        yatest_err("_fqdn is not 'yadifa.eu'");
        return 1;
    }
    ret = config_value_set(desc, "_fqdn", "yadifa.be", &cerr);
    if(FAIL(ret))
    {
        yatest_err("config_value_set failed with %s", error_gettext(ret));
        return 1;
    }
    if(!dnsname_equals(g_config._fqdn, (const uint8_t *)"\006yadifa\002be"))
    {
        yatest_err("_fqdn is not 'yadifa.be'");
        return 1;
    }

    finalise3();
    return 0;
}

static int path_test()
{
    int                          ret;
    config_error_t               cerr;
    config_section_descriptor_t *desc = type_test_init(&cerr);

    ret = config_value_set(desc, "_path", PATH_VALUE, &cerr);
    if(FAIL(ret))
    {
        yatest_err("config_value_set failed with %s", error_gettext(ret));
        return 1;
    }
    if(strcmp(g_config._path, PATH_VALUE "/") != 0)
    {
        yatest_err("_path is not '" PATH_VALUE "'");
        return 1;
    }
    ret = config_value_set(desc, "_path", PATH_VALUE, &cerr);
    if(FAIL(ret))
    {
        yatest_err("config_value_set failed with %s", error_gettext(ret));
        return 1;
    }
    if(strcmp(g_config._path, PATH_VALUE "/") != 0)
    {
        yatest_err("_path is not '" PATH_VALUE "'");
        return 1;
    }

    ret = config_value_set(desc, "_path", LOGPATH_VALUE "/", &cerr);
    if(FAIL(ret))
    {
        yatest_err("config_value_set failed with %s", error_gettext(ret));
        return 1;
    }
    if(strcmp(g_config._path, LOGPATH_VALUE "/") != 0)
    {
        yatest_err("_path is not '" LOGPATH_VALUE "'");
        return 1;
    }

    finalise3();
    return 0;
}

static int logpath_test()
{
    int                          ret;
    config_error_t               cerr;
    config_section_descriptor_t *desc = type_test_init(&cerr);

    ret = config_value_set(desc, "_logpath", PATH_VALUE, &cerr);
    if(FAIL(ret))
    {
        yatest_err("config_value_set failed with %s", error_gettext(ret));
        return 1;
    }
    if(strcmp(g_config._logpath, PATH_VALUE "/") != 0)
    {
        yatest_err("_logpath is not '" PATH_VALUE "'");
        return 1;
    }
    ret = config_value_set(desc, "_logpath", PATH_VALUE, &cerr);
    if(FAIL(ret))
    {
        yatest_err("config_value_set failed with %s", error_gettext(ret));
        return 1;
    }
    if(strcmp(g_config._logpath, PATH_VALUE "/") != 0)
    {
        yatest_err("_logpath is not '" PATH_VALUE "'");
        return 1;
    }

    ret = config_value_set(desc, "_logpath", LOGPATH_VALUE "/", &cerr);
    if(FAIL(ret))
    {
        yatest_err("config_value_set failed with %s", error_gettext(ret));
        return 1;
    }
    if(strcmp(g_config._logpath, LOGPATH_VALUE "/") != 0)
    {
        yatest_err("_logpath is not '" LOGPATH_VALUE "'");
        return 1;
    }

    finalise3();
    return 0;
}

static int chroot_test()
{
    int                          ret;
    config_error_t               cerr;
    config_section_descriptor_t *desc = type_test_init(&cerr);

    ret = config_value_set(desc, "_chroot", PATH_VALUE, &cerr);
    if(FAIL(ret))
    {
        yatest_err("config_value_set failed with %s", error_gettext(ret));
        return 1;
    }
    if(strcmp(g_config._chroot, PATH_VALUE "/") != 0)
    {
        yatest_err("_chroot is not '" PATH_VALUE "'");
        return 1;
    }
    ret = config_value_set(desc, "_chroot", PATH_VALUE, &cerr);
    if(FAIL(ret))
    {
        yatest_err("config_value_set failed with %s", error_gettext(ret));
        return 1;
    }
    if(strcmp(g_config._chroot, PATH_VALUE "/") != 0)
    {
        yatest_err("_chroot is not '" PATH_VALUE "'");
        return 1;
    }

    ret = config_value_set(desc, "_chroot", LOGPATH_VALUE "/", &cerr);
    if(FAIL(ret))
    {
        yatest_err("config_value_set failed with %s", error_gettext(ret));
        return 1;
    }
    if(strcmp(g_config._chroot, LOGPATH_VALUE "/") != 0)
    {
        yatest_err("_chroot is not '" LOGPATH_VALUE "'");
        return 1;
    }

    finalise3();
    return 0;
}

static int file_test()
{
    int                          ret;
    config_error_t               cerr;
    config_section_descriptor_t *desc = type_test_init(&cerr);

    ret = config_value_set(desc, "_file", FILE_VALUE, &cerr);
    if(FAIL(ret))
    {
        yatest_err("config_value_set failed with %s", error_gettext(ret));
        return 1;
    }
    if(strcmp(g_config._file, FILE_VALUE) != 0)
    {
        yatest_err("_file is not '" FILE_VALUE "'");
        return 1;
    }
    ret = config_value_set(desc, "_file", FILE_VALUE, &cerr);
    if(FAIL(ret))
    {
        yatest_err("config_value_set failed with %s", error_gettext(ret));
        return 1;
    }
    if(strcmp(g_config._file, FILE_VALUE) != 0)
    {
        yatest_err("_file is not '" FILE_VALUE "'");
        return 1;
    }
    ret = config_value_set(desc, "_file", FILE2_VALUE, &cerr);
    if(FAIL(ret))
    {
        yatest_err("config_value_set failed with %s", error_gettext(ret));
        return 1;
    }
    if(strcmp(g_config._file, FILE2_VALUE) != 0)
    {
        yatest_err("_file is not '" FILE2_VALUE "'");
        return 1;
    }
    ret = config_value_set(desc, "_file", FILE_VALUE "-does-not-exist", &cerr);
    if(ISOK(ret))
    {
        yatest_err("config_value_set should have failed");
        return 1;
    }

    finalise3();
    return 0;
}

static int uid_test()
{
    int                          ret;
    config_error_t               cerr;
    config_section_descriptor_t *desc = type_test_init(&cerr);

    ret = config_value_set(desc, "_uid", UID_VALUE, &cerr);
    if(FAIL(ret))
    {
        yatest_err("config_value_set failed with %s", error_gettext(ret));
        return 1;
    }
    if(g_config._uid != UID_VALUE_INT)
    {
        yatest_err("_uid is not '" UID_VALUE "'");
        return 1;
    }
    ret = config_value_set(desc, "_uid", "0", &cerr);
    if(FAIL(ret))
    {
        yatest_err("config_value_set failed with %s", error_gettext(ret));
        return 1;
    }
    if(g_config._uid != 0)
    {
        yatest_err("_uid is not 0");
        return 1;
    }
    ret = config_value_set(desc, "_uid", "-", &cerr);
    if(FAIL(ret))
    {
        yatest_err("config_value_set failed with %s", error_gettext(ret));
        return 1;
    }
    if(g_config._uid != getuid())
    {
        yatest_err("_uid is not %i", getuid());
        return 1;
    }
    ret = config_value_set(desc, "_uid", "no-such-user-uid-test", &cerr);
    if(ISOK(ret))
    {
        yatest_err("config_value_set should have failed");
        return 1;
    }

    finalise3();
    return 0;
}

static int gid_test()
{
    int                          ret;
    config_error_t               cerr;
    config_section_descriptor_t *desc = type_test_init(&cerr);

    ret = config_value_set(desc, "_gid", GID_VALUE, &cerr);
    if(FAIL(ret))
    {
        yatest_err("config_value_set failed with %s", error_gettext(ret));
        return 1;
    }
    if(g_config._gid != GID_VALUE_INT)
    {
        yatest_err("_gid is not '" GID_VALUE "'");
        return 1;
    }
    ret = config_value_set(desc, "_gid", "0", &cerr);
    if(FAIL(ret))
    {
        yatest_err("config_value_set failed with %s", error_gettext(ret));
        return 1;
    }
    if(g_config._gid != 0)
    {
        yatest_err("_gid is not 0");
        return 1;
    }
    ret = config_value_set(desc, "_gid", "-", &cerr);
    if(FAIL(ret))
    {
        yatest_err("config_value_set failed with %s", error_gettext(ret));
        return 1;
    }
    if(g_config._gid != getgid())
    {
        yatest_err("_gid is not %i", getgid());
        return 1;
    }
    ret = config_value_set(desc, "_gid", "no-such-user-gid-test", &cerr);
    if(ISOK(ret))
    {
        yatest_err("config_value_set should have failed");
        return 1;
    }

    finalise3();
    return 0;
}

static int dnstype_test()
{
    int                          ret;
    config_error_t               cerr;
    config_section_descriptor_t *desc = type_test_init(&cerr);

    ret = config_value_set(desc, "_dns_type", "A", &cerr);
    if(FAIL(ret))
    {
        yatest_err("config_value_set failed with %s", error_gettext(ret));
        return 1;
    }
    if(g_config._dns_type != ntohs(TYPE_A))
    {
        yatest_err("_dns_type is not A");
        return 1;
    }
    ret = config_value_set(desc, "_dns_type", "TYPE2", &cerr);
    if(FAIL(ret))
    {
        yatest_err("config_value_set failed with %s", error_gettext(ret));
        return 1;
    }
    if(g_config._dns_type != ntohs(TYPE_NS))
    {
        yatest_err("_dns_type is not NS");
        return 1;
    }
    ret = config_value_set(desc, "_dns_type", "no-such-dns-type", &cerr);
    if(ISOK(ret))
    {
        yatest_err("config_value_set should have failed");
        return 1;
    }

    finalise3();
    return 0;
}

static int dnsclass_test()
{
    int                          ret;
    config_error_t               cerr;
    config_section_descriptor_t *desc = type_test_init(&cerr);

    ret = config_value_set(desc, "_dns_class", "IN", &cerr);
    if(FAIL(ret))
    {
        yatest_err("config_value_set failed with %s", error_gettext(ret));
        return 1;
    }
    if(g_config._dns_class != ntohs(CLASS_IN))
    {
        yatest_err("_dns_class is not IN");
        return 1;
    }
    ret = config_value_set(desc, "_dns_class", "CLASS3", &cerr);
    if(FAIL(ret))
    {
        yatest_err("config_value_set failed with %s", error_gettext(ret));
        return 1;
    }
    if(g_config._dns_class != ntohs(CLASS_CH))
    {
        yatest_err("_dns_class is not NS");
        return 1;
    }
    ret = config_value_set(desc, "_dns_class", "no-such-dns-class", &cerr);
    if(ISOK(ret))
    {
        yatest_err("config_value_set should have failed");
        return 1;
    }

    finalise3();
    return 0;
}

static int enum_test()
{
    int                          ret;
    config_error_t               cerr;
    config_section_descriptor_t *desc = type_test_init(&cerr);

    ret = config_value_set(desc, "_enum", "one", &cerr);
    if(FAIL(ret))
    {
        yatest_err("config_value_set failed with %s", error_gettext(ret));
        return 1;
    }
    if(g_config._enum != 1)
    {
        yatest_err("_enum is not 1");
        return 1;
    }
    ret = config_value_set(desc, "_enum", "no-such-enum", &cerr);
    if(ISOK(ret))
    {
        yatest_err("config_value_set should have failed");
        return 1;
    }

    finalise3();
    return 0;
}

static int enum8_test()
{
    int                          ret;
    config_error_t               cerr;
    config_section_descriptor_t *desc = type_test_init(&cerr);

    ret = config_value_set(desc, "_enum8", "one", &cerr);
    if(FAIL(ret))
    {
        yatest_err("config_value_set failed with %s", error_gettext(ret));
        return 1;
    }
    if(g_config._enum8 != 1)
    {
        yatest_err("_enum8 is not 1");
        return 1;
    }
    ret = config_value_set(desc, "_enum8", "no-such-enum", &cerr);
    if(ISOK(ret))
    {
        yatest_err("config_value_set should have failed");
        return 1;
    }

    finalise3();
    return 0;
}

static uint8_t localhost_ip4[4] = {127, 0, 0, 1};
static uint8_t localhost2_ip4[4] = {127, 0, 0, 2};
static uint8_t localhost_ip6[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
static uint8_t localhost2_ip6[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2};

static int     host_list_test()
{
    int                          ret;
    config_error_t               cerr;
    config_section_descriptor_t *desc = type_test_init(&cerr);

    tsig_key_t                  *mykey = tsig_get(MYKEY_NAME);

    host_address_t              *localhost_v4 = host_address_new_instance_ipv4(localhost_ip4, NU16(53));
    host_address_t              *localhost2_v4 = host_address_new_instance_ipv4(localhost2_ip4, NU16(53));
    host_address_t              *localhost_v6 = host_address_new_instance_ipv6(localhost_ip6, NU16(53));
    host_address_t              *localhost2_v6 = host_address_new_instance_ipv6(localhost2_ip6, NU16(53));
    host_address_t              *www_yadifa_eu = host_address_new_instance_dname((const uint8_t *)"\003www\006yadifa\002eu", NU16(53));
    host_address_t              *localhost_v4_key = host_address_new_instance_ipv4_tsig(localhost_ip4, NU16(53), mykey);

    ret = config_value_set(desc, "_host_list", NULL, &cerr);
    if(ISOK(ret))
    {
        yatest_err("config_value_set should have failed");
        return 1;
    }

    ret = config_value_set(desc, "_host_list", "127.0.0.1 port 53", &cerr);
    if(FAIL(ret))
    {
        yatest_err("config_value_set failed with %s", error_gettext(ret));
        return 1;
    }
    if(host_address_compare(g_config._host_list, localhost_v4) != 0)
    {
        yatest_err("_host_list is not 127.0.0.1:53");
        return 1;
    }

    ret = config_value_set(desc, "_host_list", "::1 port 53, ::2 port 53, 127.0.0.1 port 53, 127.0.0.2 port 53", &cerr);
    if(FAIL(ret))
    {
        yatest_err("config_value_set failed with %s", error_gettext(ret));
        return 1;
    }
    if(host_address_compare(g_config._host_list, localhost_v6) != 0)
    {
        yatest_err("_host_list is not ::1:53");
        return 1;
    }
    if(host_address_compare(g_config._host_list->next, localhost2_v6) != 0)
    {
        yatest_err("_host_list is not ::2:53");
        return 1;
    }
    if(host_address_compare(g_config._host_list->next->next, localhost_v4) != 0)
    {
        yatest_err("_host_list is not 127.0.0.1:53");
        return 1;
    }
    if(host_address_compare(g_config._host_list->next->next->next, localhost2_v4) != 0)
    {
        yatest_err("_host_list is not 127.0.0.2:53");
        return 1;
    }

    // fqdn not allowed

    ret = config_value_set(desc, "_host_list", "127.0.0.1 port 53 key mykey", &cerr);
    if(FAIL(ret))
    {
        yatest_err("config_value_set failed with %s", error_gettext(ret));
        return 1;
    }
    if(host_address_compare(g_config._host_list, localhost_v4_key) != 0)
    {
        yatest_err("_host_list is not 127.0.0.1:53+mykey");
        return 1;
    }
    ret = config_value_set(desc, "_host_list", "127.0.0.1 port 53 key not-a-registered-key", &cerr);
    if(ISOK(ret))
    {
        yatest_err("config_value_set should have failed");
        return 1;
    }

    // key

    ret = config_value_set(desc, "_host_list", "www.yadifa.eu port 53", &cerr);
    if(ISOK(ret))
    {
        yatest_err("config_value_set should have failed");
        return 1;
    }

    // v6 on no-v6

    ret = config_value_set(desc, "_host_list_v4", "::1", &cerr);
    if(ISOK(ret))
    {
        yatest_err("config_value_set should have failed");
        return 1;
    }

    // v4 on no-v4

    ret = config_value_set(desc, "_host_list_v6", "127.0.0.1", &cerr);
    if(ISOK(ret))
    {
        yatest_err("config_value_set should have failed");
        return 1;
    }

    // port on no-port

    ret = config_value_set(desc, "_host_list_v4", "127.0.0.1 port 53", &cerr);
    if(ISOK(ret))
    {
        yatest_err("config_value_set should have failed");
        return 1;
    }

    // invalid port

    ret = config_value_set(desc, "_host_list", "127.0.0.1 port dns", &cerr);
    if(ISOK(ret))
    {
        yatest_err("config_value_set should have failed");
        return 1;
    }

    // key on no-key

    ret = config_value_set(desc, "_host_list_v4", "127.0.0.1 key mykey", &cerr);
    if(ISOK(ret))
    {
        yatest_err("config_value_set should have failed");
        return 1;
    }

    // tls

    ret = config_value_set(desc, "_host_list_v4", "127.0.0.1 tls", &cerr);
    if(FAIL(ret))
    {
        yatest_err("config_value_set failed with %s", error_gettext(ret));
        return 1;
    }
    if(g_config._host_list_v4->tls != HOST_ADDRESS_TLS_ENFORCE)
    {
        yatest_err("HOST_ADDRESS_TLS_ENFORCE not set");
        return 1;
    }

    ret = config_value_set(desc, "_host_list_v4", "127.0.0.1 notls", &cerr);
    if(FAIL(ret))
    {
        yatest_err("config_value_set failed with %s", error_gettext(ret));
        return 1;
    }
    if(g_config._host_list_v4->tls != HOST_ADDRESS_TLS_DISABLE)
    {
        yatest_err("HOST_ADDRESS_TLS_DISABLE not set");
        return 1;
    }

    // append

    ret = config_value_set(desc, "_host_list_append", "::1 port 53", &cerr);
    if(FAIL(ret))
    {
        yatest_err("config_value_set failed with %s", error_gettext(ret));
        return 1;
    }
    ret = config_value_set(desc, "_host_list_append", "::2 port 53", &cerr);
    if(FAIL(ret))
    {
        yatest_err("config_value_set failed with %s", error_gettext(ret));
        return 1;
    }
    if(host_address_compare(g_config._host_list_append, localhost_v6) != 0)
    {
        yatest_err("_host_list_append is not ::1:53");
        return 1;
    }
    if(host_address_compare(g_config._host_list_append->next, localhost2_v6) != 0)
    {
        yatest_err("_host_list_append is not ::2:53");
        return 1;
    }

    // fqdn

    ret = config_value_set(desc, "_host_list_fqdn", "www.yadifa.eu port 53", &cerr);
    if(FAIL(ret))
    {
        yatest_err("config_value_set failed with %s", error_gettext(ret));
        return 1;
    }
    if(host_address_compare(g_config._host_list_fqdn, www_yadifa_eu) != 0)
    {
        yatest_err("_host_list_fqdn is not www.yadifa.eu:53");
        return 1;
    }

    // too many

    ret = config_value_set(desc, "_host_list_ex", "::1 port 53, ::2 port 53, 127.0.0.1 port 53, 127.0.0.2 port 53, 127.0.0.3 port 53", &cerr);
    if(ISOK(ret))
    {
        yatest_err("config_value_set should have failed (count = %i)", host_address_count(g_config._host_list_ex));
        return 1;
    }

    // not too many

    ret = config_value_set(desc, "_host_list_ex", "::1 port 53, ::2 port 53, 127.0.0.1 port 53, 127.0.0.2 port 53,", &cerr);
    if(FAIL(ret))
    {
        yatest_err("config_value_set failed with %s", error_gettext(ret));
        return 1;
    }

    // ends with a separator

    ret = config_value_set(desc, "_host_list", "127.0.0.1 port 53,", &cerr);
    if(FAIL(ret))
    {
        yatest_err("config_value_set failed with %s", error_gettext(ret));
        return 1;
    }
    if(host_address_compare(g_config._host_list, localhost_v4) != 0)
    {
        yatest_err("_host_list is not 127.0.0.1:53");
        return 1;
    }
    if(g_config._host_list->next != NULL)
    {
        yatest_err("_host_list has more than one item");
        return 1;
    }

    finalise3();
    return 0;
}

// hmac:name:base64-key

static int tsig_test()
{
    int                          ret;
    config_error_t               cerr;
    config_section_descriptor_t *desc = type_test_init(&cerr);

    ret = config_value_set(desc, "_tsig_item", "hmac-sha256:newkey:ZmU1Y2QwNzlhMDQ0ZTZjZGRiYTE5NWE0MjQzNTlkNmQK", &cerr);
    if(FAIL(ret))
    {
        yatest_err("config_value_set failed with %s", error_gettext(ret));
        return 1;
    }
    if(g_config._tsig_item == NULL)
    {
        yatest_err("_tsig_item is NULL");
        return 1;
    }
    tsig_key_t *newkey = tsig_get_with_ascii_name("newkey");
    if(g_config._tsig_item != newkey)
    {
        yatest_err("_tsig_item is not newkey");
        return 1;
    }

    ret = config_value_set(desc, "_tsig_item", "newkey2:ZmU1Y2QwNzlhMDQ0ZTZjZGRiYTE5NWE0MjQzNTlkNmQK", &cerr);
    if(FAIL(ret))
    {
        yatest_err("config_value_set failed with %s", error_gettext(ret));
        return 1;
    }
    if(g_config._tsig_item == NULL)
    {
        yatest_err("_tsig_item is NULL");
        return 1;
    }
    tsig_key_t *newkey2 = tsig_get_with_ascii_name("newkey2");
    if(g_config._tsig_item != newkey2)
    {
        yatest_err("_tsig_item is not newkey2");
        return 1;
    }

    // bad base64

    ret = config_value_set(desc, "_tsig_item", "newkey3:ZmU$Y2QwNzl$MDQ0ZTZjZ$RiYTE5NW$0MjQzNTlkNmQK", &cerr);
    if(ISOK(ret))
    {
        yatest_err("config_value_set should have failed");
        return 1;
    }

    // bad name

    ret = config_value_set(desc, "_tsig_item", "new..key4:ZmU1Y2QwNzlhMDQ0ZTZjZGRiYTE5NWE0MjQzNTlkNmQK", &cerr);
    if(ISOK(ret))
    {
        yatest_err("config_value_set should have failed (invalid double-dot fqdn)");
        return 1;
    }

    // too big name

    ret = config_value_set(desc, "_tsig_item", "0123456789012345678901234567890123456789012345678901234567890123:ZmU1Y2QwNzlhMDQ0ZTZjZGRiYTE5NWE0MjQzNTlkNmQK", &cerr);
    if(ISOK(ret))
    {
        yatest_err("config_value_set should have failed");
        return 1;
    }

    // unknown name

    ret = config_value_set(desc, "_tsig_item", "hmac-dummy:newkey5:ZmU1Y2QwNzlhMDQ0ZTZjZGRiYTE5NWE0MjQzNTlkNmQK", &cerr);
    if(ISOK(ret))
    {
        yatest_err("config_value_set should have failed");
        return 1;
    }

    finalise3();
    return 0;
}

static int obsolete_test()
{
    int                          ret;
    config_error_t               cerr;
    config_section_descriptor_t *desc = type_test_init(&cerr);

    ret = config_value_set(desc, "_obsolete", "hmac-sha256:newkey:ZmU1Y2QwNzlhMDQ0ZTZjZGRiYTE5NWE0MjQzNTlkNmQK", &cerr);
    if(FAIL(ret))
    {
        yatest_err("config_value_set failed with %s", error_gettext(ret));
        return 1;
    }
    finalise3();
    return 0;
}

static int register_struct_error_test()
{
    int ret;
    dnscore_init();
    config_init();
    tsig_init();

    memset(&g_config, 0, sizeof(config_test_t));
    ptr_vector_init_empty(&g_config._string_array);

    ret = config_register_struct("config", config_test_error_desc, &g_config, 1);
    if(ISOK(ret))
    {
        yatest_err("config_register_struct should have failed");
        exit(1);
    }

    ret = config_register_struct("config", config_test_desc, &g_config, 1);
    if(FAIL(ret))
    {
        yatest_err("config_register_struct failed with %s", error_gettext(ret));
        exit(1);
    }

    ret = config_register_struct("config", config_test_desc, &g_config, 1);
    if(ISOK(ret))
    {
        yatest_err("config_register_struct should have failed");
        exit(1);
    }

    return 0;
}

static int config_section_struct_free_test()
{
    int ret;
    init();
    config_error_t cerr;
    config_error_init(&cerr);
    ret = config_read(TEST_CONFIG_FILE, &cerr);
    if(FAIL(ret))
    {
        yatest_err("error: file: %s:%i", cerr.file, cerr.line_number);
        yatest_err("error: variable: %s", config_error_get_variable_name(&cerr));
        yatest_err("error: line: %s", cerr.line);
        yatest_err("config_read failed with %s", error_gettext(ret));
        return 1;
    }

    config_section_descriptor_t *desc = config_section_get_descriptor("config");
    config_section_struct_free(desc, &g_config);
    if(g_config._host_list != NULL)
    {
        yatest_err("_host_list not freed");
        return 1;
    }
    if(g_config._host_list_ex != NULL)
    {
        yatest_err("_host_list_ex not freed");
        return 1;
    }
    if(g_config._chroot != NULL)
    {
        yatest_err("_chroot not freed");
        return 1;
    }
    if(g_config._file != NULL)
    {
        yatest_err("_file not freed");
        return 1;
    }
    if(g_config._fqdn != NULL)
    {
        yatest_err("_fqdn not freed");
        return 1;
    }
    if(g_config._logpath != NULL)
    {
        yatest_err("_logpath not freed");
        return 1;
    }
    if(g_config._path != NULL)
    {
        yatest_err("_path not freed");
        return 1;
    }
    if(g_config._password != NULL)
    {
        yatest_err("_password not freed");
        return 1;
    }
    if(g_config._string != NULL)
    {
        yatest_err("_string not freed");
        return 1;
    }
    if(ptr_vector_size(&g_config._string_array) != 0)
    {
        yatest_err("_string_array not freed");
        return 1;
    }

    finalise3();
    return 0;
}

static int config_value_get_source_test()
{
    int ret;
    init();
    config_error_t cerr;
    config_error_init(&cerr);

    int default_source = config_get_default_source();
    yatest_log("default_source=%i", default_source);
    config_set_default_source(default_source + 1);
    if(default_source + 1 != config_get_default_source())
    {
        yatest_err("config_set_default_source does not appear to work");
        return 1;
    }
    config_set_default_source(default_source);

    ret = config_read(TEST_CONFIG_FILE, &cerr);
    if(FAIL(ret))
    {
        yatest_err("error: file: %s:%i", cerr.file, cerr.line_number);
        yatest_err("error: variable: %s", config_error_get_variable_name(&cerr));
        yatest_err("error: line: %s", cerr.line);
        yatest_err("config_read failed with %s", error_gettext(ret));
        return 1;
    }

    ret = config_value_get_source("config", "_bool");
    if(ret != 0)
    {
        yatest_err("expected source to be 0, got %i instead", ret);
        return 1;
    }

    finalise3();
    return 0;
}

static int config_value_set_to_default_test()
{
    int ret;
    init();
    config_error_t cerr;
    config_error_init(&cerr);
    ret = config_read(TEST_CONFIG_FILE, &cerr);
    if(FAIL(ret))
    {
        yatest_err("error: file: %s:%i", cerr.file, cerr.line_number);
        yatest_err("error: variable: %s", config_error_get_variable_name(&cerr));
        yatest_err("error: line: %s", cerr.line);
        yatest_err("config_read failed with %s", error_gettext(ret));
        return 1;
    }
    if(!g_config._bool)
    {
        yatest_err("_bool is false (1)");
        return 1;
    }
    ret = config_value_get_source("config", "_bool");
    if(ret != 0)
    {
        yatest_err("expected source to be 0, got %i instead", ret);
        return 1;
    }
    ret = config_value_set_to_default("config", "_bool", &cerr);
    if(FAIL(ret))
    {
        yatest_err("config_value_set_to_default_test failed with %s", error_gettext(ret));
        return 1;
    }
    if(g_config._bool)
    {
        yatest_err("_bool is true (0)");
        return 1;
    }
    config_section_descriptor_t *desc = config_section_get_descriptor("config");
    ret = config_value_set(desc, "_bool", "1", &cerr);
    if(FAIL(ret))
    {
        yatest_err("config_value_set failed with %s", error_gettext(ret));
        return 1;
    }
    if(!g_config._bool)
    {
        yatest_err("_bool is false (1)");
        return 1;
    }
    ret = config_value_get_source("config", "_bool");
    if(ret != 0)
    {
        yatest_err("expected source to be 0, got %i instead", ret);
        return 1;
    }

    // no such section

    ret = config_value_set_to_default("no-such-section", "_bool", &cerr);
    if(ISOK(ret))
    {
        yatest_err("config_value_set_to_default_test should have failed (section)");
        return 1;
    }

    // no such field

    ret = config_value_set_to_default("config", "no-such-field", &cerr);
    if(ISOK(ret))
    {
        yatest_err("config_value_set_to_default_test should have failed (field)");
        return 1;
    }

    finalise3();
    return 0;
}

static int       section_read_callback_test_cb_counter = 0;

static ya_result section_read_callback_test_cb(const char *section_name, int section_index)
{
    yatest_log("config_callback_function(%s, %i)", section_name, section_index);
    ++section_read_callback_test_cb_counter;
    return SUCCESS;
}

static int section_read_callback_test()
{
    int ret;
    init();
    config_error_t cerr;
    config_error_init(&cerr);
    ret = config_add_on_section_read_callback("config", section_read_callback_test_cb);
    if(FAIL(ret))
    {
        yatest_err("config_add_on_section_read_callback failed with %s", error_gettext(ret));
        return 1;
    }
    ret = config_add_on_section_read_callback("config", section_read_callback_test_cb);
    if(ISOK(ret))
    {
        yatest_err("config_add_on_section_read_callback should have failed");
        return 1;
    }
    ret = config_read(TEST_CONFIG_FILE, &cerr);
    if(FAIL(ret))
    {
        yatest_err("error: file: %s:%i", cerr.file, cerr.line_number);
        yatest_err("error: variable: %s", config_error_get_variable_name(&cerr));
        yatest_err("error: line: %s", cerr.line);
        yatest_err("config_read failed with %s", error_gettext(ret));
        return 1;
    }
    ret = config_remove_on_section_read_callback("config", section_read_callback_test_cb);
    if(FAIL(ret))
    {
        yatest_err("config_remove_on_section_read_callback failed with %s", error_gettext(ret));
        return 1;
    }
    ret = config_remove_on_section_read_callback("config", section_read_callback_test_cb);
    if(ISOK(ret))
    {
        yatest_err("config_remove_on_section_read_callback should have failed");
        return 1;
    }
    finalise3();
    return 0;
}

static int file_line_get_test()
{
    int ret;
    init();
    config_error_t cerr;
    config_error_init(&cerr);

    struct config_source_s sources[3];
    config_source_set_commandline(&sources[0], config_cmdline, config_test_argc, config_test_argv);
    config_source_set_buffer(&sources[1], "local", 3, config_test_2_conf, sizeof(config_test_2_conf) - 1);
    config_source_set_file(&sources[2], TEST_CONFIG_FILE, 2);

    ret = config_read_from_sources(sources, 3, &cerr);

    if(FAIL(ret))
    {
        yatest_err("config_read_from_sources failed with %s", error_gettext(ret));
        return 1;
    }

    config_section_descriptor_t *desc = config_section_get_descriptor("config");
    address_to_location_t       *a2l;

    a2l = config_section_descriptor_file_line_get(desc, &g_config._bool);
    if(a2l == NULL)
    {
        yatest_err("config_section_descriptor_file_line_get returned NULL");
        return 1;
    }

    yatest_log("_bool: %s:%i", a2l->filename, a2l->line_number);
    if((strcmp(a2l->filename, TEST_CONFIG_FILE) != 0) || (a2l->line_number != 6))
    {
        yatest_err("address_to_location_t expected %s:%i, got %s:%i", TEST_CONFIG_FILE, 6, a2l->filename, a2l->line_number);
        return 1;
    }

    a2l = config_section_descriptor_file_line_get(desc, &g_config._u64);
    if(a2l == NULL)
    {
        yatest_err("config_section_descriptor_file_line_get returned NULL");
        return 1;
    }
    yatest_log("_u64: %s:%i", a2l->filename, a2l->line_number);
    if((strcmp(a2l->filename, "command line") != 0) || (a2l->line_number != 2))
    {
        yatest_err("address_to_location_t expected %s:%i, got %s:%i", "command line", 2, a2l->filename, a2l->line_number);
        return 1;
    }

    a2l = config_section_descriptor_file_line_get(desc, &g_config._u32);
    if(a2l == NULL)
    {
        yatest_err("config_section_descriptor_file_line_get returned NULL");
        return 1;
    }
    yatest_log("_u32: %s:%i", a2l->filename, a2l->line_number);
    if((strcmp(a2l->filename, "local") != 0) || (a2l->line_number != 3))
    {
        yatest_err("address_to_location_t expected %s:%i, got %s:%i", "local", 3, a2l->filename, a2l->line_number);
        return 1;
    }

    a2l = config_section_descriptor_file_line_get(desc, &g_config._u16);
    if(a2l == NULL)
    {
        yatest_err("config_section_descriptor_file_line_get returned NULL");
        return 1;
    }
    yatest_log("_u16: %s:%i", a2l->filename, a2l->line_number);
    if((strcmp(a2l->filename, TEST_CONFIG_FILE) != 0) || (a2l->line_number != 13))
    {
        yatest_err("address_to_location_t expected %s:%i, got %s:%i", TEST_CONFIG_FILE, 13, a2l->filename, a2l->line_number);
        return 1;
    }

    config_section_descriptor_config_error_update(&cerr, desc, &g_config._u16);

    if((strcmp(a2l->filename, cerr.file) != 0) || (a2l->line_number != (int)cerr.line_number))
    {
        yatest_err("config_section_descriptor_config_error_update expected %s:%i, got %s:%i", a2l->filename, a2l->line_number, cerr.file, cerr.line_number);
        return 1;
    }

    a2l = config_section_descriptor_file_line_get(desc, desc);
    if(a2l != NULL)
    {
        yatest_err("config_section_descriptor_file_line_get expected to return NULL");
        return 1;
    }

    config_section_descriptor_config_error_update(&cerr, desc, desc);
    if(cerr.line_number != 0)
    {
        yatest_err("config_section_descriptor_config_error_update expected to return line_number = 0");
        return 1;
    }

    config_section_descriptor_file_line_clear(desc);
    finalise();
    return 0;
}

static int baddefaults_test()
{
    int ret;
    dnscore_init();
    config_init();

    config_error_t cerr;
    config_error_init(&cerr);

    memset(&g_config, 0, sizeof(config_test_t));
    ptr_vector_init_empty(&g_config._string_array);

    ret = config_register_struct("config", config_test_bad_defaultdesc, &g_config, 1);
    if(FAIL(ret))
    {
        yatest_err("config_register_struct failed with %s", error_gettext(ret));
        exit(1);
    }

    config_section_descriptor_t *desc = config_section_get_descriptor("config");

    ret = config_set_section_default(desc, &cerr);
    if(ISOK(ret))
    {
        yatest_err("config_set_section_default should have failed");
        return 1;
    }

    ret = config_value_set_to_default("config", "_u64", &cerr);

    if(ISOK(ret))
    {
        yatest_err("config_value_set_to_default should have failed");
        return 1;
    }

    return 0;
}

static ya_result kv_config_set_field_function(const char *value, kv_t *dest, anytype notused)
{
    (void)notused;
    char key_buffer[64];
    char value_buffer[64];
    while((*value != '(') && (*value != '\0'))
    {
        ++value;
    }
    if(*value == '\0')
    {
        return PARSE_ERROR;
    }
    ++value;
    char *p = key_buffer;
    while((*value != ',') && (*value != '\0'))
    {
        *p++ = *value;
        ++value;
    }
    if(*value == '\0')
    {
        return PARSE_ERROR;
    }
    ++value;
    *p = '\0';
    p = value_buffer;
    while((*value != ')') && (*value != '\0'))
    {
        *p++ = *value;
        ++value;
    }
    if(*value == '\0')
    {
        return PARSE_ERROR;
    }
    *p = '\0';
    free(dest->key);
    dest->key = strdup(key_buffer);
    free(dest->value);
    dest->value = strdup(value_buffer);
    return SUCCESS;
}

static bool kv_config_section_print(output_stream_t *os, const char *name, void *ptr)
{
    kv_t *kv = (kv_t *)ptr;
    if(kv != NULL)
    {
        osformatln(os, "%24s (%s,%s)", name, kv->key, kv->value);
    }

    return true;
}

static int registered_type_handler_test()
{
    int ret;
    init();
    config_error_t cerr;
    config_error_init(&cerr);
    ret = config_read(TEST_CONFIG_FILE, &cerr);
    if(FAIL(ret))
    {
        yatest_err("error: file: %s:%i", cerr.file, cerr.line_number);
        yatest_err("error: variable: %s", config_error_get_variable_name(&cerr));
        yatest_err("error: line: %s", cerr.line);
        yatest_err("config_read failed with %s", error_gettext(ret));
        return 1;
    }

    if(!config_section_struct_register_type_handler((config_set_field_function *)kv_config_set_field_function, kv_config_section_print))
    {
        yatest_err("config_section_struct_register_type_handler failed to register");
        return 1;
    }

    if(config_section_struct_register_type_handler((config_set_field_function *)kv_config_set_field_function, kv_config_section_print))
    {
        yatest_err("config_section_struct_register_type_handler should have failed to register");
        return 1;
    }

    ret = config_value_set_to_default("config", "_kv", &cerr);
    if(FAIL(ret))
    {
        yatest_err("config_value_set_to_default_test failed with %s", error_gettext(ret));
        return 1;
    }

    config_section_descriptor_t *desc = config_section_get_descriptor("config");

    ret = config_value_set(desc, "_kv", "(Hello,World)", &cerr);
    if(FAIL(ret))
    {
        yatest_err("config_value_set failed with %s", error_gettext(ret));
        return 1;
    }

    if((strcmp(g_config._kv.key, "Hello") != 0) || (strcmp(g_config._kv.value, "World") != 0))
    {
        yatest_err("config_value_set failed: expected: (%s,%s), got: (%s,%s)", "Hello", "World", g_config._kv.key, g_config._kv.value);
        return 1;
    }

    config_section_print(desc, termout);

    finalise();
    return 0;
}

static int version_help_test()
{
    int ret;

    dnscore_init();
    config_init();
    tsig_init();

    memset(&g_config, 0, sizeof(config_test_t));
    ptr_vector_init_empty(&g_config._string_array);

    int priority = 0;

    if(FAIL(ret = config_register_cmdline(priority++))) // without this line, the help will not work
    {
        yatest_err("config_register_cmdline failed with %s", error_gettext(ret));
        exit(1);
    }

    ret = config_register_struct("config", config_test_desc, &g_config, priority++);
    if(FAIL(ret))
    {
        yatest_err("config_register_struct failed with %s", error_gettext(ret));
        exit(1);
    }

    filedir_init();

    config_error_t cerr;
    config_error_init(&cerr);

    struct config_source_s sources[3];
    config_source_set_commandline(&sources[0], config_cmdline, config_test_argc, config_test_argv_help);
    config_source_set_buffer(&sources[1], "local", 3, config_test_2_conf, sizeof(config_test_2_conf) - 1);
    config_source_set_file(&sources[2], TEST_CONFIG_FILE, 2);
    ret = config_read_from_sources(sources, 3, &cerr);

    if(FAIL(ret))
    {
        yatest_err("config_read_from_sources failed with %s", error_gettext(ret));
        yatest_err("%s:%i '%s'", cerr.file, cerr.line_number, cerr.line);
        return 1;
    }

    ret = config_postprocess();

    if(FAIL(ret))
    {
        yatest_err("config_postprocess failed with %s", error_gettext(ret));
        return 1;
    }

    if(cmdline_version_get())
    {
        yatest_log("version");
    }

    if(cmdline_help_get())
    {
        yatest_log("help");
    }

    finalise();
    return 0;
}

YATEST_TABLE_BEGIN
YATEST(file_read_test)
YATEST(buffer_read_test)
YATEST(sources_read_test)
YATEST(sources_file_error_test)
YATEST(sources_cmdline_error_test)
YATEST(sources_callback_error_test)
YATEST(parse_error_empty_tag_begin_test)
YATEST(parse_error_empty_tag_end_test)
YATEST(parse_error_tag_notclosed_test)
YATEST(parse_error_tag_nested_test)
YATEST(parse_error_tag_toobig_test)
YATEST(parse_error_tag_toobig_end_test)
YATEST(parse_error_tag_no_open_close_test)
YATEST(parse_error_tag_wrong_close_test)
YATEST(parse_error_path_max_0_test)
YATEST(parse_error_include_nopath_conf_test)
YATEST(parse_error_include_not_found_0_test)
YATEST(parse_error_unknown_keyword_test)
YATEST(default_test)
YATEST(register_const_test)
YATEST(bool_test)
YATEST(u64_test)
YATEST(u32_test)
YATEST(s32_test)
YATEST(u32_range_test)
YATEST(u32_clamp_test)
YATEST(u16_test)
YATEST(u8_test)
YATEST(dnskey_algorithm_test)
YATEST(string_test)
YATEST(string_copy_test)
YATEST(string_array_test)
YATEST(password_test)
YATEST(fqdn_test)
YATEST(path_test)
YATEST(logpath_test)
YATEST(chroot_test)
YATEST(file_test)
YATEST(uid_test)
YATEST(gid_test)
YATEST(dnstype_test)
YATEST(dnsclass_test)
YATEST(enum_test)
YATEST(enum8_test)
YATEST(host_list_test)
YATEST(tsig_test)
YATEST(obsolete_test)
YATEST(register_struct_error_test)
YATEST(config_section_struct_free_test)
YATEST(config_value_get_source_test)
YATEST(config_value_set_to_default_test)
YATEST(section_read_callback_test)
YATEST(file_line_get_test)
YATEST(baddefaults_test)
YATEST(registered_type_handler_test)
YATEST(version_help_test)
YATEST_TABLE_END
