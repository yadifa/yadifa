################################################################################
#
# Copyright (c) 2011-2025, EURid vzw. All rights reserved.
# The YADIFA TM software product is provided under the BSD 3-clause license:
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
#        * Redistributions of source code must retain the above copyright
#          notice, this list of conditions and the following disclaimer.
#        * Redistributions in binary form must reproduce the above copyright
#          notice, this list of conditions and the following disclaimer in the
#          documentation and/or other materials provided with the distribution.
#        * Neither the name of EURid nor the names of its contributors may be
#          used to endorse or promote products derived from this software
#          without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
################################################################################

cmake_minimum_required(VERSION 3.22)

cmake_path(GET CMAKE_CURRENT_SOURCE_DIR FILENAME NAME)
set(SOURCE_FILES main.c)

include_directories(BEFORE
                    "${YATEST_INCLUDE_DIRECTORY}"
                    "${CMAKE_SOURCE_DIR}/lib/dnscore/include"
                    "${CMAKE_BINARY_DIR}/lib/dnscore/include"
                    "${CMAKE_SOURCE_DIR}/lib/dnscore/tests/modules")


add_executable(${NAME} ${SOURCE_FILES})
target_coverage_test(${NAME})
target_link_libraries(${NAME} PUBLIC ${DNSCORELIB_NAME})

add_test(NAME "${NAME}-file_read_test"  COMMAND ${NAME} file_read_test)
add_test(NAME "${NAME}-buffer_read_test"  COMMAND ${NAME} buffer_read_test)
add_test(NAME "${NAME}-sources_read_test"  COMMAND ${NAME} sources_read_test)
add_test(NAME "${NAME}-sources_file_error_test"  COMMAND ${NAME} sources_file_error_test)
add_test(NAME "${NAME}-sources_cmdline_error_test"  COMMAND ${NAME} sources_cmdline_error_test)
add_test(NAME "${NAME}-sources_callback_error_test"  COMMAND ${NAME} sources_callback_error_test)
add_test(NAME "${NAME}-parse_error_empty_tag_begin_test"  COMMAND ${NAME} parse_error_empty_tag_begin_test)
add_test(NAME "${NAME}-parse_errorg-test-u8_test"  COMMAND ${NAME} parse_error_empty_tag_end_test)
add_test(NAME "${NAME}-parse_error_tag_notclosed_test"  COMMAND ${NAME} parse_error_tag_notclosed_test)
add_test(NAME "${NAME}-parse_error_tag_nested_test"  COMMAND ${NAME} parse_error_tag_nested_test)
add_test(NAME "${NAME}-parse_error_tag_toobig_test"  COMMAND ${NAME} parse_error_tag_toobig_test)
add_test(NAME "${NAME}-parse_error_tag_no_open_close_test"  COMMAND ${NAME} parse_error_tag_no_open_close_test)
add_test(NAME "${NAME}-parse_error_tag_wrong_close_test"  COMMAND ${NAME} parse_error_tag_wrong_close_test)
add_test(NAME "${NAME}-parse_error_path_max_0_test"  COMMAND ${NAME} parse_error_path_max_0_test)
add_test(NAME "${NAME}-parse_error_include_nopath_conf_test"  COMMAND ${NAME} parse_error_include_nopath_conf_test)
add_test(NAME "${NAME}-parse_error_include_not_found_0_test"  COMMAND ${NAME} parse_error_include_not_found_0_test)
add_test(NAME "${NAME}-parse_error_unknown_keyword_test"  COMMAND ${NAME} parse_error_unknown_keyword_test)
add_test(NAME "${NAME}-default_test"  COMMAND ${NAME} default_test)
add_test(NAME "${NAME}-register_const_test"  COMMAND ${NAME} register_const_test)
add_test(NAME "${NAME}-bool_test"  COMMAND ${NAME} bool_test)
add_test(NAME "${NAME}-u64_test"  COMMAND ${NAME} u64_test)
add_test(NAME "${NAME}-u32_test"  COMMAND ${NAME} u32_test)
add_test(NAME "${NAME}-s32_test"  COMMAND ${NAME} s32_test)
add_test(NAME "${NAME}-u32_range_test"  COMMAND ${NAME} u32_range_test)
add_test(NAME "${NAME}-u32_clamp_test"  COMMAND ${NAME} u32_clamp_test)
add_test(NAME "${NAME}-u16_test"  COMMAND ${NAME} u16_test)
add_test(NAME "${NAME}-u8_test"  COMMAND ${NAME} u8_test)
add_test(NAME "${NAME}-dnskey_algorithm_test"  COMMAND ${NAME} dnskey_algorithm_test)
add_test(NAME "${NAME}-string_test"  COMMAND ${NAME} string_test)
add_test(NAME "${NAME}-string_copy_test"  COMMAND ${NAME} string_copy_test)
add_test(NAME "${NAME}-string_array_test"  COMMAND ${NAME} string_array_test)
add_test(NAME "${NAME}-password_test"  COMMAND ${NAME} password_test)
add_test(NAME "${NAME}-fqdn_test"  COMMAND ${NAME} fqdn_test)
add_test(NAME "${NAME}-path_test"  COMMAND ${NAME} path_test)
add_test(NAME "${NAME}-logpath_test"  COMMAND ${NAME} logpath_test)
add_test(NAME "${NAME}-chroot_test"  COMMAND ${NAME} chroot_test)
add_test(NAME "${NAME}-file_test"  COMMAND ${NAME} file_test)
add_test(NAME "${NAME}-uid_test"  COMMAND ${NAME} uid_test)
add_test(NAME "${NAME}-gid_test"  COMMAND ${NAME} gid_test)
add_test(NAME "${NAME}-dnstype_test"  COMMAND ${NAME} dnstype_test)
add_test(NAME "${NAME}-dnsclass_test"  COMMAND ${NAME} dnsclass_test)
add_test(NAME "${NAME}-enum_test"  COMMAND ${NAME} enum_test)
add_test(NAME "${NAME}-enum8_test"  COMMAND ${NAME} enum8_test)
add_test(NAME "${NAME}-host_list_test"  COMMAND ${NAME} host_list_test)
add_test(NAME "${NAME}-tsig_test"  COMMAND ${NAME} tsig_test)
add_test(NAME "${NAME}-obsolete_test"  COMMAND ${NAME} obsolete_test)
add_test(NAME "${NAME}-register_struct_error_test"  COMMAND ${NAME} register_struct_error_test)
add_test(NAME "${NAME}-config_section_struct_free_test"  COMMAND ${NAME} config_section_struct_free_test)
add_test(NAME "${NAME}-config_value_get_source_test"  COMMAND ${NAME} config_value_get_source_test)
add_test(NAME "${NAME}-config_value_set_to_default_test"  COMMAND ${NAME} config_value_set_to_default_test)
add_test(NAME "${NAME}-section_read_callback_test"  COMMAND ${NAME} section_read_callback_test)
add_test(NAME "${NAME}-file_line_get_test"  COMMAND ${NAME} file_line_get_test)
add_test(NAME "${NAME}-baddefaults_test"  COMMAND ${NAME} baddefaults_test)
add_test(NAME "${NAME}-registered_type_handler_test"  COMMAND ${NAME} registered_type_handler_test)
add_test(NAME "${NAME}-version_help_test"  COMMAND ${NAME} version_help_test)
