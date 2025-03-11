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

add_test(NAME "${NAME}-dnsname_is_charspace_test"  COMMAND ${NAME} dnsname_is_charspace_test)
add_test(NAME "${NAME}-dnslabel_compare_test"  COMMAND ${NAME} dnslabel_compare_test)
add_test(NAME "${NAME}-dnslabel_verify_charspace_test"  COMMAND ${NAME} dnslabel_verify_charspace_test)
add_test(NAME "${NAME}-dnsname_verify_charspace_test"  COMMAND ${NAME} dnsname_verify_charspace_test)
add_test(NAME "${NAME}-dnsname_verify_rname_charspace_test"  COMMAND ${NAME} dnsname_verify_rname_charspace_test)
add_test(NAME "${NAME}-dnsname_is_rname_charspace_test"  COMMAND ${NAME} dnsname_is_rname_charspace_test)
add_test(NAME "${NAME}-dnslabel_locase_verify_charspace_test"  COMMAND ${NAME} dnslabel_locase_verify_charspace_test)
add_test(NAME "${NAME}-dnsname_locase_verify_charspace_test"  COMMAND ${NAME} dnsname_locase_verify_charspace_test)
add_test(NAME "${NAME}-dnsname_init_with_charp_test"  COMMAND ${NAME} dnsname_init_with_charp_test)
add_test(NAME "${NAME}-dnsname_init_with_charp_locase_test"  COMMAND ${NAME} dnsname_init_with_charp_locase_test)
add_test(NAME "${NAME}-dnsname_init_check_with_charp_locase_test"  COMMAND ${NAME} dnsname_init_check_with_charp_locase_test)
add_test(NAME "${NAME}-dnsname_init_check_star_with_charp_test"  COMMAND ${NAME} dnsname_init_check_star_with_charp_test)
add_test(NAME "${NAME}-dnsname_init_with_cstr_locase_test"  COMMAND ${NAME} dnsname_init_with_cstr_locase_test)
add_test(NAME "${NAME}-dnsname_init_check_star_with_cstr_test"  COMMAND ${NAME} dnsname_init_check_star_with_cstr_test)
add_test(NAME "${NAME}-dnsname_init_check_nostar_with_charp_test"  COMMAND ${NAME} dnsname_init_check_nostar_with_charp_test)
add_test(NAME "${NAME}-dnsname_init_check_nostar_with_charp_locase_test"  COMMAND ${NAME} dnsname_init_check_nostar_with_charp_locase_test)
add_test(NAME "${NAME}-dnsname_init_check_star_with_charp_and_origin_test"  COMMAND ${NAME} dnsname_init_check_star_with_charp_and_origin_test)
add_test(NAME "${NAME}-dnsname_init_check_star_with_charp_and_origin_locase_test"  COMMAND ${NAME} dnsname_init_check_star_with_charp_and_origin_locase_test)
add_test(NAME "${NAME}-dnsrname_init_check_with_cstr_test"  COMMAND ${NAME} dnsrname_init_check_with_cstr_test)
add_test(NAME "${NAME}-dnsrname_init_check_with_charp_test"  COMMAND ${NAME} dnsrname_init_check_with_charp_test)
add_test(NAME "${NAME}-cstr_get_dnsname_len_test"  COMMAND ${NAME} cstr_get_dnsname_len_test)
add_test(NAME "${NAME}-cstr_init_with_dnsname_test"  COMMAND ${NAME} cstr_init_with_dnsname_test)
add_test(NAME "${NAME}-dnslabel_equals_test"  COMMAND ${NAME} dnslabel_equals_test)
add_test(NAME "${NAME}-dnslabel_equals_ignorecase_left1_test"  COMMAND ${NAME} dnslabel_equals_ignorecase_left1_test)
add_test(NAME "${NAME}-dnslabel_equals_ignorecase_left4_test"  COMMAND ${NAME} dnslabel_equals_ignorecase_left4_test)
add_test(NAME "${NAME}-dnsname_is_subdomain_test"  COMMAND ${NAME} dnsname_is_subdomain_test)
add_test(NAME "${NAME}-dnsname_equals_ignorecase3_test"  COMMAND ${NAME} dnsname_equals_ignorecase3_test)
add_test(NAME "${NAME}-dnsname_len_with_size_test"  COMMAND ${NAME} dnsname_len_with_size_test)
add_test(NAME "${NAME}-dnsname_len_checked_with_size_test"  COMMAND ${NAME} dnsname_len_checked_with_size_test)
add_test(NAME "${NAME}-dnsname_len_checked_test"  COMMAND ${NAME} dnsname_len_checked_test)
add_test(NAME "${NAME}-dnsname_getdepth_test"  COMMAND ${NAME} dnsname_getdepth_test)
add_test(NAME "${NAME}-dnsname_dup_free_test"  COMMAND ${NAME} dnsname_dup_free_test)
add_test(NAME "${NAME}-dnsname_copy_test"  COMMAND ${NAME} dnsname_copy_test)
add_test(NAME "${NAME}-dnsname_copy_checked_test"  COMMAND ${NAME} dnsname_copy_checked_test)
add_test(NAME "${NAME}-dnslabel_vector_to_dnsname_test"  COMMAND ${NAME} dnslabel_vector_to_dnsname_test)
add_test(NAME "${NAME}-dnslabel_vector_to_cstr_test"  COMMAND ${NAME} dnslabel_vector_to_cstr_test)
add_test(NAME "${NAME}-dnsname_vector_sub_to_dnsname_test"  COMMAND ${NAME} dnsname_vector_sub_to_dnsname_test)
add_test(NAME "${NAME}-dnsname_vector_copy_test"  COMMAND ${NAME} dnsname_vector_copy_test)
add_test(NAME "${NAME}-dnsname_vector_len_test"  COMMAND ${NAME} dnsname_vector_len_test)
add_test(NAME "${NAME}-dnslabel_stack_to_dnsname_test"  COMMAND ${NAME} dnslabel_stack_to_dnsname_test)
add_test(NAME "${NAME}-dnslabel_stack_to_cstr_test"  COMMAND ${NAME} dnslabel_stack_to_cstr_test)
add_test(NAME "${NAME}-dnsname_stack_to_dnsname_test"  COMMAND ${NAME} dnsname_stack_to_dnsname_test)
add_test(NAME "${NAME}-dnsname_stack_len_test"  COMMAND ${NAME} dnsname_stack_len_test)
add_test(NAME "${NAME}-dnsname_stack_to_cstr_test"  COMMAND ${NAME} dnsname_stack_to_cstr_test)
add_test(NAME "${NAME}-dnsname_equals_dnsname_stack_test"  COMMAND ${NAME} dnsname_equals_dnsname_stack_test)
add_test(NAME "${NAME}-dnsname_under_dnsname_stack_test"  COMMAND ${NAME} dnsname_under_dnsname_stack_test)
add_test(NAME "${NAME}-dnsname_stack_push_pop_peek_test"  COMMAND ${NAME} dnsname_stack_push_pop_peek_test)
add_test(NAME "${NAME}-dnsname_zdup_zfree_test"  COMMAND ${NAME} dnsname_zdup_zfree_test)
add_test(NAME "${NAME}-dnslabel_zdup_zfree_test"  COMMAND ${NAME} dnslabel_zdup_zfree_test)
