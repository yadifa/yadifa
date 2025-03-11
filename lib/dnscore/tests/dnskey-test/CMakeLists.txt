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
set(SOURCE_FILES main.c keys.c settings.h)

include_directories(BEFORE
                    "${YATEST_INCLUDE_DIRECTORY}"
                    "${CMAKE_SOURCE_DIR}/lib/dnscore/include"
                    "${CMAKE_BINARY_DIR}/lib/dnscore/include"
                    "${CMAKE_SOURCE_DIR}/lib/dnscore/tests/modules")


add_executable(${NAME} ${SOURCE_FILES})
target_coverage_test(${NAME})
target_link_libraries(${NAME} PUBLIC ${DNSCORELIB_NAME})

add_test(NAME "${NAME}-key_algorithms_test"  COMMAND ${NAME} key_algorithms_test)
add_test(NAME "${NAME}-dnskey_sign_rrset_with_maxinterval_test"  COMMAND ${NAME} dnskey_sign_rrset_with_maxinterval_test)
add_test(NAME "${NAME}-public_key_parse_test"  COMMAND ${NAME} public_key_parse_test)
add_test(NAME "${NAME}-private_key_parse_test"  COMMAND ${NAME} private_key_parse_test)
add_test(NAME "${NAME}-dnskey_equals_test"  COMMAND ${NAME} dnskey_equals_test)
add_test(NAME "${NAME}-algorithms_test"  COMMAND ${NAME} algorithms_test)
add_test(NAME "${NAME}-algorithm_by_index_test"  COMMAND ${NAME} algorithm_by_index_test)
add_test(NAME "${NAME}-fields_test"  COMMAND ${NAME} fields_test)
add_test(NAME "${NAME}-dnskey_newinstance_errors_test"  COMMAND ${NAME} dnskey_newinstance_errors_test)
add_test(NAME "${NAME}-dnskey_newemptyinstance_test"  COMMAND ${NAME} dnskey_newemptyinstance_test)
add_test(NAME "${NAME}-dnskey_store_test"  COMMAND ${NAME} dnskey_store_test)
add_test(NAME "${NAME}-dnskey_chain_test"  COMMAND ${NAME} dnskey_chain_test)
add_test(NAME "${NAME}-dnskey_generate_ds_rdata_test"  COMMAND ${NAME} dnskey_generate_ds_rdata_test)
add_test(NAME "${NAME}-dnskey_digest_init_test"  COMMAND ${NAME} dnskey_digest_init_test)
add_test(NAME "${NAME}-dnskey_new_from_rdata_error_test"  COMMAND ${NAME} dnskey_new_from_rdata_error_test)
add_test(NAME "${NAME}-dnskey_matches_rdata_test"  COMMAND ${NAME} dnskey_matches_rdata_test)
add_test(NAME "${NAME}-dnskey_init_dns_resource_record_test"  COMMAND ${NAME} dnskey_init_dns_resource_record_test)
add_test(NAME "${NAME}-dnskey_new_public_key_from_stream_test"  COMMAND ${NAME} dnskey_new_public_key_from_stream_test)
add_test(NAME "${NAME}-dnskey_keyring_test"  COMMAND ${NAME} dnskey_keyring_test)
add_test(NAME "${NAME}-dnskey_keyring_add_from_nameserver_test"  COMMAND ${NAME} dnskey_keyring_add_from_nameserver_test)
add_test(NAME "${NAME}-dnskey_keyring_add_from_nameserver_broken_fqdn_test"  COMMAND ${NAME} dnskey_keyring_add_from_nameserver_broken_fqdn_test)
add_test(NAME "${NAME}-dnskey_keyring_add_from_nameserver_broken_tctr_test"  COMMAND ${NAME} dnskey_keyring_add_from_nameserver_broken_tctr_test)
if(${HAS_OQS_SUPPORT})
add_test(NAME "${NAME}-dnskey_postquantumsafe_experimental_test"  COMMAND ${NAME} dnskey_postquantumsafe_experimental_test)
endif()
