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

add_test(NAME "${NAME}-axfr_simple_test"  COMMAND ${NAME} axfr_simple_test)
add_test(NAME "${NAME}-axfr_simple_by2_test"  COMMAND ${NAME} axfr_simple_by2_test)
add_test(NAME "${NAME}-axfr_simple_by3_test"  COMMAND ${NAME} axfr_simple_by3_test)
add_test(NAME "${NAME}-axfr_simple_whole_test"  COMMAND ${NAME} axfr_simple_whole_test)
add_test(NAME "${NAME}-axfr_loose_test"  COMMAND ${NAME} axfr_loose_test)
add_test(NAME "${NAME}-axfr_uptodate_test"  COMMAND ${NAME} axfr_uptodate_test)
add_test(NAME "${NAME}-axfr_noaxfr_test"  COMMAND ${NAME} axfr_noaxfr_test)
add_test(NAME "${NAME}-ixfr_noixfr_test"  COMMAND ${NAME} ixfr_noixfr_test)
add_test(NAME "${NAME}-axfr_tsig_test"  COMMAND ${NAME} axfr_tsig_test)
add_test(NAME "${NAME}-axfr_notsiginreply_test"  COMMAND ${NAME} axfr_notsiginreply_test)
add_test(NAME "${NAME}-axfr_brokentsig_test"  COMMAND ${NAME} axfr_brokentsig_test)
add_test(NAME "${NAME}-axfr_replacedtsig_test"  COMMAND ${NAME} axfr_replacedtsig_test)
add_test(NAME "${NAME}-axfr_delayed0_tcplen0_test"  COMMAND ${NAME} axfr_delayed0_tcplen0_test)
add_test(NAME "${NAME}-axfr_delayed0_tcplen1_test"  COMMAND ${NAME} axfr_delayed0_tcplen1_test)
add_test(NAME "${NAME}-axfr_delayed0_tcplen11_test"  COMMAND ${NAME} axfr_delayed0_tcplen11_test)
add_test(NAME "${NAME}-axfr_delayed0_tcplen12_test"  COMMAND ${NAME} axfr_delayed0_tcplen12_test)
add_test(NAME "${NAME}-axfr_delayed0_tcplen14_test"  COMMAND ${NAME} axfr_delayed0_tcplen14_test)
add_test(NAME "${NAME}-axfr_delayed2_tcplen0_test"  COMMAND ${NAME} axfr_delayed2_tcplen0_test)
add_test(NAME "${NAME}-axfr_delayed2_tcplen1_test"  COMMAND ${NAME} axfr_delayed2_tcplen1_test)
add_test(NAME "${NAME}-axfr_delayed2_tcplen11_test"  COMMAND ${NAME} axfr_delayed2_tcplen11_test)
add_test(NAME "${NAME}-axfr_delayed2_tcplen12_test"  COMMAND ${NAME} axfr_delayed2_tcplen12_test)
add_test(NAME "${NAME}-axfr_delayed2_tcplen14_test"  COMMAND ${NAME} axfr_delayed2_tcplen14_test)
add_test(NAME "${NAME}-axfr_delayed4_tcplen0_test"  COMMAND ${NAME} axfr_delayed4_tcplen0_test)
add_test(NAME "${NAME}-axfr_delayed0_tsig_test"  COMMAND ${NAME} axfr_delayed0_tsig_test)
add_test(NAME "${NAME}-axfr_delayed4_tsig_test"  COMMAND ${NAME} axfr_delayed4_tsig_test)
add_test(NAME "${NAME}-axfr_delayed0_dnserror_test"  COMMAND ${NAME} axfr_delayed0_dnserror_test)
add_test(NAME "${NAME}-axfr_delayed4_dnserror_test"  COMMAND ${NAME} axfr_delayed4_dnserror_test)
add_test(NAME "${NAME}-axfr_delayed0_notauthoritative_test"  COMMAND ${NAME} axfr_delayed0_notauthoritative_test)
add_test(NAME "${NAME}-axfr_delayed4_notauthoritative_test"  COMMAND ${NAME} axfr_delayed4_notauthoritative_test)
add_test(NAME "${NAME}-axfr_read1_test"  COMMAND ${NAME} axfr_read1_test)
add_test(NAME "${NAME}-axfr_skip1_test"  COMMAND ${NAME} axfr_skip1_test)
add_test(NAME "${NAME}-ixfr_simple_test"  COMMAND ${NAME} ixfr_simple_test)
add_test(NAME "${NAME}-ixfr_uptodate_test"  COMMAND ${NAME} ixfr_uptodate_test)
add_test(NAME "${NAME}-ixfr_query_test"  COMMAND ${NAME} ixfr_query_test)
add_test(NAME "${NAME}-ixfr_tsig_test"  COMMAND ${NAME} ixfr_tsig_test)
add_test(NAME "${NAME}-axfr_incomplete_test"  COMMAND ${NAME} axfr_incomplete_test)
add_test(NAME "${NAME}-axfr_notxfr_test"  COMMAND ${NAME} axfr_notxfr_test)
add_test(NAME "${NAME}-axfr_mismatched_origins_test"  COMMAND ${NAME} axfr_mismatched_origins_test)
add_test(NAME "${NAME}-axfr_badsoaformat_test"  COMMAND ${NAME} axfr_badsoaformat_test)
add_test(NAME "${NAME}-axfr_badrecordtype_test"  COMMAND ${NAME} axfr_badrecordtype_test)
add_test(NAME "${NAME}-axfr_unsupportedtype_test"  COMMAND ${NAME} axfr_unsupportedtype_test)
add_test(NAME "${NAME}-axfr_badorigin_test"  COMMAND ${NAME} axfr_badorigin_test)
add_test(NAME "${NAME}-axfr_badqueryorigin_test"  COMMAND ${NAME} axfr_badqueryorigin_test)
add_test(NAME "${NAME}-axfr_brokenqueryorigin_test"  COMMAND ${NAME} axfr_brokenqueryorigin_test)
add_test(NAME "${NAME}-axfr_truncatedsoa_test"  COMMAND ${NAME} axfr_truncatedsoa_test)
add_test(NAME "${NAME}-axfr_badquerytype_test"  COMMAND ${NAME} axfr_badquerytype_test)
add_test(NAME "${NAME}-axfr_badqueryclass_test"  COMMAND ${NAME} axfr_badqueryclass_test)
add_test(NAME "${NAME}-axfr_truncated_at_half_query_type_test"  COMMAND ${NAME} axfr_truncated_at_half_query_type_test)
add_test(NAME "${NAME}-axfr_truncated_at_half_query_class_test"  COMMAND ${NAME} axfr_truncated_at_half_query_class_test)
add_test(NAME "${NAME}-axfr_nosuchdomain_test"  COMMAND ${NAME} axfr_nosuchdomain_test)
add_test(NAME "${NAME}-axfr_noserver_test"  COMMAND ${NAME} axfr_noserver_test)
add_test(NAME "${NAME}-axfr_cantsend_test"  COMMAND ${NAME} axfr_cantsend_test)
