################################################################################
#
# Copyright (c) 2011-2024, EURid vzw. All rights reserved.
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

message("var will be installed in ${CMAKE_INSTALL_FULL_LOCALSTATEDIR}/var")

install(DIRECTORY DESTINATION ${CMAKE_INSTALL_FULL_LOCALSTATEDIR})
install(DIRECTORY DESTINATION ${CMAKE_INSTALL_FULL_LOCALSTATEDIR}/log)
install(DIRECTORY DESTINATION ${CMAKE_INSTALL_FULL_LOCALSTATEDIR}/log/yadifa)
install(DIRECTORY DESTINATION ${CMAKE_INSTALL_FULL_LOCALSTATEDIR}/log/yadifad)
install(DIRECTORY DESTINATION ${CMAKE_INSTALL_FULL_LOCALSTATEDIR}/log/yakeyrolld)
install(DIRECTORY DESTINATION ${CMAKE_INSTALL_FULL_LOCALSTATEDIR}/plans)
install(DIRECTORY DESTINATION ${CMAKE_INSTALL_FULL_LOCALSTATEDIR}/run)
install(DIRECTORY DESTINATION ${CMAKE_INSTALL_FULL_LOCALSTATEDIR}/zones)
install(DIRECTORY DESTINATION ${CMAKE_INSTALL_FULL_LOCALSTATEDIR}/zones/keys)
install(DIRECTORY DESTINATION ${CMAKE_INSTALL_FULL_LOCALSTATEDIR}/zones/primaries)
install(DIRECTORY DESTINATION ${CMAKE_INSTALL_FULL_LOCALSTATEDIR}/zones/secondaries)
install(DIRECTORY DESTINATION ${CMAKE_INSTALL_FULL_LOCALSTATEDIR}/zones/xfr)

install(FILES   zones/primaries/0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa.zone
                zones/primaries/0.0.127.in-addr.arpa.zone
                zones/primaries/localhost6.zone
                zones/primaries/localhost.zone
                zones/primaries/somedomain.eu.zone
        DESTINATION ${CMAKE_INSTALL_FULL_LOCALSTATEDIR}/zones/primaries)
