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

add_subdirectory(circular-file-test)
add_subdirectory(cjf-scan)
add_subdirectory(cmdline-test)
add_subdirectory(collection-test)
if(NOT WIN32)
#add_subdirectory(cwisstable-test)
endif()
add_subdirectory(daemonised-logger-test)
add_subdirectory(dns-message-test)
add_subdirectory(dnssec-test)
#add_subdirectory(dnsserver-test)
#add_subdirectory(dns-pcap-analyser)
#add_subdirectory(dns-query-tcp)
add_subdirectory(dsfromkey-test)
add_subdirectory(ethbenchprobe)
#add_subdirectory(filepool-test)
add_subdirectory(file-test)
#add_subdirectory(futex-test)
#add_subdirectory(hash-test)
add_subdirectory(hmac-test)
if(UNIX)
add_subdirectory(ipc-test)
endif()
add_subdirectory(journal-from-ixfr)
add_subdirectory(journal-fusion)
#add_subdirectory(journal-server)
add_subdirectory(journal-speed-test)
#add_subdirectory(json-test)
add_subdirectory(keygen-test)
add_subdirectory(limiter-test)
#add_subdirectory(logger-test)
add_subdirectory(message-test)
#add_subdirectory(mutex-test)
add_subdirectory(network-interfaces-forall-test)
add_subdirectory(notify-test)
add_subdirectory(nsec3-answer)
add_subdirectory(nsec3-hash)
#add_subdirectory(parser-test)
add_subdirectory(pid-file-test)
add_subdirectory(protocol-test)
add_subdirectory(query-hammer-test)
#add_subdirectory(random-test)
add_subdirectory(rndc-test)
add_subdirectory(rrsig-test)
add_subdirectory(shared-circular-buffer-test)
add_subdirectory(shared-heap-test)
add_subdirectory(simple-http-server-test)
#add_subdirectory(skeleton)
#add_subdirectory(ssl3-test)
add_subdirectory(stream-test)
add_subdirectory(tag-gen)
#add_subdirectory(tcp-manager-test)
add_subdirectory(threaded-queue)
#add_subdirectory(tsig-test)
add_subdirectory(udp-echo-test)
add_subdirectory(update-test)
#add_subdirectory(xfr)
#add_subdirectory(zone-rev)
add_subdirectory(zone-save-test)
#add_subdirectory(zone-verify-test)
#add_subdirectory(zoneread-test)
#add_subdirectory(zonediff-test)
if(UNIX AND NOT APPLE)
#add_subdirectory(openssl111a-ecdsa-test)
#add_subdirectory(openssl111a-eddsa-test)
add_subdirectory(freebsd12-test)
#add_subdirectory(axfr-intr-hammer)
endif()
