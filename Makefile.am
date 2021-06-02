################################################################################
#
#  Copyright (c) 2011-2021, EURid vzw. All rights reserved.
#  The YADIFA TM software product is provided under the BSD 3-clause license:
#
#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted provided that the following conditions
#  are met:
#
#         * Redistributions of source code must retain the above copyright
#           notice, this list of conditions and the following disclaimer.
#         * Redistributions in binary form must reproduce the above copyright
#           notice, this list of conditions and the following disclaimer in the
#           documentation and/or other materials provided with the distribution.
#         * Neither the name of EURid nor the names of its contributors may be
#           used to endorse or promote products derived from this software
#           without specific prior written permission.
#
#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
#  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
#  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
#  DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
#  FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
#  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
#  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
#  CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
#  OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
#  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
################################################################################        

ACLOCAL_AMFLAGS = -I m4

dist_noinst_DATA = VERSION yadifa.supp autogen.sh m4/contributions/20201002-bug_971605_message_5.mbox

SUBDIRS = lib/dnscore lib/dnsdb

SUBDIRS += etc doc var

SUBDIRS += sbin/yadifad
SUBDIRS += sbin/yakeyrolld
SUBDIRS += lib/dnslg
SUBDIRS += bin/yadifa

if HAS_TESTS
SUBDIRS += test/circular-file-test
SUBDIRS += test/cjf-scan
SUBDIRS += test/cmdline-test
SUBDIRS += test/collection-test
SUBDIRS += test/daemonised-logger-test
SUBDIRS += test/dnskey-test
SUBDIRS += test/dnsname-test
SUBDIRS += test/dnssec-test
SUBDIRS += test/dnsserver-test
SUBDIRS += test/dsfromkey-test
SUBDIRS += test/filepool-test
SUBDIRS += test/file-test
SUBDIRS += test/freebsd12-test
SUBDIRS += test/ipc-test
SUBDIRS += test/journal-fusion
SUBDIRS += test/journal-from-ixfr
#SUBDIRS += test/journal-server
SUBDIRS += test/journal-speed-test
SUBDIRS += test/keygen-test
SUBDIRS += test/limiter-test
SUBDIRS += test/logger-test
SUBDIRS += test/message-test
SUBDIRS += test/mutex-test
SUBDIRS += test/network-interfaces-forall-test
SUBDIRS += test/notify-test
SUBDIRS += test/nsec3-answer
SUBDIRS += test/nsec3-hash
SUBDIRS += test/openssl111a-ecdsa-test
SUBDIRS += test/openssl111a-eddsa-test
SUBDIRS += test/parser-test
SUBDIRS += test/protocol-test
SUBDIRS += test/query-hammer-test
SUBDIRS += test/rrsig-test
SUBDIRS += test/shared-circular-buffer-test
SUBDIRS += test/shared-heap-test
SUBDIRS += test/simple-http-server-test
SUBDIRS += test/skeleton
SUBDIRS += test/stream-test
SUBDIRS += test/threaded-queue
SUBDIRS += test/update-test
SUBDIRS += test/xfr
SUBDIRS += test/zone-save-test
endif

features:
	for m in $(SUBDIRS); do $(MAKE) -C $$m features;done

