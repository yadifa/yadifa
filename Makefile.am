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

ACLOCAL_AMFLAGS = -I m4

dist_noinst_DATA = VERSION yadifa.supp autogen.sh m4/contributions/20201002-bug_971605_message_5.mbox

SUBDIRS = lib/dnscore lib/dnsdb

SUBDIRS += etc doc var

SUBDIRS += sbin/yadifad
SUBDIRS += sbin/yakeyrolld
SUBDIRS += lib/dnslg
SUBDIRS += bin/yadifa

if HAS_TESTS
SUBDIRS += tests/circular-file-test
SUBDIRS += tests/cjf-scan
SUBDIRS += tests/cmdline-test
SUBDIRS += tests/collection-test
SUBDIRS += tests/daemonised-logger-test
SUBDIRS += tests/dns-message-test
SUBDIRS += tests/dnssec-test
SUBDIRS += tests/dsfromkey-test
SUBDIRS += tests/ethbenchprobe
SUBDIRS += tests/file-test
SUBDIRS += tests/freebsd12-test
SUBDIRS += tests/hmac-test
SUBDIRS += tests/ipc-test
SUBDIRS += tests/journal-fusion
SUBDIRS += tests/journal-from-ixfr
#SUBDIRS += tests/journal-server
SUBDIRS += tests/journal-speed-test
SUBDIRS += tests/keygen-test
SUBDIRS += tests/limiter-test
SUBDIRS += tests/message-test
SUBDIRS += tests/network-interfaces-forall-test
SUBDIRS += tests/notify-test
SUBDIRS += tests/nsec3-answer
SUBDIRS += tests/nsec3-hash
SUBDIRS += tests/pid-file-test
SUBDIRS += tests/protocol-test
SUBDIRS += tests/query-hammer-test
SUBDIRS += tests/rndc-test
SUBDIRS += tests/rrsig-test
SUBDIRS += tests/shared-circular-buffer-test
SUBDIRS += tests/shared-heap-test
SUBDIRS += tests/simple-http-server-test
SUBDIRS += tests/stream-test
SUBDIRS += tests/threaded-queue
SUBDIRS += tests/udp-echo-test
SUBDIRS += tests/update-test
SUBDIRS += tests/zone-save-test
endif

features:
	for m in $(SUBDIRS); do $(MAKE) -C $$m features;done

