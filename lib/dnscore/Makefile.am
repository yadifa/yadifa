################################################################################
#
# Copyright (c) 2011-2016, EURid. All rights reserved.
# The YADIFA TM software product is provided under the BSD 3-clause license:
#
# Redistribution and use in source and binary forms, with or without 
# modification, are permitted provided that the following conditions
# are met:
#
#		* Redistributions of source code must retain the above copyright 
#		  notice, this list of conditions and the following disclaimer.
#		* Redistributions in binary form must reproduce the above copyright 
#		  notice, this list of conditions and the following disclaimer in the 
#		  documentation and/or other materials provided with the distribution.
#		* Neither the name of EURid nor the names of its contributors may be 
#		  used to endorse or promote products derived from this software 
#		  without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE 
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL 
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR 
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
##############################################################################

srcdir =	@srcdir@
libdir =	@libdir@
top_srcdir =	@top_srcdir@
VPATH =	 	@srcdir@

ACLOCAL_AMFLAGS = -I m4

dist_noinst_DATA = VERSION

lib_LTLIBRARIES= libdnscore.la

I=include/dnscore

FEATURESFILE=dnscore-config-features.h
FEATURES=$(I)/$(FEATURESFILE)

# alphabetically please

libdnscore_la_SOURCES = \
	src/alarm.c \
	src/allocator.c \
	src/async.c \
	src/base16.c \
	src/base32.c \
	src/base32hex.c \
	src/base64.c \
	src/basic-priority-queue.c \
	src/buffer_input_stream.c \
	src/buffer_output_stream.c \
	src/bytearray_input_stream.c \
	src/bytearray_output_stream.c \
	src/bytezarray_output_stream.c \
	src/chroot.c \
	src/clone_input_output_stream.c \
	src/cmdline.c \
	src/concat_input_stream.c \
	src/config-cmdline.c \
	src/config_file_reader.c \
	src/config_key.c \
	src/config_logger.c \
	src/config_settings.c \
	src/config_struct.c \
	src/counter_output_stream.c \
	src/debug.c \
	src/digest_sha1.c \
	src/digest_sha256.c \
	src/digest_sha384.c \
	src/digest_sha512.c \
	src/dns-udp.c \
	src/dns_resource_record.c \
	src/dnscore.c \
	src/dnsformat.c \
	src/dnskey.c \
	src/dnskey-keyring.c \
	src/dnskey_dsa.c \
    src/dnskey_ecdsa.c \
	src/dnskey_rsa.c \
	src/dnsname.c \
	src/empty-input-stream.c \
	src/fdtools.c \
	src/file_input_stream.c \
	src/file_output_stream.c \
	src/format.c \
	src/host_address.c \
	src/hsdllist.c \
	src/identity.c \
	src/input_stream.c \
	src/limited_input_stream.c \
	src/list-dl.c \
	src/list-sl.c \
	src/list-sl-debug.c \
	src/logger-output-stream.c \
	src/logger.c \
	src/logger_channel_file.c \
	src/logger_channel_stream.c \
	src/logger_channel_syslog.c \
	src/logger_handle.c \
	src/message-buffer.c \
	src/message-viewer.c \
	src/message.c \
	src/message_verify_rrsig.c \
    src/message_dnsupdate.c \
	src/mt_output_stream.c \
	src/mutex.c \
	src/name.c \
	src/output_stream.c \
	src/pace.c \
	src/packet_reader.c \
	src/packet_writer.c \
	src/parser.c \
	src/parsing.c \
	src/pid.c \
	src/pipe_stream.c \
	src/pool.c \
	src/ptr_set.c \
	src/ptr_set_debug.c \
	src/ptr_vector.c \
	src/queue-sl.c \
	src/random.c \
	src/rc.c \
	src/rewind-input-stream.c \
	src/rfc.c \
	src/serial.c \
	src/server-setup.c \
	src/service.c \
	src/string_set.c \
	src/sys_error.c \
	src/sys_get_cpu_count.c \
	src/tcp_io_stream.c \
	src/thread_pool.c \
	src/threaded-qsl-cw.c \
	src/threaded_dll_cw.c \
	src/threaded_nb_mm.c \
	src/threaded_nbrb.c \
	src/threaded_ringbuffer.c \
	src/threaded_ringbuffer_cw.c \
	src/threaded_ringlist.c \
	src/timeformat.c \
	src/timems.c \
	src/typebitmap.c \
	src/u32_set.c \
	src/u64_set.c \
	src/u64_set_debug.c \
	src/xfr_input_stream.c \
	src/zalloc.c

pkginclude_HEADERS = \
	$(FEATURES) \
	$(I)/alarm.h \
	$(I)/allocator.h \
	$(I)/async.h \
	$(I)/avl.c.inc \
	$(I)/avl.h.inc \
	$(I)/base16.h \
	$(I)/base32.h \
	$(I)/base32hex.h \
	$(I)/base64.h \
	$(I)/basic-priority-queue.h \
	$(I)/buffer_input_stream.h \
	$(I)/buffer_output_stream.h \
	$(I)/bytearray_input_stream.h \
	$(I)/bytearray_output_stream.h \
	$(I)/bytezarray_output_stream.h \
	$(I)/chroot.h \
	$(I)/clone_input_output_stream.h \
	$(I)/cmdline.h \
	$(I)/concat_input_stream.h \
	$(I)/config-cmdline.h \
	$(I)/config_file_reader.h \
	$(I)/config_settings.h \
	$(I)/counter_output_stream.h \
	$(I)/ctrl-rfc.h \
	$(I)/debug.h \
	$(I)/debug_config.h \
	$(I)/digest.h \
	$(I)/dns-udp.h \
	$(I)/dns_resource_record.h \
	$(I)/dnscore-config.h \
	$(I)/dnscore.h \
	$(I)/dnsformat.h \
	$(I)/dnskey.h \
	$(I)/dnskey-keyring.h \
	$(I)/dnskey_dsa.h \
    $(I)/dnskey_ecdsa.h \
	$(I)/dnskey_rsa.h \
	$(I)/dnsname.h \
	$(I)/dnsname_set.h \
	$(I)/dnssec_errors.h \
	$(I)/empty-input-stream.h \
	$(I)/fdtools.h \
	$(I)/file_input_stream.h \
	$(I)/file_output_stream.h \
	$(I)/fingerprint.h \
	$(I)/format.h \
	$(I)/host_address.h \
	$(I)/hsdllist.h \
	$(I)/identity.h \
	$(I)/input_stream.h \
	$(I)/io_stream.h \
	$(I)/limited_input_stream.h \
	$(I)/list-dl.h \
	$(I)/list-sl.h \
	$(I)/list-sl-debug.h \
	$(I)/logger.h \
	$(I)/logger_channel_file.h \
	$(I)/logger_channel_stream.h \
	$(I)/logger_channel_syslog.h \
	$(I)/logger_handle.h \
	$(I)/logger-output-stream.h \
	$(I)/message-buffer.h \
	$(I)/message-viewer.h \
	$(I)/message.h \
	$(I)/message_verify_rrsig.h \
    $(I)/message_dnsupdate.h \
	$(I)/mt_output_stream.h \
	$(I)/mutex.h \
	$(I)/name.h \
	$(I)/network.h \
	$(I)/output_stream.h \
	$(I)/pace.h \
	$(I)/packet_reader.h \
	$(I)/packet_writer.h \
	$(I)/parser.h \
	$(I)/parsing.h \
	$(I)/pid.h \
	$(I)/pipe_stream.h \
	$(I)/pool.h \
	$(I)/print_stream.h \
	$(I)/ptr_set.h \
	$(I)/ptr_set_debug.h \
	$(I)/ptr_vector.h \
	$(I)/queue-sl.h \
	$(I)/random.h \
	$(I)/rc.h \
	$(I)/rewind-input-stream.h \
	$(I)/rfc.h \
	$(I)/serial.h \
	$(I)/server-setup.h \
	$(I)/service.h \
	$(I)/string_set.h \
	$(I)/sys_error.h \
	$(I)/sys_get_cpu_count.h \
	$(I)/sys_types.h \
	$(I)/tcp_io_stream.h \
	$(I)/thread_pool.h \
	$(I)/threaded-qsl-cw.h \
	$(I)/threaded_dll_cw.h \
	$(I)/threaded_nb_mm.h \
	$(I)/threaded_nbrb.h \
	$(I)/threaded_queue.h \
	$(I)/threaded_ringbuffer.h \
	$(I)/threaded_ringbuffer_cw.h \
	$(I)/threaded_ringlist.h \
	$(I)/timeformat.h \
	$(I)/timems.h \
	$(I)/typebitmap.h \
	$(I)/u32_set.h \
	$(I)/u64_set.h \
	$(I)/u64_set_debug.h \
	$(I)/xfr_input_stream.h \
	$(I)/zalloc.h \
	$(I)/zonefile_reader.h

if IS_DARWIN_OS
pkginclude_HEADERS += $(I)/osx_clock_gettime.h
libdnscore_la_SOURCES += src/osx_clock_gettime.c
endif

if HAS_TSIG_SUPPORT
pkginclude_HEADERS += $(I)/tsig.h
libdnscore_la_SOURCES += src/tsig.c src/tsig_algorithms.c
endif

if HAS_NSID_SUPPORT
pkginclude_HEADERS += $(I)/nsid.h
libdnscore_la_SOURCES += src/nsid.c
endif

libdnscore_la_LDFLAGS = -version-info 3:0:0

include ../../mk/common-settings.mk

include ../../mk/common-labels.mk

all: REVISION

REVISION:
	(svn info 2>/dev/null;if [ $$? -ne 0 ];then echo "Revision: 0";fi)|grep Revision:|sed 's/^Revision: *//' > REVISION

src/alarm.c: features

features: $(FEATURES)

$(FEATURES): config.log REVISION VERSION
	echo "#pragma once" > $(FEATURES)
if HAS_TSIG_SUPPORT
	echo "#define DNSCORE_HAS_TSIG_SUPPORT 1" >> $(FEATURES)
else
	echo "#define DNSCORE_HAS_TSIG_SUPPORT 0" >> $(FEATURES)
endif
if HAS_RDTSC
	echo "#define DNSCORE_HAS_RDTSC 1" >> $(FEATURES)
else
	echo "#define DNSCORE_HAS_RDTSC 0" >> $(FEATURES)
endif
if HAS_ACL_SUPPORT
	echo "#define DNSCORE_HAS_ACL_SUPPORT 1" >> $(FEATURES)
else
	echo "#define DNSCORE_HAS_ACL_SUPPORT 0" >> $(FEATURES)
endif
if HAS_NSEC3_SUPPORT
	echo "#define DNSCORE_HAS_NSEC3_SUPPORT 1" >> $(FEATURES)
else
	echo "#define DNSCORE_HAS_NSEC3_SUPPORT 0" >> $(FEATURES)
endif
if HAS_NSEC_SUPPORT
	echo "#define DNSCORE_HAS_NSEC_SUPPORT 1" >> $(FEATURES)
else
	echo "#define DNSCORE_HAS_NSEC_SUPPORT 0" >> $(FEATURES)
endif
if HAS_ZALLOC_SUPPORT
	echo "#define DNSCORE_HAS_ZALLOC_SUPPORT 1" >> $(FEATURES)
else
	echo "#define DNSCORE_HAS_ZALLOC_SUPPORT 0" >> $(FEATURES)
endif
if HAS_ZALLOC_DEBUG_SUPPORT
	echo "#define DNSCORE_HAS_ZALLOC_DEBUG_SUPPORT 1" >> $(FEATURES)
else
	echo "#define DNSCORE_HAS_ZALLOC_DEBUG_SUPPORT 0" >> $(FEATURES)
endif
if HAS_NSID_SUPPORT
	echo "#define DNSCORE_HAS_NSID_SUPPORT 1" >> $(FEATURES)
else
	echo "#define DNSCORE_HAS_NSID_SUPPORT 0" >> $(FEATURES)
endif
if HAS_ZALLOC_STATISTICS_SUPPORT
	echo "#define DNSCORE_HAS_ZALLOC_STATISTICS_SUPPORT 1" >> $(FEATURES)
else
	echo "#define DNSCORE_HAS_ZALLOC_STATISTICS_SUPPORT 0" >> $(FEATURES)
endif
if HAS_MALLOC_DEBUG_SUPPORT
	echo "#define DNSCORE_HAS_MALLOC_DEBUG_SUPPORT 1" >> $(FEATURES)
else
	echo "#define DNSCORE_HAS_MALLOC_DEBUG_SUPPORT 0" >> $(FEATURES)
endif
if HAS_MUTEX_DEBUG_SUPPORT
	echo "#define DNSCORE_HAS_MUTEX_DEBUG_SUPPORT 1" >> $(FEATURES)
else
	echo "#define DNSCORE_HAS_MUTEX_DEBUG_SUPPORT 0" >> $(FEATURES)
endif
if HAS_MEMALIGN_ISSUES
	echo "#define DNSCORE_HAS_MEMALIGN_ISSUES 1" >> $(FEATURES)
else
	echo "#define DNSCORE_HAS_MEMALIGN_ISSUES 0" >> $(FEATURES)
endif
VP=DNSCORE
	which printf > /dev/null 2>&1
	if [ $$? -eq 0 ];then \
		printf '// version %i.%i.%i.%i-%i\n' $$(cat VERSION|sed 's/.*\([0-9][0-9]*\)\.\([0-9][0-9]*\)\.\([0-9][0-9]*\).*/\1 \2 \3/') 0 $$(cat REVISION) >> $(FEATURES) ; \
		printf '#define $(VP)_VERSION 0x%02x%02x%02x%02x%04xLL' $$(cat VERSION|sed 's/.*\([0-9][0-9]*\)\.\([0-9][0-9]*\)\.\([0-9][0-9]*\).*/\1 \2 \3/') 0 $$(cat REVISION) >> $(FEATURES) ; \
	else \
		echo "#define $(VP)_VERSION_(vmain_,vsub_,vminor_,vpatch_,vrevision_) ((vmain_)<<40)|((vsub_)<<32)|((vminor_)<<24)|((vpatch_)<<16)|(vrevision_)" >> $(FEATURES) ; \
		echo "#define $(VP)_VERSION_VMAIN_ $$(cat VERSION|sed 's/.*\([0-9][0-9]*\)\.\([0-9][0-9]*\)\.\([0-9][0-9]*\).*/\1')" >> $(FEATURES) ; \
		echo "#define $(VP)_VERSION_VSUB_ $$(cat VERSION|sed 's/.*\([0-9][0-9]*\)\.\([0-9][0-9]*\)\.\([0-9][0-9]*\).*/\2')" >> $(FEATURES) ; \
		echo "#define $(VP)_VERSION_VMINOR_ $$(cat VERSION|sed 's/.*\([0-9][0-9]*\)\.\([0-9][0-9]*\)\.\([0-9][0-9]*\).*/\3')" >> $(FEATURES) ; \
		echo "#define $(VP)_VERSION_VPATCH_ 0 >> $(FEATURES)" ; \
		echo "#define $(VP)_VERSION_VREVISION_ $$(cat REVISION)" >> $(FEATURES) ; \
		echo '#define $(VP)_VERSION $(VP)_VERSION_($(VP)_VERSION_VMAIN_,$(VP)_VERSION_VSUB_,$(VP)_VERSION_VMINOR_,$(VP)_VERSION_VPATCH_,$(VP)_VERSION_VREVISION_)' >> $(FEATURES) ; \
	fi
	echo "// $(FEATURES)" >> $(FEATURES)
	echo >> $(FEATURES)


