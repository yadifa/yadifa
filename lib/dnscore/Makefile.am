################################################################################
#
# Copyright (c) 2011, EURid. All rights reserved.
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

I=include/dnscore

FEATURESFILE=dnscore-config-features.h
FEATURES=$(I)/$(FEATURESFILE)

lib_LTLIBRARIES= libdnscore.la

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
	src/digest_sha0.c \
	src/digest_sha1.c \
	src/digest_sha256.c \
	src/digest_sha384.c \
	src/digest_sha512.c \
	src/dns-udp.c \
	src/dns_resource_record.c \
	src/dnscore.c \
	src/dnsformat.c \
	src/dnskey.c \
	src/dnskey_dsa.c \
	src/dnskey_rsa.c \
	src/dnsname.c \
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
	src/logger.c \
	src/logger_channel_file.c \
	src/logger_channel_stream.c \
	src/logger_channel_syslog.c \
	src/logger_handle.c \
	src/logger-output-stream.c \
	src/message.c \
	src/message_dnsupdate.c \
	src/message_print_format_dig.c \
	src/message_verify_rrsig.c \
	src/mt_output_stream.c \
	src/mutex.c \
	src/network.c \
	src/output_stream.c \
	src/pace.c \
	src/packet_reader.c \
	src/packet_writer.c \
	src/parser.c \
	src/parsing.c \
	src/pid.c \
	src/pipe_stream.c \
	src/pool.c \
	src/ptr_vector.c \
	src/random.c \
	src/rfc.c \
	src/serial.c \
	src/service.c \
	src/server-setup.c \
	src/string_set.c \
	src/sys_error.c \
	src/sys_get_cpu_count.c \
	src/tcp_io_stream.c \
	src/thread_pool.c \
	src/threaded_nb_mm.c \
	src/threaded_nbrb.c \
	src/threaded_ringbuffer.c \
	src/threaded_ringbuffer_cw.c \
	src/threaded_ringlist.c \
	src/threaded_sll_cw.c \
	src/timeformat.c \
	src/timems.c \
	src/treeset.c \
	src/typebitmap.c \
	src/u32_set.c \
	src/u64_set.c \
	src/xfr_copy.c \
	src/xfr_input_stream.c

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
	$(I)/dnskey_dsa.h \
	$(I)/dnskey_rsa.h \
	$(I)/dnsname.h \
	$(I)/dnsname_set.h \
	$(I)/dnssec_errors.h \
	$(I)/fdtools.h \
	$(I)/file_input_stream.h \
	$(I)/file_output_stream.h \
	$(I)/filter_input_stream.h \
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
	$(I)/logger.h \
	$(I)/logger_channel_file.h \
	$(I)/logger_channel_stream.h \
	$(I)/logger_channel_syslog.h \
	$(I)/logger_handle.h \
	$(I)/logger-output-stream.h \
	$(I)/message.h \
	$(I)/message_dnsupdate.h \
	$(I)/message_verify_rrsig.h \
	$(I)/mt_output_stream.h \
	$(I)/mutex.h \
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
	$(I)/ptr_vector.h \
	$(I)/random.h \
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
	$(I)/threaded_nb_mm.h \
	$(I)/threaded_nbrb.h \
	$(I)/threaded_queue.h \
	$(I)/threaded_ringbuffer.h \
	$(I)/threaded_ringbuffer_cw.h \
	$(I)/threaded_ringlist.h \
	$(I)/threaded_sll_cw.h \
	$(I)/timeformat.h \
	$(I)/timems.h \
	$(I)/treeset.h \
	$(I)/typebitmap.h \
	$(I)/u32_set.h \
	$(I)/u64_set.h \
	$(I)/xfr_copy.h \
	$(I)/xfr_input_stream.h \
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

libdnscore_la_LDFLAGS = -version-info 2:0:0

include ../../mk/common-settings.mk

include ../../mk/common-labels.mk

src/alarm.c: $(FEATURES)

$(FEATURES): config.log
	echo "#pragma once" > $(FEATURES)
	echo "#define DNSCORE_HAS_TSIG_SUPPORT 1" >> $(FEATURES)
	echo "#define DNSCORE_HAS_RDTSC 0" >> $(FEATURES)
	echo "#define DNSCORE_HAS_ACL_SUPPORT 1" >> $(FEATURES)
	echo "#define DNSCORE_HAS_NSEC3_SUPPORT 1" >> $(FEATURES)
	echo "#define DNSCORE_HAS_NSEC_SUPPORT 1" >> $(FEATURES)

