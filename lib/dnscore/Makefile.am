################################################################################
#
# Copyright (c) 2011, EURid. All rights reserved.
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

srcdir =        @srcdir@
libdir =	@libdir@
top_srcdir =    @top_srcdir@
VPATH =         @srcdir@

ACLOCAL_AMFLAGS = -I m4

dist_noinst_DATA = VERSION

lib_LTLIBRARIES= libdnscore.la

libdnscore_la_SOURCES = src/sys_error.c src/sys_get_cpu_count.c src/timems.c \
			\
			src/input_stream.c src/file_input_stream.c src/buffer_input_stream.c \
			src/output_stream.c src/file_output_stream.c src/buffer_output_stream.c src/mt_output_stream.c src/clone_input_output_stream.c\
			src/bytearray_output_stream.c src/counter_output_stream.c \
			src/fdtools.c \
			src/tcp_io_stream.c \
			src/host_address.c src/network.c \
			src/packet_reader.c src/packet_writer.c src/message.c \
			src/logger_channel_syslog.c src/logger_channel_stream.c src/logger_channel_file.c \
			src/logger_channel.c \
			src/logger_handle.c  \
			src/logger.c \
			src/dnsname.c \
			src/typebitmap.c \
			src/base64.c src/base32hex.c src/base32.c src/base16.c src/parsing.c \
			src/ptr_vector.c \
			src/string_set.c \
            src/u32_set.c \
			src/threaded_ringlist.c src/threaded_ringbuffer.c src/threaded_ringbuffer_cw.c \
			src/threaded_nbrb.c src/threaded_nb_mm.c \
			src/thread_pool.c \
			src/scheduler.c \
			src/random.c \
			src/format.c src/dnsformat.c \
			src/debug.c src/rdtsc.c \
			src/dnscore.c src/rfc.c src/serial.c \
			src/xfr_copy.c \
			src/alarm.c src/treeset.c
if HAS_TSIG_SUPPORT
libdnscore_la_SOURCES+= src/tsig.c src/tsig_algorithms.c
endif		

pkginclude_HEADERS =include/dnscore/base16.h include/dnscore/base32.h include/dnscore/base32hex.h include/dnscore/base64.h \
					include/dnscore/dnscore-config.h \
					include/dnscore/buffer_input_stream.h include/dnscore/buffer_output_stream.h include/dnscore/bytearray_output_stream.h include/dnscore/mt_output_stream.h include/dnscore/clone_input_output_stream.h \
					include/dnscore/host_address.h include/dnscore/network.h \
					include/dnscore/counter_output_stream.h \
					include/dnscore/debug_config.h include/dnscore/debug.h include/dnscore/dnscore.h include/dnscore/dnsformat.h include/dnscore/dnsname.h include/dnscore/dnsname_set.h include/dnscore/u32_set.h include/dnscore/treeset.h \
					include/dnscore/file_input_stream.h include/dnscore/file_output_stream.h include/dnscore/filter_input_stream.h include/dnscore/fingerprint.h include/dnscore/format.h \
					include/dnscore/input_stream.h include/dnscore/logger_channel.h include/dnscore/logger_channel_stream.h \
					include/dnscore/logger_channel_syslog.h include/dnscore/logger.h include/dnscore/logger_handle.h include/dnscore/logger_channel_file.h \
					include/dnscore/message.h include/dnscore/mutex.h include/dnscore/output_stream.h \
					include/dnscore/packet_reader.h include/dnscore/packet_writer.h include/dnscore/parsing.h include/dnscore/print_stream.h include/dnscore/ptr_vector.h \
					include/dnscore/random.h include/dnscore/rdtsc.h include/dnscore/rfc.h include/dnscore/scheduler.h include/dnscore/serial.h include/dnscore/string_set.h include/dnscore/sys_error.h include/dnscore/sys_get_cpu_count.h \
					include/dnscore/sys_types.h include/dnscore/threaded_queue.h include/dnscore/threaded_ringbuffer.h include/dnscore/threaded_ringbuffer_cw.h include/dnscore/threaded_ringlist.h include/dnscore/threaded_nbrb.h include/dnscore/thread_pool.h include/dnscore/threaded_nb_mm.h \
					include/dnscore/timems.h include/dnscore/typebitmap.h include/dnscore/zonefile_reader.h include/dnscore/avl.h.inc include/dnscore/avl.c.inc include/dnscore/fdtools.h include/dnscore/tcp_io_stream.h include/dnscore/io_stream.h include/dnscore/xfr_copy.h include/dnscore/alarm.h \
					include/dnscore/ctrl-rfc.h

if HAS_TSIG_SUPPORT
pkginclude_HEADERS+=include/dnscore/tsig.h
endif

include ../../mk/common-settings.mk

include ../../mk/common-labels.mk

