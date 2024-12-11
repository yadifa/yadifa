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

include ../../mk/common_settings.mk

AM_CFLAGS += -DDNSCORE_BUILD=1

AM_CFLAGS += -I$(top_srcdir)/lib/dnscore/include -I$(top_builddir)/lib/dnscore/include
#AM_CFLAGS += -I$(top_srcdir)/lib/dnsdb/include -I$(top_builddir)/lib/dnsdb/include
#AM_CFLAGS += -I$(top_srcdir)/lib/dnslg/include -I$(top_builddir)/lib/dnslg/include 
#AM_CFLAGS += -I$(top_srcdir)/lib/dnstcl/include -I$(top_builddir)/lib/dnstcl/include

dist_noinst_DATA = include/dnscore/thirdparty/stdatomic.h

lib_LTLIBRARIES= libdnscore.la
libdnscore_la_LDFLAGS = -version-info 10:0:0
#libdnscore_la_LIBADD=$(top_buildir)/lib/.../libsomething.la

I=include/dnscore

FEATURESFILE=dnscore_config_features.h
FEATURES=$(I)/$(FEATURESFILE)
FEATURESDIR=lib/dnscore/include/dnscore
FEATURESSRC=$(top_builddir)/$(FEATURESDIR)/dnscore_config.h

# libdnscore_ladir=.

# alphabetically please

pkgincludedir = $(includedir)/dnscore
pkginclude_HEADERS = \
	$(I)/acl.h \
	$(I)/acl_config.h \
	$(I)/alarm.h \
	$(I)/async.h \
	$(I)/avl.c.inc \
	$(I)/avl.h.inc \
	$(I)/base16.h \
	$(I)/base32.h \
	$(I)/base32hex.h \
	$(I)/base64.h \
	$(I)/basic_priority_queue.h \
	$(I)/buffer_input_stream.h \
	$(I)/buffer_output_stream.h \
	$(I)/buffered_file.h \
	$(I)/bytearray_input_stream.h \
	$(I)/bytearray_output_stream.h \
	$(I)/bytezarray_output_stream.h \
	$(I)/cache.h \
	$(I)/checked_output_stream.h \
	$(I)/circular_file.h \
	$(I)/clone_input_output_stream.h \
	$(I)/cmdline.h \
	$(I)/concat_input_stream.h \
	$(I)/config_cmdline.h \
	$(I)/config_file_reader.h \
	$(I)/config_settings.h \
	$(I)/counter_output_stream.h \
	$(I)/crc32.h \
	$(I)/crypto.h \
	$(I)/ctrl_rfc.h \
	$(I)/debug.h \
	$(I)/debug_config.h \
	$(I)/digest.h \
	$(I)/dns_udp.h \
	$(I)/dns_message_verify_rrsig.h \
	$(I)/dns_resource_record.h \
	$(I)/dnscore.h \
	$(I)/dnscore_extension.h \
	$(I)/dnscore_release_date.h \
	$(I)/dnsformat.h \
	$(I)/dnskey.h \
	$(I)/dnskey_keyring.h \
	$(I)/dnskey_dsa.h \
	$(I)/dnskey_ecdsa.h \
	$(I)/dnskey_eddsa.h \
	$(I)/dnskey_rsa.h \
	$(I)/dnskey_signature.h \
	$(I)/dns_message.h \
	$(I)/dns_message_writer.h \
	$(I)/dnsname.h \
	$(I)/dnsname_set.h \
	$(I)/dnssec_errors.h \
	$(I)/empty_input_stream.h \
	$(I)/error_state.h \
	$(I)/fdtools.h \
	$(I)/file.h \
	$(I)/file_input_stream.h \
	$(I)/file_mtime_set.h \
	$(I)/file_output_stream.h \
	$(I)/file_pool.h \
	$(I)/filesystem_file.h \
	$(I)/fingerprint.h \
	$(I)/format.h \
	$(I)/hash.h \
	$(I)/hmac.h \
	$(I)/host_address.h \
	$(I)/http_chunk_output_stream.h \
	$(I)/identity.h \
	$(I)/initialise_state.h \
	$(I)/input_stream.h \
	$(I)/io_stream.h \
	$(I)/json.h \
	$(I)/json_type.h \
	$(I)/limited_input_stream.h \
	$(I)/limiter.h \
	$(I)/list_dl.h \
    $(I)/list_dl_nodata.h \
	$(I)/list_sl.h \
	$(I)/list_sl_debug.h \
	$(I)/logger.h \
	$(I)/logger_channel_file.h \
	$(I)/logger_channel_stream.h \
	$(I)/logger_channel_syslog.h \
	$(I)/logger_handle.h \
	$(I)/logger_output_stream.h \
	$(I)/mapped_file.h \
	$(I)/dns_message_update.h \
	$(I)/dns_message_opt.h \
	$(I)/mt_output_stream.h \
	$(I)/mutex.h \
	$(I)/mutex_contention_monitor.h \
	$(I)/mutex_debug.h \
	$(I)/mutex_defines.h \
	$(I)/mutex_futex.h \
	$(I)/mutex_group.h \
	$(I)/mutex_logger.h \
	$(I)/mutex_mutex.h \
	$(I)/mutex_semaphore.h \
	$(I)/mutex_shared_group.h \
	$(I)/mutex_spinlock.h \
	$(I)/network.h \
	$(I)/nsec3_hash.h \
	$(I)/openssl.h \
	$(I)/output_stream.h \
	$(I)/pace.h \
	$(I)/dns_packet_reader.h \
	$(I)/dns_packet_writer.h \
	$(I)/parser.h \
	$(I)/parsing.h \
	$(I)/pcg_basic.h \
	$(I)/permut.h \
	$(I)/pid.h \
	$(I)/pipe_stream.h \
	$(I)/pool.h \
	$(I)/print_stream.h \
	$(I)/process.h \
	$(I)/ptr_set.h \
	$(I)/ptr_set_debug.h \
	$(I)/ptr_treemap.h \
    $(I)/ptr_treemap_debug.h \
    $(I)/ptr_treeset.h \
    $(I)/ptr_treeset_debug.h \
	$(I)/ptr_vector.h \
	$(I)/pushback_input_stream.h \
	$(I)/queue_sl.h \
	$(I)/random.h \
	$(I)/rest_client.h \
	$(I)/rest_server.h \
	$(I)/rewind_input_stream.h \
	$(I)/rfc.h \
	$(I)/rndc.h \
	$(I)/serial.h \
	$(I)/server_setup.h \
	$(I)/service.h \
	$(I)/shared_heap.h \
	$(I)/shared_circular_buffer.h \
	$(I)/shared_heap_bytearray_output_stream.h \
	$(I)/signals.h \
	$(I)/simple_http_server.h \
	$(I)/smp_int.h \
	$(I)/socket_server.h \
	$(I)/ssl_input_output_stream.h \
	$(I)/string_set.h \
	$(I)/sys_error.h \
	$(I)/sys_get_cpu_count.h \
	$(I)/sys_types.h \
	$(I)/tcp_io_stream.h \
    $(I)/tcp_manager2.h \
	$(I)/thread_pool.h \
	$(I)/thread.h \
	$(I)/thread_tag.h \
	$(I)/threaded_qsl_cw.h \
	$(I)/threaded_dll_cw.h \
	$(I)/threaded_nbrb.h \
	$(I)/threaded_queue.h \
	$(I)/threaded_queue_slg.h \
	$(I)/threaded_ringbuffer_cw.h \
	$(I)/timeformat.h \
	$(I)/timems.h \
	$(I)/tools.h \
	$(I)/typebitmap.h \
	$(I)/u32_set.h \
	$(I)/u32_treeset.h \
	$(I)/u64_treeset.h \
	$(I)/u64_set.h \
	$(I)/u64_set_debug.h \
	$(I)/u64_treeset_debug.h \
	$(I)/u32_treemap.h \
	$(I)/u64_treemap.h \
	$(I)/uri.h \
	$(I)/utf8.h \
	$(I)/xfr_input_stream.h \
	$(I)/zalloc.h \
	$(I)/zone_reader.h \
	$(I)/zone_reader_axfr.h \
	$(I)/zone_reader_text.h \
	$(I)/zonefile_reader.h

libdnscore_la_SOURCES = \
	src/acl.c \
	src/acl_config.c \
	src/alarm.c \
	src/async.c \
	src/base16.c \
	src/base32.c \
	src/base32hex.c \
	src/base64.c \
	src/basic_priority_queue.c \
	src/buffer_input_stream.c \
	src/buffer_output_stream.c \
	src/buffered_file.c \
	src/bytearray_input_stream.c \
	src/bytearray_output_stream.c \
	src/bytezarray_output_stream.c \
	src/cache.c \
	src/checked_output_stream.c \
	src/circular_file.c \
	src/clone_input_output_stream.c \
	src/cmdline.c \
	src/concat_input_stream.c \
	src/config_cmdline.c \
	src/config_file_reader.c \
	src/config_key.c \
	src/config_logger.c \
	src/config_settings.c \
	src/config_struct.c \
	src/counter_output_stream.c \
	src/crc32.c \
	src/crypto.c \
	src/debug.c \
	src/debug_bench.c \
	src/debug_bfd.c \
	src/debug_malloc.c \
	src/debug_mmap.c \
	src/debug_stacktrace.c \
    src/digest_md5_internal.c \
	src/digest_rawdata.c \
	src/dns_udp.c \
	src/dns_message_verify_rrsig.c \
	src/dns_message_writer.c \
    src/dns_message_writer_dig.c \
    src/dns_message_writer_json.c \
    src/dns_message_writer_easyparse.c \
	src/dns_resource_record.c \
	src/dnscore.c \
	src/dnscore_extension.c \
	src/dnsformat.c \
	src/dnskey.c \
	src/dnskey_keyring.c \
	src/dnskey_eddsa.c \
	src/dnskey_signature.c \
	src/dns_message.c \
	src/dnsname.c \
	src/empty_input_stream.c \
	src/error_state.c \
	src/fdtools.c \
	src/file_input_stream.c \
	src/file_mtime_set.c \
	src/file_output_stream.c \
	src/file_pool.c \
	src/filesystem_file.c \
	src/format.c \
	src/hash.c \
	src/hash_table_values.c \
	src/host_address.c \
	src/http_chunk_output_stream.c \
	src/identity.c \
	src/initialise_state.c \
	src/input_stream.c \
	src/json.c \
	src/limited_input_stream.c \
	src/limiter.c \
	src/list_dl.c \
    src/list_dl_nodata.c \
	src/list_sl.c \
	src/list_sl_debug.c \
	src/logger_output_stream.c \
	src/logger.c \
	src/logger_channel_file.c \
	src/logger_channel_stream.c \
	src/logger_channel_syslog.c \
	src/logger_handle.c \
	src/mapped_file.c \
	src/dns_message_update.c \
	src/mt_output_stream.c \
	src/mutex.c \
	src/mutex_contention_monitor.c \
	src/mutex_debug.c \
	src/mutex_futex.c \
	src/mutex_group.c \
	src/mutex_mutex.c \
	src/mutex_shared_group.c \
	src/network.c \
	src/nsec3_hash.c \
	src/output_stream.c \
	src/pace.c \
	src/dns_packet_reader.c \
	src/dns_packet_writer.c \
	src/parser.c \
	src/parsing.c \
	src/pcg_basic.c \
	src/permut.c \
	src/process.c \
	src/pid.c \
	src/pipe_stream.c \
	src/pool.c \
	src/ptr_treeset.c \
	src/ptr_treeset_debug.c \
	src/ptr_treemap.c \
    src/ptr_treemap_debug.c \
	src/ptr_vector.c \
	src/pushback_input_stream.c \
	src/queue_sl.c \
	src/random.c \
	src/rest_client.c \
	src/rest_server.c \
	src/rewind_input_stream.c \
	src/rfc.c \
	src/rndc.c \
	src/serial.c \
	src/server_setup.c \
	src/service.c \
	src/shared_heap.c \
	src/shared_circular_buffer.c \
	src/shared_heap_bytearray_output_stream.c \
	src/signals.c \
	src/simple_http_server.c \
	src/socket_server.c \
	src/ssl_input_output_stream.c \
	src/string_set.c \
	src/sys_error.c \
	src/sys_get_cpu_count.c \
	src/tcp_io_stream.c \
	src/tcp_manager2.c \
	src/thread_pool.c \
	src/thread.c \
	src/thread_tag.c \
	src/threaded_qsl_cw.c \
	src/threaded_dll_cw.c \
	src/threaded_nbrb.c \
	src/threaded_queue_slg.c \
	src/threaded_ringbuffer_cw.c \
	src/timeformat.c \
	src/timems.c \
	src/tools.c \
	src/typebitmap.c \
	src/u32_treeset.c \
	src/u64_treeset.c \
	src/u64_treeset_debug.c \
	src/u32_treemap.c \
	src/u64_treemap.c \
	src/uri.c \
	src/utf8.c \
	src/xfr_input_stream.c \
	src/zalloc.c \
	src/zone_reader_axfr.c \
	src/zone_reader_text.c

if OPENSSL_VERSION_MAJOR_3
libdnscore_la_SOURCES += \
	src/dnskey_evp.c \
	src/dnskey_evp_ecdsa.c \
	src/dnskey_evp_rsa.c \
	src/digest_evp.c \
	src/hmac_evp.c
else
libdnscore_la_SOURCES += \
	src/dnskey_ecdsa.c \
	src/dnskey_eddsa.c \
	src/dnskey_rsa.c \
	src/dnskey_signature.c \
	src/digest_rawdata.c \
	src/digest_sha1.c \
	src/digest_sha256.c \
	src/digest_sha384.c \
	src/digest_sha512.c \
	src/hmac_openssl.c
endif

pkginclude_HEADERS += \
	$(I)/chroot.h \
	$(I)/logger_channel_pipe.h \
	$(I)/popen_output_stream.h

libdnscore_la_SOURCES += \
	src/chroot.c \
	src/logger_channel_pipe.c \
	src/popen_output_stream.c

BUILT_SOURCES = $(FEATURES)
#nodist_include_HEADERS = $(FEATURES)

if IS_DARWIN_OS
pkginclude_HEADERS += $(I)/osx_clock_gettime.h
libdnscore_la_SOURCES += src/osx_clock_gettime.c
endif

pkginclude_HEADERS += $(I)/tsig.h
libdnscore_la_SOURCES += src/tsig.c src/tsig_algorithms.c

if HAS_NSID_SUPPORT
pkginclude_HEADERS += $(I)/nsid.h
libdnscore_la_SOURCES += src/nsid.c
endif

include ../../mk/common_labels.mk

all: $(FEATURESSRC)

$(srcdir)/src/alarm.c: $(FEATURES) $(FEATURESSRC)

$(FEATURESSRC): ../../config.h
	mkdir -p $(top_builddir)/$(FEATURESDIR)
	cp ../../config.h $(FEATURESSRC)
	
CLEANFILES += $(FEATURESSRC)

features: $(FEATURES)

$(FEATURES): ../../config.log ../../VERSION $(FEATURESSRC)
VP=DNSCORE
	mkdir -p $(I)
	echo "#pragma once" > $(FEATURES)
	grep "^#define" $(FEATURESSRC) | sed -e 's/^#define /#define $(VP)_/' >> $(FEATURES)
	echo '#undef $(VP)_VERSION' >> $(FEATURES)

	echo "// $(FEATURES)" >> $(FEATURES)
	echo >> $(FEATURES)

install-data-local: $(FEATURES)
	mkdir -p $(DESTDIR)$(prefix)/include/dnscore
	/usr/bin/install -c -m 644 $(FEATURES) $(DESTDIR)$(prefix)/$(FEATURES)
