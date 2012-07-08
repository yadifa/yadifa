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
################################################################################

srcdir =        @srcdir@
libdir =	@libdir@
top_srcdir =    @top_srcdir@
VPATH =         @srcdir@

ACLOCAL_AMFLAGS = -I m4

dist_noinst_DATA = VERSION

lib_LTLIBRARIES= libdnszone.la

libdnszone_la_SOURCES = src/output_stream_write_dname.c src/dnszone.c src/output_stream_write_rdata.c src/zone_axfr_reader.c src/zone_file_reader.c src/resourcerecord.c
	
pkginclude_HEADERS = include/dnszone/output_stream_write_rdata.h include/dnszone/dnszone.h include/dnszone/dnszone-config.h include/dnszone/zone_axfr_reader.h include/dnszone/zone_file_reader.h include/dnszone/resourcerecord.h

include ../../mk/common-settings.mk

include ../../mk/common-labels.mk

