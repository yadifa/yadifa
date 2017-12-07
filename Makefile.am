################################################################################
#
# Copyright (c) 2011-2017, EURid. All rights reserved.
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
#
#       SVN Program:
#               $URL: https://svn.int.eurid.eu/svn/sysdevel/projects/yadifa/tags/release-2.3.7-public/Makefile.am $
#
#       Last Update:
#               $Date: 2017-09-26 11:33:35 +0200 (Tue, 26 Sep 2017) $
#               $Revision: 7307 $
#
#       Purpose:
#               YADIFA main Makefile.am script
#
################################################################################

srcdir =        @srcdir@
top_srcdir =    @top_srcdir@

VPATH =         @srcdir@

ACLOCAL_AMFLAGS = -I m4

dist_noinst_DATA = VERSION

SUBDIRS = lib/dnscore lib/dnsdb lib/dnszone

if HAS_TOOLS
SUBDIRS += lib/dnslg
endif

SUBDIRS += sbin/yadifad

if HAS_TOOLS
SUBDIRS += bin/yadifa
endif

SUBDIRS += etc doc var

release:
	for m in $(SUBDIRS); do $(MAKE) -C $$m release;done

profile:
	for m in $(SUBDIRS); do $(MAKE) -C $$m profile;done

debug:
	for m in $(SUBDIRS); do $(MAKE) -C $$m debug;done

showsubdirs:
	for m in $(SUBDIRS); do echo $$m; done

features:
	for m in $(SUBDIRS); do $(MAKE) -C $$m features;done


release-install: release install

profile-install: profile install

debug-install: debug install

