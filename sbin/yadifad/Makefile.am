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

ACLOCAL_AMFLAGS = -I m4

LOCALFLAGS = -DPREFIX='"$(prefix)"'

dist_noinst_DATA = VERSION

sbin_PROGRAMS = yadifad
yadifad_SOURCES = axfr.c check.c confs.c database.c ixfr.c notify.c parser.c list.c main.c process_command_line.c server.c server-st.c server-mt.c server_context.c log_statistics.c log_query.c poll-util.c signals.c wrappers.c zone.c confs_channels.c confs_control.c confs_main.c confs_zone.c scheduler_xfr.c process_class_ch.c process_class_ctrl.c scheduler_database_load_zone.c

if TCLCOMMANDS
yadifad_SOURCES += tcl_cmd.c
endif

if HAS_ACL_SUPPORT 
yadifad_SOURCES += acl.c confs_acl.c
endif

if HAS_TSIG_SUPPORT
yadifad_SOURCES += confs_key.c
endif

noinst_HEADERS = axfr.h check.h config_error.h config.h confs.h database.h ixfr.h notify.h list.h parser.h server_context.h server_error.h server.h server-st.h server-mt.h log_query.h log_statistics.h poll-util.h signals.h tcl_cmd.h wrappers.h zone_data.h zone.h scheduler_xfr.h process_class_ch.h process_class_ctrl.h scheduler_database_load_zone.h

if HAS_ACL_SUPPORT
noinst_HEADERS += acl.h
endif

include ../../mk/common-settings.mk

include ../../mk/common-labels.mk

