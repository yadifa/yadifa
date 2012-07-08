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
#
#       SVN Program:
#               $URL: $
#
#       Last Update:
#               $Date:$
#               $Revision: 1717 $
#
#       Purpose:
#               Settings common to all makefiles
#
################################################################################


AM_CFLAGS = 
AM_LDFLAGS =
DEBUGFLAGS =

#ACLOCAL_AMFLAGS = -I m4


#
# Intel C Compiler
#

if USES_ICC

#ICC
#IPO= -ipo (need to use the intel xiar instead of ar)

if HAS_LTO_SUPPORT
AM_CFLAGS += -ipo
AM_LDFLAGS += -ipo
AM_AR = xiar
endif

AM_CFLAGS += -ansi-alias -std=c99 -U__STRICT_ANSI__ -I$(abs_builddir) -I$(abs_srcdir)/include
AM_LD = ld

DEBUGFLAGS += -O0 -g -DMODE_DEBUG_ICC

endif

#
# LLVM Clang
#

if USES_CLANG

# CLANG

if HAS_LTO_SUPPORT
AM_CFLAGS += -flto
AM_LDFLAGS += -use-gold-plugin
endif

AM_CFLAGS += -mtune=native
AM_CFLAGS += -fcatch-undefined-behavior -I$(abs_builddir) -I$(abs_srcdir)/include

AM_AR = llvm-ar
AM_LD = ld.gold

DEBUGFLAGS += -O0 -g -DMODE_DEBUG_CLANG

endif

#
# Gnu C
#

if USES_GCC

#GCC
if HAS_CPU_NIAGARA
AM_CFLAGS += -mcpu=niagara
endif

if HAS_CPU_AMDINTEL
AM_CFLAGS += -mtune=native
endif

if HAS_LTO_SUPPORT
AM_CFLAGS += -flto
AM_LDFLAGS += -flto
endif

AM_CFLAGS += -fno-ident -ansi -pedantic -std=gnu99 -I$(abs_builddir) -I$(abs_srcdir)/include

AM_AR = ar
AM_LD = ld

DEBUGFLAGS+=-g3 -gdwarf-2 -O0 -DMODE_DEBUG_GCC -rdynamic

endif

if HAS_FADDRESS_SANITIZER
DEBUGFLAGS+=-faddress-sanitizer
endif

if HAS_FNO_OMIT_FRAME_POINTER
DEBUGFLAGS+=-fno-omit-frame-pointer
endif


#
#
#

AM_CFLAGS += $(LOCALFLAGS)

YRCFLAGS = -DNDEBUG $(CCOPTIMISATIONFLAGS) -DCMR
YPCFLAGS = -DNDEBUG $(CCOPTIMISATIONFLAGS) -pg -DCMP
YDCFLAGS = -DDEBUG $(DEBUGFLAGS) -DCMD
YSCFLAGS = $(YRCFLAGS)

YRLDFLAGS =
YPLDFLAGS = -pg
YDLDFLAGS = -g
YSLDFLAGS = $(YRLDFLAGS)

AM_CFLAGS += $(YCFLAGS)
AM_LDFLAGS += $(YLDFLAGS)

AM_MAKEFLAGS=MODE_CFLAGS="$(AM_CFLAGS)" CC=$(CC) AR=$(AM_AR) LD=$(AM_LD)

