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

#
# ALL
#

AM_CFLAGS  = -D_THREAD_SAFE -D_REENTRANT -D_FILE_OFFSET_BITS=64 -I$(abs_builddir) -I$(abs_builddir)/include -I$(abs_srcdir)/include

AM_LDFLAGS =
DEBUGFLAGS =
LOCALFLAGS = -DPREFIX='"$(prefix)"' -DSYSCONFDIR='"$(sysconfdir)"' -DLOCALSTATEDIR='"$(localstatedir)"' -DDATAROOTDIR='"$(datarootdir)"' -DDATADIR='"$(datadir)"' -DLOCALEDIR='"$(localedir)"' -DLOGDIR='"$(logdir)"' -DTCLDIR='"$(tcldir)"'

if USES_SUNC
DEBUGFLAGS +=
else
DEBUGFLAGS += -O0
endif

if IS_DARWIN_OS
AM_CFLAGS += -Wno-deprecated
endif

if HAS_CC_NO_IDENT
AM_CFLAGS += -fno-ident
endif

if HAS_CC_ANSI
AM_CFLAGS += -ansi
endif

if HAS_CC_PEDANTIC
AM_CFLAGS += -pedantic
endif

if HAS_CC_WALL
AM_CFLAGS += -Wall -Wno-unknown-pragmas
endif

if HAS_CC_MISSING_FIELD_INITIALIZERS
AM_CFLAGS += -Werror=missing-field-initializers
endif

if HAS_CC_STD_GNU11
AM_CFLAGS += -std=gnu11
else
if HAS_CC_STD_C11
AM_CFLAGS += -std=c11 -D_GNU_SOURCE
else
if HAS_CC_STD_GNU99
AM_CFLAGS += -std=gnu99
else
if HAS_CC_STD_C99
AM_CFLAGS += -std=c99
else
if HAS_CC_XC99
AM_CFLAGS += -xc99
endif # XC99
endif # C99
endif # GNU99
endif # C11
endif # GNU11

if HAS_CC_TUNE_NATIVE
AM_CFLAGS += -mtune=native
endif

if FORCE64BITS
if HAS_CC_M64
AM_CFLAGS += -m64
AM_LDFLAGS += -m64
endif

else

if FORCE32BITS
if HAS_CC_M32
AM_CFLAGS += -m32
AM_LDFLAGS += -m32
endif
endif

endif

#
# DEBUG
#

if HAS_CC_G3
DEBUGFLAGS += -g3
else
if HAS_CC_G
DEBUGFLAGS += -g
endif
endif

if HAS_CC_DWARF4
DEBUGFLAGS += -gdwarf-4
else
if HAS_CC_DWARF3
DEBUGFLAGS += -gdwarf-3
endif
endif

#
# Intel C Compiler
#
###############################################################################

if USES_ICC

#ICC
#IPO= -ipo (need to use the intel xiar instead of ar)

if HAS_LTO_SUPPORT
AM_CFLAGS += -DLTO -ipo
AM_LDFLAGS += -ipo
AM_AR = xiar
endif

AM_LD = ld

AM_CFLAGS += -DUSES_ICC 

if HAS_CC_ANSI_ALIAS
AM_CFLAGS += -ansi-alias -U__STRICT_ANSI__ 
endif

DEBUGFLAGS += -DMODE_DEBUG_ICC

endif

#
# LLVM Clang
#
###############################################################################

if USES_CLANG

# CLANG

if HAS_LTO_SUPPORT
AM_CFLAGS += -DLTO -flto
AM_LDFLAGS += -flto
AM_AR = llvm-ar
AM_LD = ld.gold
else
AM_AR = ar
AM_LD = ld
endif

AM_CFLAGS += -DUSES_LLVM -Wno-gnu
#-Wno-extended-offsetof

DEBUGFLAGS += -DMODE_DEBUG_CLANG -fsanitize=address -fsanitize=bounds

if IS_LINUX_FAMILY
AM_LDFLAGS += -Wl,-z,stack-size=8388608
endif

# Note: add a _d suffix for debug builds ?

endif # CLANG

#
# Gnu C
#
###############################################################################

if USES_GCC

#GCC
if HAS_CPU_NIAGARA
AM_CFLAGS += -mcpu=niagara
endif


if HAS_LTO_SUPPORT
AM_CFLAGS += -DLTO -flto -fwhole-program -fno-fat-lto-objects -fuse-linker-plugin
AM_LDFLAGS += -flto -fwhole-program -fno-fat-lto-objects -fuse-linker-plugin
AM_LDFLAGS += -Wl,-Map=module.map -Wl,--cref
AM_AR = gcc-ar
AM_RANLIB = gcc-ranlib
else
AM_AR = ar
AM_LD = ld
endif

AM_CFLAGS += -DUSES_GCC
DEBUGFLAGS += -DMODE_DEBUG_GCC -fstack-check -fstack-protector-strong

if IS_LINUX_FAMILY
AM_LDFLAGS += -Wl,-z,stack-size=8388608
endif

endif # USES_GCC

#
# Sun C
#
###############################################################################

if USES_SUNC

# SUNC

AM_AR = ar
AM_LD = ld

AM_CFLAGS += -DUSES_SUNC

DEBUGFLAGS += -DMODE_DEBUG_SUNC

# Note: add a _d suffix for debug builds ?

endif # SUNC

#
# Unknown compiler
#
###############################################################################

if USES_UNKNOWN
# if an unknown compiler is used, it should have its own section
AM_CFLAGS += -DUSES_UNKNOWN_COMPILER
DEBUGFLAGS += -DMODE_DEBUG_UNKNOWN
endif

#
# Some BSD-based OSes need this
#

if IS_BSD_FAMILY
AM_CFLAGS += -I./include
endif

if IS_SOLARIS_FAMILY
AM_CFLAGS += -D_POSIX_PTHREAD_SEMANTICS
endif

#
#
#

AM_CFLAGS += $(LOCALFLAGS)

### YRCFLAGS = -DNDEBUG $(CCOPTIMISATIONFLAGS) -g -DCMR
### YPCFLAGS = -DNDEBUG $(CCOPTIMISATIONFLAGS) -pg -DCMP
### YDCFLAGS = -DDEBUG $(DEBUGFLAGS) -DCMD
### YSCFLAGS = $(YRCFLAGS)
### 
### YRLDFLAGS = -g
### YPLDFLAGS = -pg
### YDLDFLAGS = -g
### 
### if HAS_CC_RDYNAMIC
### YPLDFLAGS += -rdynamic
### YDLDFLAGS += -rdynamic
### endif
### 
### if USES_CLANG
### # workaround a bug where clang does not handle properly profiling and optimizations
### YPCFLAGS += -mno-omit-leaf-frame-pointer -fno-omit-frame-pointer
### endif
### 
### YSLDFLAGS = $(YRLDFLAGS)
### 
### AM_CFLAGS += $(YCFLAGS)
### AM_LDFLAGS += $(YLDFLAGS)
### 
### AM_MAKEFLAGS=MODE_CFLAGS="$(AM_CFLAGS)" CC=$(CC) AR=$(AM_AR) LD=$(AM_LD)
