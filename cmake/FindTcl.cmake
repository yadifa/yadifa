################################################################################
#
# Copyright (c) 2011-2025, EURid vzw. All rights reserved.
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

	message(STATUS "\tfind package                 : Tcl")

	set(tcl_versions ${TCL_VERSIONS})
        foreach(TCL_VERSION ${tcl_versions})
                find_path(TCL_INCLUDE_DIR
                                tcl.h
                                PATHS
                                /usr/local /usr
                                PATH_SUFFIXES
                                include ${TCL_VERSION}/include include/${TCL_VERSION}
                                )
        endforeach(TCL_VERSION)

	message(STATUS "\t\tTCL_INCLUDE_DIR      : ${TCL_INCLUDE_DIR}")

        include_directories(${TCL_INCLUDE_DIR})

        find_library(TCL_LIB
                        NAMES
                        ${tcl_versions}
                        PATHS
                        /usr/local/ /usr/ /System/Library/FrameWorks/Tcl.frameworks
                        PATH_SUFFIXES
                        lib
                        )

        # if TCL_LIB is found then fo further otherwise quit
        if(TCL_LIB)
                set(Tcl_FOUND true)
#		message(STATUS "\t\tTcl_FOUND            : ${Tcl_FOUND}")
		message(STATUS "\t\tTCL_LIB              : ${TCL_LIB}")
        else(TCL_LIB)
                message(STATUS "\t\tHAS_TCL              : NOT FOUND!")
                message(SEND_ERROR "TCL is needed")
        endif(TCL_LIB)
	#endfunction(find_tcl)

#find_tcl(${TCL_VERSIONS})
#message(STATUS "\tTcl_FOUND      : ${Tcl_FOUND}")

