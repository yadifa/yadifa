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

include(CheckCCompilerFlag)

function(append_c_compiler_flag FLAG FLAGVARIABLE VARIABLE)
    #message("Testing: '${FLAG}' '${FLAGVARIABLE}' '${VARIABLE}'")
    check_c_compiler_flag(${FLAG} ${FLAGVARIABLE})
    #message("Tested: '${FLAG}' '${FLAGVARIABLE}=${${FLAGVARIABLE}}' '${VARIABLE}=${${VARIABLE}}'")
    if(${FLAGVARIABLE})
        set(${VARIABLE} "${${VARIABLE}} ${FLAG}" PARENT_SCOPE)
        message("Checked for ${FLAG} support: yes")
    else()
        message("Checked for ${FLAG} support: no")
    endif()
endfunction()

function(check_c_compiler_flags)
    #append_c_compiler_flag(-std=gnu11 STD_GNU11 C_COMMON_FLAG)
    #append_c_compiler_flag(-std=c11 STD_C11 C_COMMON_FLAG)
    #append_c_compiler_flag(-std=gnu99 STD_GNU99 C_COMMON_FLAG)
    #append_c_compiler_flag(-std=c99 STD_C99 C_COMMON_FLAG)
    #append_c_compiler_flag(-xc99 XC99 C_COMMON_FLAG)
    #append_c_compiler_flag(-m32 M32 C_COMMON_FLAG)
    #append_c_compiler_flag(-m64 M64 C_COMMON_FLAG)

    append_c_compiler_flag(-mtune=native TUNE_NATIVE C_COMMON_FLAG)
    append_c_compiler_flag(-fno-ident NO_IDENT C_COMMON_FLAG)
    append_c_compiler_flag(-fPIC PIC C_LIBRARY_FLAG)
    #append_c_compiler_flag(-fPIE PIE C_PROGRAM_FLAG)

    append_c_compiler_flag(-ansi ANSI C_COMMON_FLAG)
    append_c_compiler_flag(-ansi-alias ANSI_ALIAS C_COMMON_FLAG)

    append_c_compiler_flag(-Wpedantic PEDANTIC C_COMMON_FLAG)
    append_c_compiler_flag(-Wall WALL C_COMMON_FLAG)
    append_c_compiler_flag(-Werror=missing-field-initializers MISSING_FIELD_INITIALIZERS C_COMMON_FLAG)

    append_c_compiler_flag(-g G C_COMMON_FLAG)
    #append_c_compiler_flag(-g3 G3 C_COMMON_FLAG)
    #append_c_compiler_flag(-gdwarf-2 DWARF2 C_COMMON_FLAG)
    #append_c_compiler_flag(-gdwarf-3 DWARF3 C_COMMON_FLAG)
    #append_c_compiler_flag(-gdwarf-4 DWARF4 C_COMMON_FLAG)

    append_c_compiler_flag(-fexceptions EXCEPTIONS C_CODEGENERATION_FLAG)

    append_c_compiler_flag(-fstack-protector --param=ssp-buffer-size=4 STACK_PROTECTOR C_INSTRUMENTATION_FLAG)
    append_c_compiler_flag(-fsanitize=address SANITIZE_ADDRESS C_COMMON_FLAG)
    append_c_compiler_flag(-fno-omit-frame-pointer NO_OMIT_FRAME_POINTER C_COMMON_FLAG)
    append_c_compiler_flag(-faddress-sanitizer ADDRESS_SANITIZER_CHECK C_COMMON_FLAG)
#    append_c_compiler_flag(-fcatch_undefined_behavior CATCH_UNDEFINED_BEHAVIOR C_COMMON_FLAG)
    append_c_compiler_flag(-rdynamic RDYNAMIC C_COMMON_FLAG)

#    set(C_COMMON_FLAGS "")
#    if(NO_IDENT)
#        set(C_COMMON_FLAGS-fno-ident)
#    endif()
#    if(NO_IDENT)
#        set(C_COMMON_FLAGS-fno-ident)
#    endif()
#    set(C_LIBRARY_FLAGS "")
endfunction()

