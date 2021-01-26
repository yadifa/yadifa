/*------------------------------------------------------------------------------
 *
 * Copyright (c) 2011-2021, EURid vzw. All rights reserved.
 * The YADIFA TM software product is provided under the BSD 3-clause license:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *        * Redistributions of source code must retain the above copyright
 *          notice, this list of conditions and the following disclaimer.
 *        * Redistributions in binary form must reproduce the above copyright
 *          notice, this list of conditions and the following disclaimer in the
 *          documentation and/or other materials provided with the distribution.
 *        * Neither the name of EURid nor the names of its contributors may be
 *          used to endorse or promote products derived from this software
 *          without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 *------------------------------------------------------------------------------
 *
 */

#pragma once

#include <dnsdb/journal.h>

#ifdef	__cplusplus
extern "C" {
#endif

#if JOURNAL_CJF_ENABLED
    
// Internal function, this is probably not the one you want to use.
    
ya_result journal_cjf_open_file(journal **jhp, const char *filename, const u8* origin, bool create);

/**
 * The caller guarantees not to call this on an already opened journal
 * 
 * Should not be called directly (only by journal_* functions.
 * 
 * Opens or create a journal handling structure.
 * If the journal did not exist, the structure is returned without a file opened
 * 
 * @param jh
 * @param origin
 * @param workingdir
 * @param create
 * 
 * @return 
 */
    
ya_result journal_cjf_open(journal **jh, const u8 *origin, const char *workingdir, bool create);

void journal_cjf_finalize();

#else

ya_result journal_cjf_ro_open_file(journal **jhp, const char *filename, const u8* origin, bool create);

#endif

#ifdef	__cplusplus
}
#endif

/** @} */
