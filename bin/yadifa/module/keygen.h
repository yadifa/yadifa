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



/** @defgroup yadifa
 *  @ingroup ###
 *  @brief yadifa
 */


#include "module.h"


typedef struct yadifa_keygen_settings_s yadifa_keygen_settings_s;
struct yadifa_keygen_settings_s
{
    u8 *origin;
    //char                                                       *config_file;
    char                                                     *keys_path;
    char                                                *random_device_file;

    char                                                          *key_flag;
    char                                                         *algorithm;

    char                                                  *publication_date_text;
    char                                                   *activation_date_text;
    char                                                   *revocation_date_text;
    char                                                 *inactivation_date_text;
    char                                                     *deletion_date_text;

    int                                                                 ttl;
    int                                                            key_size;
    int                                                              digest;
    int                                                            interval;
    int                                                     verbosity_level;

    u8                                                                 test; /// @TODO 20160511 gve -- needs to be removed afterward

    bool                                                  generate_key_only;
    bool                                            backward_compatible_key;
    bool                                                      successor_key;
    bool                                                      nsec3_capable;


};


#ifndef KEYGEN_C_

extern const module_s keygen_program;

#endif

