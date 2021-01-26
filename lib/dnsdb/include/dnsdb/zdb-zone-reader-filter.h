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

/** @defgroup dnsdbzone
 *  @ingroup dnsdb
 *  @brief Functions used to load a zone
 *
 *  Functions used to load a zone
 *
 * @{
 */
#pragma once

#include <dnscore/zone_reader.h>

#define ZONE_READER_FILTER_ACCEPT   0
#define ZONE_READER_FILTER_REJECT   1

/**
 * 
 * The filter returns ACCEPT, REJECT or an error code.
 * 
 */

typedef ya_result zone_file_reader_filter_callback(zone_reader *zr, resource_record *rr, void *callback_data);


/**
 * 
 * Wraps a zone_reader to a filter that skips records using a callback
 * 
 * @param filtering_reader  the filter
 * @param filtered_reader   the filtered
 * @param callback          the callback function
 * @param callback_data     parameter given to the callback function
 */

void zone_file_reader_filter(zone_reader *filtering_reader,
                                zone_reader *filtered_reader,
                                zone_file_reader_filter_callback *callback,
                                void *callback_data);

/**
 * @}
 */
