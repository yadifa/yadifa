/*------------------------------------------------------------------------------
*
* Copyright (c) 2011-2016, EURid. All rights reserved.
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

#include "config.h"

#include <dnscore/dnscore.h>
#include <dnscore/host_address.h>

#ifdef	__cplusplus
extern "C" {
#endif
    
#define TOSTRING(s) TOSTRING_(s)
#define TOSTRING_(s) #s    
#define PREPROCESSOR_INT2STR(x) #x

     
#define MAIN_CONFIG_LISTEN      "0.0.0.0,::0"
//#define MAIN_CONFIG_MASTER      "10.0.0.11"
#define MAIN_CONFIG_MASTER      "172.19.67.21"
    
#define MAIN_CONFIG_TSIG_NAME   "dynupdate"
#define MAIN_CONFIG_TSIG_ALG    "hmac-md5"
#define MAIN_CONFIG_TSIG_SECRET "MasterAndSlavesTSIGKey=="
    
#define MAIN_CONFIG_CONFIG_FILE PREFIX "/etc/" PACKAGE ".conf"
#define MAIN_CONFIG_LOG_PATH    PREFIX "/var/log"
#define MAIN_CONFIG_PID_FILE    PREFIX "/var/run/" PACKAGE ".pid"
#define MAIN_CONFIG_XFR_PATH    PREFIX "/var/xfr/"
    
#define MAIN_CONFIG_ORIGIN      "eu"
    
#define MAIN_CONFIG_XFR_CONNECT_TIMEOUT_S 10
#define MAIN_CONFIG_XFR_CONNECT_TIMEOUT_S_MIN 1
#define MAIN_CONFIG_XFR_CONNECT_TIMEOUT_S_MAX 300
    
#define MAIN_CONFIG_ACTION_POLL_MIN_TIME_S 10
#define MAIN_CONFIG_SHUTDOWN_POLL_TIME_S 1
    
#define MAIN_CONFIG_UID         "-" // by default, use the current user/group
#define MAIN_CONFIG_GID         "-"
    
#define MAIN_CONFIG_IGNORE_IPV6 1
    
#define MAIN_CONFIG_DAEMONIZE   0
    
    ///////
    
    ///////
    
struct main_settings_s
{
    //host_address *listen;
    host_address *master;
    
    char *config_file;
    char *log_path;
    char *pid_file;
    char *xfr_path;
    u8   *origin;
    
    u32   xfr_connect_timeout;
    u32   action_poll_min_time;
    u32   shutdown_poll_time;
    
    uid_t uid;
    gid_t gid;
    
    bool  ignore_ipv6;
    bool  daemonize;
};

typedef struct main_settings_s main_settings_s;

#ifndef MAIN_CONFIG_C
extern main_settings_s *main_settings;
#endif

#ifdef	__cplusplus
}
#endif


