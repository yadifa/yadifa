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

/** @defgroup chroot
 *  @ingroup dnscore
 *  @brief Chroot functions
 *
 * @{
 */

#include "dnscore/dnscore-config.h"
#include <unistd.h>
#include <sys/stat.h>
#include <string.h>

#include "dnscore/thread.h"
#include "dnscore/chroot.h"
#include "dnscore/logger.h"
#include "dnscore/ptr_set.h"
#include "dnscore/mutex.h"

#define MODULE_MSG_HANDLE g_system_logger

static const char CHROOT_DEFAULT[] = "/";
static const char *chroot_path = CHROOT_DEFAULT;
static bool chroot_jailed = FALSE;

#define CHRTMPTH_TAG 0x4854504d54524843

struct chroot_managed_path_s
{
    char **managed_location;
    char *prefixed_path;
    bool chrooted;
};

typedef struct chroot_managed_path_s chroot_managed_path_s;

static ptr_set chroot_managed_path_set = PTR_SET_PTR_EMPTY;
static mutex_t choot_managed_path_set_mtx = MUTEX_INITIALIZER;

/**
 * chroot relative: /my-sub-dirs or my-sub-dirs
 * not chroot relative: /my-chroot/my-sub-dirs
 *
 * @param managed_location is a pointer to the pointer of the path which MUST be mallocated (e.g.: strdup).
 * @param path
 * @param chroot_relative
 */

ya_result
chroot_manage_path(char **managed_location, const char *path, bool chroot_relative)
{
    const char *cp = chroot_get_path();;
    const char *prefixed_path = path;
    int cl = ((int)strlen(cp)) - 1;
    
    if(cl < 0)
    {
        return ERROR;
    }
    
    if(cp[cl] != '/')
    {
        return ERROR;
    }
    
    if(!chroot_relative)
    {
        int pl = (int)strlen(path);
        
        if(pl < cl)
        {
            return ERROR;
        }
        
        if(memcmp(path, cp, (size_t )cl) != 0)
        {
            return ERROR; // prefix is wrong
        }
        
        prefixed_path = &path[cl];
    }
    else
    {
        if(path[0] != '/')
        {
            return ERROR;
        }
    }
    
    mutex_lock(&choot_managed_path_set_mtx);
    
    ptr_node *node = ptr_set_insert(&chroot_managed_path_set, managed_location);
    if(node->value == NULL)
    {
        chroot_managed_path_s *cmp;
        MALLOC_OBJECT_OR_DIE(cmp, chroot_managed_path_s, CHRTMPTH_TAG);
        cmp->managed_location = managed_location;
        cmp->prefixed_path = strdup(prefixed_path);
        cmp->chrooted = FALSE;
        node->value = cmp;

        mutex_unlock(&choot_managed_path_set_mtx);
        
        return SUCCESS;
    }
    else
    {
            // location already managed
        mutex_unlock(&choot_managed_path_set_mtx);
        return ERROR;
    }
}

ya_result
chroot_unmanage_path(char **managed_location)
{
    mutex_lock(&choot_managed_path_set_mtx);
    
    ptr_node *node = ptr_set_find(&chroot_managed_path_set, managed_location);
    if(node != NULL)
    {
        chroot_managed_path_s *cmp = (chroot_managed_path_s*)node->value;
        ptr_set_delete(&chroot_managed_path_set, managed_location);
        free(*cmp->managed_location);
        *cmp->managed_location = NULL;
        free(cmp->prefixed_path);
        free(cmp);
        
        mutex_unlock(&choot_managed_path_set_mtx);
        
        return SUCCESS;
    }
    else
    {
        mutex_unlock(&choot_managed_path_set_mtx);
        
        return ERROR;
    }
}

static void
chroot_unmanage_all_cb(ptr_node *node)
{
    chroot_managed_path_s *cmp = (chroot_managed_path_s*)node->value;
    free(*cmp->managed_location);
    *cmp->managed_location = NULL;
    free(cmp->prefixed_path);
    free(cmp);
}

void
chroot_unmanage_all()
{
    mutex_lock(&choot_managed_path_set_mtx);
    ptr_set_callback_and_destroy(&chroot_managed_path_set, chroot_unmanage_all_cb);
    mutex_unlock(&choot_managed_path_set_mtx);
}

const char *
chroot_get_path()
{
    return chroot_path;
}

ya_result
chroot_set_path(const char *path)
{
    if(chroot_jailed)
    {
        return CHROOT_ALREADY_JAILED;
    }
    
    if(path != NULL)
    {
        if(strcmp(path, chroot_path) == 0)
        {
            return SUCCESS;
        }

        struct stat fileinfo;

        if(stat(path, &fileinfo) < 0)
        {
            return ERRNO_ERROR;
        }
        /* Is it a directory ? */
        if(!S_ISDIR(fileinfo.st_mode))
        {
            return CHROOT_NOT_A_DIRECTORY;
        }

        if(chroot_path != CHROOT_DEFAULT)
        {
            free((char*)chroot_path);
        }

        chroot_path = strdup(path);
    }
    else
    {
        if(chroot_path != CHROOT_DEFAULT)
        {
            free((char*)chroot_path);
            chroot_path = CHROOT_DEFAULT;
        }
    }
    
#if DEBUG
    osformatln(termout, "chroot_set_path: set to '%s'", chroot_path);
#endif
    
    return SUCCESS;
}

/**
 * dummy thread used to pre-load libgcc_s.so.1 (if the architecture needs this)
 * 
 * @param config
 */

static void *
chroot_jail_dummy_thread(void *parm)
{    
    thread_exit(parm);

    // unreachable
    // return parm;
    return NULL;	// just so the compiler shuts-up
}

ya_result
chroot_jail()
{
    if(chroot_jailed)
    {
        return CHROOT_ALREADY_JAILED;
    }
    
    thread_t t;
    
    /**
     * This thread is a workaround against libraries not being linked yet
     * from outside the chroot environment.
     * 
     * Launching it will trigger the linkage.
     */
    
    if(thread_create(&t, chroot_jail_dummy_thread, NULL) == 0)
    {
        thread_join(t, NULL);
    }
    else
    {
        log_err("chroot-jail: unable to start dummy thread");
    }
    
    if(chroot(chroot_path) < 0)   
    {
        return ERRNO_ERROR;
    }
    
    chroot_jailed = TRUE;
    
    if(chdir("/") < 0)
    {
        log_warn("chroot-jail: failed to change directory to '/'");
    }
    
    mutex_lock(&choot_managed_path_set_mtx);
     
    ptr_set_iterator iter;
    ptr_set_iterator_init(&chroot_managed_path_set, &iter);
    while(ptr_set_iterator_hasnext(&iter))
    {
        ptr_node *node = ptr_set_iterator_next_node(&iter);
        chroot_managed_path_s *cmp = (chroot_managed_path_s*)node->value;
        if(!cmp->chrooted)
        {
            char *new_path = strdup(cmp->prefixed_path);
            char *old_path = *cmp->managed_location;
            
            int new_path_len = (int)strlen(new_path);
            
            bool dirsep = TRUE;
            int j = 1;
            for(int i = 1; i <= new_path_len; i++)
            {
                char c = new_path[i];
                if(c == '/')
                {
                    if(!dirsep)
                    {
                        new_path[j++] = c;
                    }
                    dirsep = TRUE;
                }
                else
                {
                    new_path[j++] = new_path[i];
                    dirsep = FALSE;
                }
            }
#if DEBUG
            log_debug("chroot-jail: @%p: '%s' -> '%s'", *cmp->managed_location, old_path, new_path);
#endif
            *cmp->managed_location = new_path;
            free(old_path);
            cmp->chrooted = TRUE;
        }
    }
    
    mutex_unlock(&choot_managed_path_set_mtx);
    
    return SUCCESS;
}

/** @} */
