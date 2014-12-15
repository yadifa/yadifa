/*------------------------------------------------------------------------------
*
* Copyright (c) 2011, EURid. All rights reserved.
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
/** @defgroup records_labels Internal functions for the database: zoned resource records label.
 *  @ingroup dnsdb
 *  @brief Internal functions for the database: zoned resource records label.
 *
 *  Internal functions for the database: zoned resource records label.
 *
 * @{
 */



#include <dnscore/format.h>

#include "dnsdb/zdb_types.h"
#include "dnsdb/zdb_record.h"
#include "dnsdb/zdb_rr_label.h"
#include "dnsdb/zdb_utils.h"
#include "dnsdb/zdb_error.h"
#include "dnsdb/zdb_dnsname.h"

#include "dnsdb/zdb_listener.h"

#include "dnsdb/dictionary.h"

static void zdb_rr_label_destroy_callback(dictionary_node* rr_label_record, void* arg);

/**
 *  NSEC3: Zone possible
 *
 * @note The zdb_rr_label_free functions handles the NSEC3 extension.
 *
 */
static inline void
zdb_rr_label_free(zdb_zone* zone, zdb_rr_label* label)
{
    dictionary_destroy_ex(&(label)->sub, zdb_rr_label_destroy_callback, zone);
    zdb_record_destroy(&(label)->resource_record_set); /// @note not an edition, use only for cleanup/delete


#ifdef DEBUG
#if ZDB_HAS_NSEC_SUPPORT != 0
    if((label->flags & ZDB_RR_LABEL_NSEC) != 0)
    {
        /*
         * Here, if there are NSEC nodes pointing to the label they MUST have been destroyed
         */

#if defined(DEBUG)
        yassert(label->nsec.nsec.node == NULL);
#endif
    }
#endif
#endif

#if ZDB_HAS_NSEC3_SUPPORT != 0
    if((label->flags & ZDB_RR_LABEL_NSEC3) != 0)
    {
        /*
         * Here, if there are NSEC3 nodes pointing to the label they MUST be destroyed
         */

        if(label->nsec.nsec3 != NULL)
        {
            yassert(label->nsec.nsec3->self == NULL);
            yassert(label->nsec.nsec3->star == NULL);

            ZFREE(label->nsec.nsec3, nsec3_label_extension);
        }
    }
#endif
    
    u32 len = label->name[0]; /* get the memory required to store the label name */
    len++;
    u32 pad = (len > 2)?0:2-len;

    ZFREE_ARRAY(label, sizeof(zdb_rr_label) - 1 + len + pad);
}

/**
 * @brief INTERNAL callback
 */

static void
zdb_rr_label_destroy_callback(dictionary_node* rr_label_record, void* zone)
{
    if(rr_label_record == NULL)
    {
        return;
    }

    zdb_rr_label* rr_label = (zdb_rr_label*)rr_label_record;

    /* detach is made by destroy */

    /* dictionary destroy will take every item in the dictionary and
     * iterate through it calling the passed function.
     *
     * Maybe I should use the iterator directly instead.
     */

    zdb_rr_label_free((zdb_zone*)zone, rr_label); // valid call because in a delete
}

/**
 * @brief INTERNAL callback
 */

/* NSEC3: Zone possible */
static int
zdb_rr_label_zlabel_match(const void* label, const dictionary_node* node)
{
    const zdb_rr_label* rr_label = (const zdb_rr_label*)node;
    return dnslabel_equals(rr_label->name, label);
}

zdb_rr_label*
zdb_rr_label_new_instance(const u8* label_name)
{
    zdb_rr_label* rr_label;

    u32 len = label_name[0]; /* get the memory required to store the label name */
    len++;
    u32 pad = (len > 2)?0:2-len;
    ZALLOC_ARRAY_OR_DIE(zdb_rr_label*, rr_label, sizeof(zdb_rr_label) - 1 + len + pad, ZDB_RRLABEL_TAG);
    
#ifdef DEBUG
    memset(rr_label, 0xac, sizeof(zdb_rr_label) - 1 + len);
#endif
    rr_label->name[1] = (u8)0xee;   // this slot is guaranteed by pad, and used by the wild card 16 bits test
                                    // specifically written a byte here avoid a valgrind check
                                    // (otherwise harmless : 8 bytes are allocated at least, no overrun is possible)
    MEMCOPY(rr_label->name, label_name, len);

    rr_label->next = NULL;
    btree_init(&rr_label->resource_record_set);
    dictionary_init(&rr_label->sub);

    rr_label->flags = 0;

#if ZDB_HAS_DNSSEC_SUPPORT != 0
    /* I have to clean this pointer, the caller will be responsible
     * for setting it up.
     */
    rr_label->nsec.dnssec = NULL;

#endif

    return rr_label;
}

/**
 * @brief INTERNAL callback
 */

static dictionary_node*
zdb_rr_label_create_callback(const void* data)
{
    zdb_rr_label* rr_label = zdb_rr_label_new_instance((const u8*)data);

    return (dictionary_node*)rr_label;
}

/**
 * @brief Destroys an rr label and its contents
 *
 * Destroys an rr label and its contents
 *
 * @param[in] zone_labep a pointer to a pointer to the label to destroy
 *
 */

/* NSEC3: Zone possible */
void
zdb_rr_label_destroy(zdb_zone* zone, zdb_rr_label** rr_labelp)
{
    yassert(rr_labelp != NULL);

    zdb_rr_label *rr_label = *rr_labelp;

    if(rr_label != NULL)
    {
        zdb_rr_label_free(zone, rr_label); // valid call because in a delete
        *rr_labelp = NULL;
    }
}

/**
 * @brief Destroys an rr label and its contents
 *
 * Destroys an rr label and its contents
 *
 * @param[in] zone_labep a pointer to a pointer to the label to destroy
 *
 */

/* NSEC3: Zone possible */
void
zdb_rr_label_truncate(zdb_zone* zone, zdb_rr_label* rr_label)
{
    if(rr_label != NULL)
    {
        dictionary_destroy_ex(&rr_label->sub, zdb_rr_label_destroy_callback, zone);
        zdb_record_destroy(&rr_label->resource_record_set); /// @note not an edition, use only for cleanup/delete
    }
}

/**
 * @brief Finds the resource record label matching a path of labels starting from another rr label
 *
 * Finds the resource record label matching a path of labels starting from another rr label
 * Typically the starting label is a zone cut.
 *
 * @param[in] apex the starting label
 * @param[in] path a stack of labels
 * @param[in] path_index the index of the top of the stack
 *
 * @return the matching label or NULL if it has not been found
 */

zdb_rr_label*
zdb_rr_label_find_exact(zdb_rr_label* apex, dnslabel_vector_reference sections, s32 index)
{
    zdb_rr_label* rr_label = apex; /* the zone cut */

    /* look into the sub level*/

    while(rr_label != NULL && index >= 0)
    {
        u8* label = sections[index];
        hashcode hash = hash_dnslabel(label);
        rr_label = (zdb_rr_label*)dictionary_find(&rr_label->sub, hash, label, zdb_rr_label_zlabel_match);

        index--;
    }

    return rr_label;
}

zdb_rr_label*
zdb_rr_label_find_child(zdb_rr_label* parent, const u8* dns_label)
{
    hashcode hash = hash_dnslabel(dns_label);
    
    zdb_rr_label *rr_label = (zdb_rr_label*)dictionary_find(&parent->sub, hash, dns_label, zdb_rr_label_zlabel_match);
    
    return rr_label;
}

zdb_rr_label*
zdb_rr_label_stack_find(zdb_rr_label* apex, dnslabel_stack_reference sections, s32 pos, s32 index)
{
    zdb_rr_label* rr_label = apex; /* the zone cut */

    /* look into the sub level*/

    while(rr_label != NULL && index <= pos)
    {
        u8* label = sections[index];
        hashcode hash = hash_dnslabel(label);

        rr_label = (zdb_rr_label*)dictionary_find(&rr_label->sub, hash, label, zdb_rr_label_zlabel_match);

        index++;
    }

    return rr_label;
}

/**
 * @brief Finds the resource record label matching a path of labels starting from another rr label or the wildcard label
 *
 * Finds the resource record label matching a path of labels starting from another rr label or the wildcard label
 * Typically the starting label is a zone cut.
 *
 * @param[in] apex the starting label
 * @param[in] path a stack of labels
 * @param[in] path_index the index of the top of the stack
 *
 * @return the matching label, the * label or NULL if none of them has not been found
 */
#if 1

zdb_rr_label*
zdb_rr_label_find(zdb_rr_label* apex, dnslabel_vector_reference sections, s32 index)
{
    yassert(apex != NULL);

    zdb_rr_label* rr_label = apex; /* the zone cut */

    /* look into the sub level*/

    while(index >= 0)
    {
        u8* label = sections[index];
        hashcode hash = hash_dnslabel(label);

        zdb_rr_label* sub_rr_label = (zdb_rr_label*)dictionary_find(&rr_label->sub, hash, label, zdb_rr_label_zlabel_match);

        if(sub_rr_label == NULL)
        {
            /* If the label does not exist BUT we got a wildcard, THEN it is what we are looking for */
            
            if((rr_label->flags & ZDB_RR_LABEL_GOT_WILD) != 0)
            {
                rr_label = (zdb_rr_label*)dictionary_find(&rr_label->sub, WILD_HASH, (void*)WILD_LABEL, zdb_rr_label_zlabel_match);

                return rr_label;
            }

            return sub_rr_label; /* NULL */
        }

        rr_label = sub_rr_label;

        index--;
    }

    return rr_label;
}
#else

zdb_rr_label*
zdb_rr_label_find(zdb_rr_label* apex, dnslabel_vector_reference label_sections, s32 index)
{
    yassert(apex != NULL);

    zdb_rr_label* rr_label = apex; /* the zone cut */

    /* look into the sub level*/
    u8** section = &label_sections[index];

    while(section >= label_sections)
    {
        u8* label = *section--;

        hashcode hash = hash_dnslabel(label);

        zdb_rr_label* sub_rr_label = (zdb_rr_label*)dictionary_find(&rr_label->sub, hash, label, zdb_rr_label_zlabel_match);

        if(sub_rr_label == NULL)
        {
            if((rr_label->flags & ZDB_RR_LABEL_GOT_WILD) != 0)
            {

                rr_label = (zdb_rr_label*)dictionary_find(&rr_label->sub, WILD_HASH, (void*)WILD_LABEL, zdb_rr_label_zlabel_match);

                return rr_label;
            }

            return sub_rr_label;
        }

        rr_label = sub_rr_label;
    }

    return rr_label;
}
#endif

zdb_rr_label*
zdb_rr_label_find_ext(zdb_rr_label* apex, dnslabel_vector_reference sections, s32 index_, zdb_rr_label_find_ext_data *ext)
{
    yassert(apex != NULL && sections != NULL);

    s32 index = index_;
    zdb_rr_label* rr_label = apex; /* the zone cut */

    zdb_rr_label* authority = apex;
    zdb_rr_label* closest = apex;
    s32 authority_index = index_ + 1;
    s32 closest_index = index_ + 1;

    /* look into the sub level*/

    while(index >= 0)
    {
        u8* label = sections[index];
        hashcode hash = hash_dnslabel(label);

        rr_label = (zdb_rr_label*)dictionary_find(&rr_label->sub, hash, label, zdb_rr_label_zlabel_match);

        if(rr_label == NULL)
        {
            /* If the label does not exist BUT we got a wildcard, THEN it is what we are looking for */
            
            if((closest->flags & ZDB_RR_LABEL_GOT_WILD) != 0)
            {
                /* got it all anyway, from previous node ... */

                rr_label = (zdb_rr_label*)dictionary_find(&closest->sub, WILD_HASH, (void*)WILD_LABEL, zdb_rr_label_zlabel_match);
                closest_index = 0;
            }

            break;
        }

        if((rr_label->flags & ZDB_RR_LABEL_DELEGATION) != 0)
        {
            authority = rr_label;
            authority_index = index;
        }

        closest = rr_label;
        closest_index = index;

        index--;
    }

    ext->authority = authority;
    ext->closest = closest;
    ext->answer = rr_label;
    ext->authority_index = authority_index;
    ext->closest_index = closest_index;
    
    return rr_label;
}

/**
 * @brief Adds the resource record label matching a path of labels starting from another rr label
 *
 * Adds the resource record label matching a path of labels starting from another rr label
 * Typically the starting label is a zone cut.
 *
 * @param[in] apex the starting label
 * @param[in] path a stack of labels
 * @param[in] path_index the index of the top of the stack
 *
 * @return the matching label or NULL if it has not been found
 */

zdb_rr_label*
zdb_rr_label_add(zdb_zone* zone, dnslabel_vector_reference labels, s32 labels_top)
{
    zdb_rr_label* rr_label = zone->apex; /* the zone cut */

    /* look into the sub level*/

    u16 or_flags = 0;

    while(labels_top >= 0)
    {
        u8* label = labels[labels_top];
        hashcode hash = hash_dnslabel(label);
        
        /* If the current label is '*' (wild) then the parent is marked as owner of a wildcard. */

        if(IS_WILD_LABEL(label))
        {
            rr_label->flags |= ZDB_RR_LABEL_GOT_WILD;
        }
        
        rr_label = (zdb_rr_label*)dictionary_add(&rr_label->sub, hash, label, zdb_rr_label_zlabel_match, zdb_rr_label_create_callback);

        rr_label->flags |= or_flags;

        if((rr_label->flags & ZDB_RR_LABEL_DELEGATION) != 0)
        {
            /* the next one down is under a delegation */
            
            or_flags = ZDB_RR_LABEL_UNDERDELEGATION;
        }

        labels_top--;
    }

    return rr_label;
}

/* once */

typedef struct zdb_rr_label_delete_record_process_callback_args zdb_rr_label_delete_record_process_callback_args;

struct zdb_rr_label_delete_record_process_callback_args
{
    dnslabel_vector_reference sections;
    zdb_zone* zone;
    s32 top;
    u16 type;
};

/**
 * @brief INTERNAL callback
 */

static ya_result
zdb_rr_label_delete_record_process_callback(void* a, dictionary_node* node)
{
    yassert(node != NULL);

    zdb_rr_label* rr_label = (zdb_rr_label*)node;

    zdb_rr_label_delete_record_process_callback_args* args = (zdb_rr_label_delete_record_process_callback_args*)a;

    /*
     * a points to a kind of dnsname and we are going in
     *
     * we go down and down each time calling the dictionnary process for the next level
     *
     * at the last level we return the "delete" code
     *
     * from there, the dictionnary processor will remove the entry
     *
     * at that point the calling dictionnary will know if he has to delete his node or not
     *
     * and so on and so forth ...
     *
     */

    s32 top = args->top;
    u8* label = (u8*)args->sections[top];

    if(!dnslabel_equals(rr_label->name, label))
    {
        return COLLECTION_PROCESS_NEXT;
    }

    /* match */

    if(top > 0)
    {
        /* go to the next level */

        label = args->sections[--args->top];
        hashcode hash = hash_dnslabel(label);

        ya_result err;
        if((err = dictionary_process(&rr_label->sub, hash, args, zdb_rr_label_delete_record_process_callback)) == COLLECTION_PROCESS_DELETENODE)
        {
            /* check the node for relevance, return "delete" if irrelevant */

            if(RR_LABEL_IRRELEVANT(rr_label))
            {
                zdb_rr_label_free(args->zone, rr_label); // valid call because in a delete

                return COLLECTION_PROCESS_DELETENODE;
            }
            
            /* If the label just removed is a wildcard, then the parent is marked as not having a wildcard. */
             
            if(IS_WILD_LABEL(label))
            {
                rr_label->flags &= ~ZDB_RR_LABEL_GOT_WILD;
            }

            return COLLECTION_PROCESS_STOP;
        }

        /* or ... stop */

        return err;
    }

    /* We are at the right place for the record */

#if ZDB_CHANGE_FEEDBACK_SUPPORT != 0
    zdb_listener_notify_remove_type(args->sections[args->top], &rr_label->resource_record_set, args->type);
#endif

    ya_result err;

    if(ISOK(err = zdb_record_delete(&rr_label->resource_record_set, args->type))) /* FB done */
    {
        if(RR_LABEL_RELEVANT(rr_label))
        {
            /* If the type was NS, clear the delegation flag */

            u16 clear_mask = 0;
            switch(args->type)
            {
                case TYPE_NS:
                    clear_mask = ~ZDB_RR_LABEL_DELEGATION; // will clear "delegation"
                    break;
                case TYPE_CNAME:
                    clear_mask = ~ZDB_RR_LABEL_HASCNAME; // will clear "has cname"
                    break;
                case TYPE_ANY:
                    clear_mask = ~(ZDB_RR_LABEL_DELEGATION|ZDB_RR_LABEL_DROPCNAME|ZDB_RR_LABEL_HASCNAME); // will clear "delegation", "drop cname" and "has cname"
                    break;
                case TYPE_RRSIG:
                case TYPE_NSEC:
                    break;
                default:
                    // checks if there are any other types than CNAME, RRSIG and NSEC, clears DROPCNAME if it's true
                    clear_mask = ~ZDB_RR_LABEL_DROPCNAME; // will clear "drop cname"
                    break;
            }

            rr_label->flags &= clear_mask; // clears the bits using the mask

            return COLLECTION_PROCESS_STOP;
        }

        /* NOTE: the 'detach' is made by destroy : do not touch to the "next" field */
        /* NOTE: the freee of the node is made by destroy : do not do it */

        /* dictionary destroy will take every item in the dictionary and
         * iterate through it calling the passed function.
         */

        zdb_rr_label_free(args->zone, rr_label); // valid call because in a delete

        return COLLECTION_PROCESS_DELETENODE;
    }

    return err /*COLLECTION_PROCESS_RETURNERROR*/;
}

/**
 * @brief Deletes the resource record of the given type on the label matching a path of labels starting from another rr label
 *
 * Deletes the resource record of the given type on the label matching a path of labels starting from another rr label
 * Typically the starting label is a zone cut.
 *
 * @param[in] apex the starting label
 * @param[in] path a stack of labels
 * @param[in] path_index the index of the top of the stack
 *
 * @return the matching label or NULL if it has not been found
 */

ya_result
zdb_rr_label_delete_record(zdb_zone* zone, dnslabel_vector_reference path, s32 path_index, u16 type)
{
    yassert(zone != NULL && path != NULL && path_index >= -1);

    zdb_rr_label* apex = zone->apex;

    if(apex == NULL)
    {
        return ZDB_ERROR_DELETEFROMEMPTY;
    }
    
    if(path_index < 0)
    {
        if(ISOK(zdb_record_delete(&apex->resource_record_set, type))) /* FB done, APEX : no delegation */
        {
#if ZDB_CHANGE_FEEDBACK_SUPPORT != 0
            zdb_listener_notify_remove_type(path[path_index], &apex->resource_record_set, type);
#endif
            /*
            if(RR_LABEL_IRRELEVANT(apex))
            {
                zdb_rr_label_free(zone, apex); // valid call because in a delete
                zone->apex = NULL;

                return ZDB_RR_LABEL_DELETE_TREE;
            }
            */
            
            return ZDB_RR_LABEL_DELETE_NODE;
        }

        return ZDB_ERROR_KEY_NOTFOUND;
    }

    zdb_rr_label_delete_record_process_callback_args args;
    args.sections = path;
    args.zone = zone;
    args.top = path_index;
    args.type = type;

    hashcode hash = hash_dnslabel(args.sections[args.top]);

    ya_result err;

    if((err = dictionary_process(&apex->sub, hash, &args, zdb_rr_label_delete_record_process_callback)) == COLLECTION_PROCESS_DELETENODE)
    {
        if(RR_LABEL_IRRELEVANT(apex))
        {
            zdb_rr_label_free(zone, apex); // valid call because in a delete
            zone->apex = NULL;

            return ZDB_RR_LABEL_DELETE_TREE;
        }
        
        /* If the label just removed is a wildcard, then the parent is marked as not having a wildcard. */

        if(IS_WILD_LABEL(args.sections[args.top]))
        {
            apex->flags &= ~ZDB_RR_LABEL_GOT_WILD;
        }

        return ZDB_RR_LABEL_DELETE_NODE;
    }

    return err;
}

typedef struct zdb_rr_label_delete_record_exact_process_callback_args zdb_rr_label_delete_record_exact_process_callback_args;

struct zdb_rr_label_delete_record_exact_process_callback_args
{
    dnslabel_vector_reference sections;
    zdb_ttlrdata* ttlrdata;
    zdb_zone* zone;
    s32 top;
    u16 type;
};

/**
 * @brief INTERNAL callback
 */

/* NSEC3: Zone possible */
static ya_result
zdb_rr_label_delete_record_exact_process_callback(void* a, dictionary_node* node)
{
    yassert(node != NULL);

    zdb_rr_label* rr_label = (zdb_rr_label*)node;

    zdb_rr_label_delete_record_exact_process_callback_args* args = (zdb_rr_label_delete_record_exact_process_callback_args*)a;

    /*
     * a points to a kind of dnsname and we are going in
     *
     * we go down and down each time calling the dictionnary process for the next level
     *
     * at the last level we return the "delete" code
     *
     * from there, the dictionnary processor will remove the entry
     *
     * at that point the calling dictionnary will know if he has to delete his node or not
     *
     * and so on and so forth ...
     *
     */

    s32 top = args->top;
    u8* label = (u8*)args->sections[top];

    if(!dnslabel_equals(rr_label->name, label))
    {
        return COLLECTION_PROCESS_NEXT;
    }

    /* match */

    if(top > 0)
    {
        /* go to the next level */

        label = args->sections[--args->top];
        hashcode hash = hash_dnslabel(label);

        ya_result return_code;

        if((return_code = dictionary_process(&rr_label->sub, hash, args, zdb_rr_label_delete_record_exact_process_callback)) == COLLECTION_PROCESS_DELETENODE)
        {
            /* check the node for relevance, return "delete" if irrelevant */

            if(RR_LABEL_IRRELEVANT(rr_label))
            {
                zdb_rr_label_free(args->zone, rr_label); // valid call because in a delete

                return COLLECTION_PROCESS_DELETENODE;
            }
            
            /* If the label just removed is a wildcard, then the parent is marked as not having a wildcard. */

            if(IS_WILD_LABEL(label))
            {
                rr_label->flags &= ~ZDB_RR_LABEL_GOT_WILD;
            }

            return COLLECTION_PROCESS_STOP;
        }

        /* or ... stop */

        return return_code;
    }

    /* We are at the right place for the record */

    ya_result delete_return_code;

    if(ISOK(delete_return_code = zdb_record_delete_exact(&rr_label->resource_record_set, args->type, args->ttlrdata))) /* FB done */
    {

        /*
         * @NOTE delete_return_code can be either SUCCESS_STILL_RECORDS or SUCCESS_LAST_RECORD
         */

#if ZDB_CHANGE_FEEDBACK_SUPPORT != 0
        zdb_listener_notify_remove_record(args->sections[args->top], args->type, args->ttlrdata);
#endif

        if(RR_LABEL_RELEVANT(rr_label))
        {
            /* If the type was XXXX and we deleted the last one the flag may change.
             * NS => not a delegation anymore
             * CNAME => no cname anymore
             * ANY => nothing anymore (and should not be relevant anymore either ...)
             */

            if(delete_return_code == SUCCESS_LAST_RECORD)
            {
                u16 clear_mask = ~0;
                switch(args->type)
                {
                    case TYPE_NS:
                        clear_mask = ~ZDB_RR_LABEL_DELEGATION; // will clear "delegation"
                        break;
                    case TYPE_CNAME:
                        clear_mask = ~ZDB_RR_LABEL_HASCNAME; // will clear "has cname"
                        break;
                    case TYPE_ANY:
                        clear_mask = ~(ZDB_RR_LABEL_DELEGATION|ZDB_RR_LABEL_DROPCNAME|ZDB_RR_LABEL_HASCNAME); // will clear "delegation", "drop cname" and "has cname"
                        break;
                    case TYPE_RRSIG:
                    case TYPE_NSEC:
                        break;
                    default:
                        // checks if there are any other types than CNAME, RRSIG and NSEC, clears DROPCNAME if it's true
                        clear_mask = ~ZDB_RR_LABEL_DROPCNAME; // will clear "drop cname"
                        break;
                }

                rr_label->flags &= clear_mask;
            }

            return COLLECTION_PROCESS_STOP;
        }

        /* NOTE: the 'detach' is made by destroy : do not touch to the "next" field */
        /* NOTE: the freee of the node is made by destroy : do not do it */

        /* dictionary destroy will take every item in the dictionary and
         * iterate through it calling the passed function.
         */

        zdb_rr_label_free(args->zone, rr_label); // valid call because in a delete

        return COLLECTION_PROCESS_DELETENODE;
    }

    return delete_return_code /*COLLECTION_PROCESS_RETURNERROR*/;
}

/**
 * @brief Deletes the resource record of the given type, ttl and rdata on the label matching a path of labels starting from another rr label
 *
 * Deletes the resource record of the given type, ttl and rdata on the label matching a path of labels starting from another rr label
 * Typically the starting label is a zone cut.
 *
 * @param[in] apex the starting label
 * @param[in] path a stack of labels
 * @param[in] path_index the index of the top of the stack
 *
 * @return the matching label or NULL if it has not been found
 */

/* NSEC3: Zone possible */
ya_result
zdb_rr_label_delete_record_exact(zdb_zone* zone, dnslabel_vector_reference path, s32 path_index, u16 type, zdb_ttlrdata* ttlrdata)
{
    zdb_rr_label* apex = zone->apex;

    if(apex == NULL)
    {
        return ZDB_ERROR_DELETEFROMEMPTY;
    }

    /* Are we working on the apex ? */

    if(path_index < 0)
    {
        if(ISOK(zdb_record_delete_exact(&apex->resource_record_set, type, ttlrdata))) /* FB done, APEX : no delegation */
        {
#if ZDB_CHANGE_FEEDBACK_SUPPORT != 0
            zdb_listener_notify_remove_record(path[path_index], type, ttlrdata);
#endif
            if(RR_LABEL_IRRELEVANT(apex))
            {
                zdb_rr_label_free(zone, apex); // valid call because in a delete
                zone->apex = NULL;

                return ZDB_RR_LABEL_DELETE_TREE;
            }

            return ZDB_RR_LABEL_DELETE_NODE;
        }

        return ZDB_ERROR_KEY_NOTFOUND;
    }

    /* We are not working on the apex */

    zdb_rr_label_delete_record_exact_process_callback_args args;
    args.sections = path;
    args.ttlrdata = ttlrdata;
    args.zone = zone;
    args.top = path_index;
    args.type = type;

    hashcode hash = hash_dnslabel(args.sections[args.top]);

    ya_result err;

    if((err = dictionary_process(&apex->sub, hash, &args, zdb_rr_label_delete_record_exact_process_callback)) == COLLECTION_PROCESS_DELETENODE)
    {
        if(RR_LABEL_IRRELEVANT(apex))
        {
            zdb_rr_label_free(zone, apex); // valid call because in a delete
            zone->apex = NULL;

            return COLLECTION_PROCESS_DELETENODE;
        }
        
        /* If the label just removed is a wildcard, then the parent is marked as not having a wildcard. */

        if(IS_WILD_LABEL(args.sections[args.top]))
        {
            apex->flags &= ~ZDB_RR_LABEL_GOT_WILD;
        }

        return COLLECTION_PROCESS_STOP;
    }

    return err;
}

#ifdef DEBUG

void
zdb_rr_label_print_indented(zdb_rr_label* rr_label, output_stream *os, int indent)
{
    osformatln(os, "%tl: '%{dnslabel}'(%u) #[%08x]", indent, rr_label->name, rr_label->flags, hash_dnslabel(rr_label->name));

    indent++;

    zdb_record_print_indented(rr_label->resource_record_set, os, indent);

    dictionary_iterator iter;
    dictionary_iterator_init(&rr_label->sub, &iter);
    while(dictionary_iterator_hasnext(&iter))
    {
        zdb_rr_label** sub_labelp = (zdb_rr_label**)dictionary_iterator_next(&iter);

        zdb_rr_label_print_indented(*sub_labelp, os, indent);
    }
}

void
zdb_rr_label_print(zdb_rr_label* rr_label, output_stream *os)
{
    zdb_rr_label_print_indented(rr_label, os, 0);
}

#endif
