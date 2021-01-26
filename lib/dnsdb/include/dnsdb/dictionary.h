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

/** @defgroup dnsdbcollection Collections used by the database
 *  @ingroup dnsdb
 *  @brief Hash-based collection designed to change it's structure to improve speed.
 *
 *  Hash-based collection designed to change it's structure to improve speed.
 *
 * @{
 */
#ifndef _dictionary_H
#define	_dictionary_H

#include <dnscore/sys_types.h>

#include <dnsdb/btree.h>
#include <dnsdb/htbt.h>

//#define DICTIONARY_NODE_MODE 0 // struct
#define DICTIONARY_NODE_MODE 1 // union

#ifdef	__cplusplus
extern "C"
{
#endif

#if !DICTIONARY_NODE_MODE
    
struct dictionary_node;
    
typedef struct dictionary_node dictionary_node;

#else

union dictionary_node;

typedef union dictionary_node dictionary_node;

#endif

/**
 * @brief Function type used to find a node match
 *
 * Function type used to find a node match
 *
 * @param[in] data an arbitrary data (whose meaning is known by the function, of course)
 * @param[in] node the node to checked for a match
 *
 * @return <0, 0, >0 if the node respectively is before the data, matches the data, or is above the data.
 */

typedef int dictionary_data_record_compare_function(const void* data, const dictionary_node* node);

/**
 * @brief Function type used to create a node
 *
 * Function type used to create a node
 *
 * @param[in] data an arbitrary data (whose meaning is known by the function, of course)
 *
 * @return a pointer to a node created from the data
 */

typedef dictionary_node* dictionary_data_record_create_function(const void* data);

/**
 * @brief Function type used to destroy a node
 *
 * Function type used to destroy a node
 *
 * @param[in] node the node to destroy
 */

typedef void dictionary_destroy_record_function(dictionary_node* node);

/**
 * @brief Function type used to destroy a node
 *
 * Function type used to destroy a node
 *
 * @param[in] node the node to destroy
 */

typedef void dictionary_destroy_ex_record_function(dictionary_node* node, void* arg);


/**
 * @brief Function type used to transfer a node just detached from a dictionary
 *
 * Function type used to transfer a node just detached from a dictionary to another
 *
 * @param[in] bucket_data an arbitrary data passed to the function
 * @param[in] key the hashcode of the node detached from the dicionary
 * @param[in] node the node detached from the dictionary
 */

typedef void dictionary_bucket_record_function(void* bucket_data, hashcode key, dictionary_node* node);

#define COLLECTION_PROCESS_RETURNERROR  -1
#define COLLECTION_PROCESS_STOP          0
#define COLLECTION_PROCESS_NEXT          1
#define COLLECTION_PROCESS_DELETENODE    2

/**
 * Function type called by a dictionary_process_method to do whatever is required on a node.
 *
 * Mostly used for deletion in a cascade of dictionaries (what the database is)
 *
 * In case of deletion of the node, the function cannot process the dictionary_node pointed
 * by the next field (node->next).
 *
 * Returns a control code to the caller.
 *
 * @param[in] data an arbitrary data passed to the callee.
 * @param[in] node the node to be processed by the callee.
 *
 * @return COLLECTION_PROCESS_NEXT        if the next node must be proccessed.
 * @return COLLECTION_PROCESS_STOP        if the process MUST be stopped immediately.
 * @return COLLECTION_PROCESS_DELETENODE  if the node has been deleted and the process MUST be stopped immediately.
 * @return COLLECTION_PROCESS_RETURNERROR if an error occurred and the process MUST be stopped immediately.
 */

typedef ya_result dictionary_process_record_function(void* data, dictionary_node* node);

struct dictionary_vtbl;
typedef struct dictionary dictionary;


/**
 * @brief The dictionary descriptor.
 *
 * The dictionary descriptor.
 *
 */

struct dictionary
{

    union
    {
	btree btree_collection; /*  4  8 */
	htbt htbt_collection; /*  4  8 */
    } ct; /* Collection-type*/
    const struct dictionary_vtbl* vtbl; /*  4  8 */
    u32 count; /*  4  4 */
    u32 threshold; /*  4  4 */
}; /* 16 24 */

typedef struct dictionary_iterator dictionary_iterator;

/**
 * @brief The dictionary iterator.
 *
 * The dictionary iterator.
 *
 */

struct dictionary_iterator
{
    const struct dictionary_iterator_vtbl* vtbl;
    dictionary_node* sll;

    union
    {
	btree_iterator as_btree;
	htbt_iterator as_htbt;
    } ct;
};

/**
 * @brief Function type called to initialize a dictionary.
 *
 * Function type called to initialize a dictionary.
 *
 * @param[in] dico a pointer to the dictionary descriptor to initialize.
 *
 */

typedef void dictionary_init_method(dictionary* dico);

/**
 * @brief Function type called to destroy a dictionary
 *
 * Function type called to destroy a dictionary
 *
 * @param[in] dico a pointer to the dictionary descriptor
 * @param[in] destroy a pointer to a function called for each node of the dictionary in order to delete them.
 *
 */

typedef void dictionary_destroy_method(dictionary* dico, dictionary_destroy_record_function destroy);

/**
 * @brief Function type called to destroy a dictionary
 *
 * Function type called to destroy a dictionary
 *
 * @param[in] dico a pointer to the dictionary descriptor
 * @param[in] destroyex a pointer to a function called for each node of the dictionary in order to delete them.
 * @param[in] arg a pointer to an argument that will be passed to the destroyex function
 *
 */

typedef void dictionary_destroy_ex_method(dictionary* dico, dictionary_destroy_ex_record_function destroyex, void* arg);


/**
 * @brief Function type called to add a record to a dictionary
 *
 * Function type called to add a record to a dictionary
 *
 * @param[in] dico a pointer to the dictionary descriptor
 * @param[in] key the hashcode of the record that will be inserted
 * @param[in] record_match_data arbitrary data for the compare and create functions
 * @param[in] compare pointer to a function called to check for duplicates (same hashcode)
 * @param[in] create pointer to a function called to create the new record
 *
 * @return Returns a pointer to the newly created record, or NULL if an error occurred.
 *
 */

typedef dictionary_node* dictionary_add_method(dictionary* dico, hashcode key, const void* record_match_data, dictionary_data_record_compare_function compare, dictionary_data_record_create_function create);

/**
 * @brief Function type called to find a record in a dictionary
 *
 * Function type called to find a record in a dictionary
 *
 * @param[in] dico a pointer to the dictionary descriptor
 * @param[in] key the hashcode of the record
 * @param[in] record_match_data arbitrary data for the compare function
 * @param[in] compare pointer to a function called to check for duplicates (same hashcode)
 *
 * @return Returns a pointer to the record matching the search, or NULL if no record has been found
 *
 */

typedef dictionary_node* dictionary_find_method(const dictionary* dico, hashcode key, const void* record_match_data, dictionary_data_record_compare_function compare);

/**
 * @brief Function type called to find a record in a dictionary
 *
 * Function type called to find a record in a dictionary
 *
 * @param[in] dico a pointer to the dictionary descriptor
 * @param[in] key the hashcode of the record
 * @param[in] record_match_data arbitrary data for the compare function
 * @param[in] compare pointer to a function called to check for a match
 *
 * @return Returns a pointer to a pointer to the record matching the search, or NULL if no record has been found
 *
 */

typedef dictionary_node** dictionary_findp_method(const dictionary* dico, hashcode key, const void* record_match_data, dictionary_data_record_compare_function compare);

/**
 * @brief Function type called to remove a record from a dictionary
 *
 * Function type called to remove a record from a dictionary
 *
 * @param[in] dico a pointer to the dictionary descriptor
 * @param[in] key the hashcode of the record that will be inserted
 * @param[in] record_match_data arbitrary data for the compare function
 * @param[in] compare pointer to a function called to check for a match
 *
 * @return Returns a pointer to a pointer to the record matching the search, or NULL if no record has been found
 *
 */

typedef dictionary_node* dictionary_remove_method(dictionary* dico, hashcode key, void* record_match_data, dictionary_data_record_compare_function compare);

/**
 * @brief Function type called to process a record from a dictionary
 *
 * Function type called to process a record from a dictionary
 *
 * @param[in] dico a pointer to the dictionary descriptor
 * @param[in] key the hashcode of the record that will be inserted
 * @param[in] record_match_data arbitrary data for the compare function
 * @param[in] compare pointer to a function called to check for a match and do whatever operation on the record.
 *
 * @return COLLECTION_PROCESS_STOP        if the process succeeded
 * @return COLLECTION_PROCESS_DELETENODE  if the process succeeded and the node has been deleted
 * @return COLLECTION_PROCESS_RETURNERROR if an error occurred
 *
 */

typedef ya_result dictionary_process_method(dictionary* dico, hashcode key, void* record_match_data, dictionary_process_record_function compare);

/**
 * @brief Function type called to empty a dictionary
 *
 * Function type called to empty a dictionary.
 * This is a part of the dictionary's mutating feature.
 *
 * @param[in] dico a pointer to the dictionary descriptor
 * @param[in] bucket a pointer to an arbitrary data passed to the bucket_record function (ie: the new dictionary)
 * @param[in] bucket_record pointer to a function called to take care of the removed record. (ie: add it to another dictionary)
 *
 */

typedef void dictionary_empties_method(dictionary* dico, void* bucket, dictionary_bucket_record_function bucket_record);

/**
 * @brief Function type called to fill a dictionary
 *
 * Function type called to fill a dictionary
 * This is a part of the dictionary's mutating feature.
 *
 * Note there is no MATCH callback because collisions cannot occur.
 * (It's used to transfer node from a dictionary to another ... so ...)
 *
 * @param[in] dico a pointer to the dictionary descriptor
 * @param[in] key the hashcode of the node that needs to be added into the dictionary
 * @param[in] node the node that needs to be added into the dictionary
 *
 */

typedef void dictionary_fills_method(dictionary* dico, hashcode key, dictionary_node* node);

/**
 * @brief Function type called to initialize a dictionary iterator
 *
 * Function type called to initialize a dictionary iterator
 *
 * @param[in] dico a pointer to the dictionary descriptor
 * @param[in] iter a pointer to the dictionary iterator
 */

typedef void dictionary_iterator_init_method(const dictionary* dico, dictionary_iterator* iter);

/**
 * @brief Function type called check if the iterator still has items to return
 *
 * Function type called check if the iterator still has items to return
 *
 * @param[in] iter a pointer to the dictionary iterator
 *
 * @return TRUE if calling the dictionary_iterator_next_method will return an item, FALSE otherwise
 */

typedef bool dictionary_iterator_hasnext_method(dictionary_iterator* dico);

/**
 * @brief Function type called to get the next item of the iterator
 *
 * Function type called to get the next item of the iterator
 * The caller should check for item availability by calling the "hasnext" method.
 *
 * @param[in] iter a pointer to the dictionary iterator
 *
 * @return A pointer to a pointer to the next item.
 */

typedef void** dictionary_iterator_next_method(dictionary_iterator* dico);

/**
 * @brief Function type called to initialize a dictionary iterator from a starting point
 *
 * Function type called to initialize a dictionary iterator
 * If the key has not been found the previous or next key is used instead (whatever has been hit last)
 *
 * @param[in] dico a pointer to the dictionary descriptor
 * @param[in] iter a pointer to the dictionary iterator
 * @param[in] the key to start from.
 */


//typedef void dictionary_iterator_init_from_method(const dictionary* dico, dictionary_iterator* iter, hashcode key);
typedef void dictionary_iterator_init_from_method(const dictionary* dico, dictionary_iterator* iter, const u8 *label);

typedef const char * const dictionary_class;

/**
 * @brief The dictionary virtual table
 *
 * The dictionary virtual table
 */

struct dictionary_vtbl
{
    /*dictionary_init_method* dictionary_init_call;*/
    dictionary_destroy_method * const dictionary_destroy_call;
    dictionary_add_method * const dictionary_add_call;
    dictionary_find_method * const dictionary_find_call;
    dictionary_findp_method * const dictionary_findp_call;
    dictionary_remove_method * const dictionary_remove_call;
    dictionary_process_method * const dictionary_process_call;

    dictionary_destroy_ex_method * const dictionary_destroy_ex_call;

    dictionary_iterator_init_method * const dictionary_iterator_init_call;
    
    dictionary_iterator_init_from_method * const dictionary_iterator_init_from_call;

    dictionary_empties_method * const dictionary_empties_call;
    dictionary_fills_method * const dictionary_fills_call;

    dictionary_class __class__;
};

/**
 * @brief The dictionary_iterator virtual table
 *
 * The dictionary virtual table
 */


struct dictionary_iterator_vtbl
{
    dictionary_iterator_hasnext_method * const dictionary_iterator_hasnext_call;
    dictionary_iterator_next_method * const dictionary_iterator_next_call;
};

/**
 * @brief Used to initialize a dictionary
 *
 * Used to initialize a dictionary.
 * This will set the dictionary's initial type.
 *
 * @param[in] dico a pointer to the dictionary descriptor
 *
 */

void dictionary_init(dictionary* dico);

/**
 * @brief Used to mutate a dictionary
 *
 * Used to mutate a dictionary
 * This will change the dictionary's type to the one adapted for its current
 * item count.
 * If dictionary_should_mutate(dico) is FALSE, then this function does nothing.
 *
 * @param[in] dico a pointer to the dictionary descriptor
 *
 */

void dictionary_mutate(dictionary* dico);

/**
 * 
 * Initialises the iterator so that it has no next items to return
 * 
 * @param iter
 */

void dictionary_empty_iterator_init(dictionary_iterator* iter);

/**
 * @brief Checks if a dictionary should be processed by dictionary_mutate
 *
 * Checks if a dictionary should be processed by dictionary_mutate
 *
 * @return TRUE if and only if the dictionary should be processed by dictionary_mutate
 */

#define           dictionary_should_mutate(dico_) ((dico_)->count>(dico_)->threshold)

/** @brief helper macro */
#define dictionary_destroy(dico_, destroy_) (dico_)->vtbl->dictionary_destroy_call((dico_), (destroy_))
/** @brief helper macro */
#define dictionary_destroy_ex(dico_, destroy_, arg_) (dico_)->vtbl->dictionary_destroy_ex_call((dico_), (destroy_), (arg_))
/** @brief helper macro */
#define dictionary_add(dico_, key_, record_match_data_, compare_, create_) (dico_)->vtbl->dictionary_add_call((dico_), (key_), (record_match_data_), (compare_), (create_))
/** @brief helper macro */
#define dictionary_find(dico_, key_, record_match_data_, compare_) (dico_)->vtbl->dictionary_find_call((dico_), (key_), (record_match_data_), (compare_))
/** @brief helper macro */
#define dictionary_findp(dico_, key_, record_match_data_, compare_) (dico_)->vtbl->dictionary_findp_call((dico_), (key_), (record_match_data_), (compare_))
/** @brief helper macro */
#define dictionary_remove(dico_, key_, record_match_data_, compare_) (dico_)->vtbl->dictionary_remove_call((dico_), (key_), (record_match_data_), (compare_))
/** @brief helper macro */
#define dictionary_process(dico_, key_, record_match_data_, compare_) (dico_)->vtbl->dictionary_process_call((dico_), (key_), (record_match_data_), (compare_))
/** @brief helper macro */
#define dictionary_iterator_init(dico_, iter_) (dico_)->vtbl->dictionary_iterator_init_call((dico_), (iter_))
/** @brief helper macro */
#define dictionary_iterator_init_from(dico_, iter_, key_) (dico_)->vtbl->dictionary_iterator_init_from_call((dico_), (iter_), (key_))
/** @brief helper macro */
#define dictionary_iterator_hasnext(iter_) (iter_)->vtbl->dictionary_iterator_hasnext_call((iter_))
/** @brief helper macro */
#define dictionary_iterator_next(iter_) (iter_)->vtbl->dictionary_iterator_next_call((iter_))
/** @brief helper macro */
#define dictionary_empties(dico_,bucket_data_,callback_) (dico_)->vtbl->dictionary_empties_call((dico_),(bucket_data_),(callback_))
/** @brief helper macro */
#define dictionary_fills(dico_,key_,node_) (dico_)->vtbl->dictionary_fills_call((dico_),(key_),(node_))
/** @brief helper macro*/
#define dictionary_size(dico_) ((dico_)->count)

/** @brief Checks if a dictionary is not empty
 *
 *  Checks if a dictionary is not empty
 *
 * @return TRUE if and only if the dictionary is not empty
 */

#define dictionary_notempty(dico_) ((dico_)->count!=0)

/** @brief Checks if a dictionary is empty
 *
 *  Checks if a dictionary is empty
 *
 * @return TRUE if and only if the dictionary is empty
 */

#define dictionary_isempty(dico_) ((dico_)->count==0)

#ifdef	__cplusplus
}
#endif

#endif	/* _dictionary_H */

/** @} */
