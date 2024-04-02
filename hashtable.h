/**
* Datakommunikation och Datornät HT22
* OU3
*
* File: hashtable.h
* Author: Hanna Littorin
* Username: c19hln
* Version: 1.0
**/

#ifndef __HASHTABLE_H
#define __HASHTABLE_H


#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <inttypes.h>
#include <string.h>

typedef struct ht ht;
typedef struct entry entry;
typedef void (*free_function)();

// key value set. 
typedef struct node {
    char *key;
    void *value;
    struct node *next; // pointer to next node in the chain.
} node_t;

struct ht {
    node_t **entries;   // buckets.
    int num_entries;    // number of buckets containing data in hash table.
    size_t length;      // number of items in hash table, including each node in the buckets.
    free_function value_free_function; // a function that is called when a nodes
                                            //value is to be freed
};

#define MAX_SIZE 256
#define KEY_LEN 12
#define hash_t uint8_t

/**
* Function:     ht_create()
* Description:  Initializes an empty hashtable.
* Input:        *value_free_function - a function aimed to free the value of the key-value set
*               or NULL if wanting to free outside of remove/destroy functions.
* Returns:      pointer to a struct ht
**/
ht* ht_create(free_function val_free_function);

/**
* Function:     ht_insert()
* Description:  inserts a key-value pair to the hash table. If the key already exists
*               in table, then the corresponding value of that key will be replaced
*               with the new value. NOTE - if no value_free_function was specified
*               at creation of the table, the old value needs to be freed outside
*               of this function.
*
* Input:        *ht - pointer to a struct ht
                *key - character pointer or uint8_t* array, 12 bytes, no null-termination.
                *value - the value to be inserted
* Returns:      pointer to the modified table
**/
ht* ht_insert(struct ht *ht, char *key, void *value);


/**
* Function:     ht_remove()
* Description:  removes the key-value set from the table. If a value_free_function
*               was specified at creation of the table the value will be freed.
*
* Input:        *ht - pointer to a struct ht
*               *key - character pointer or uint8_t* array, 12 bytes, no null-termination
*
* Returns:      pointer to the modified table.
**/
ht* ht_remove(struct ht *ht, char *key);


/**
* Function:     lookup()
* Description:  Get value with given key from table.
* Input:        *ht - pointer to a struct ht
*               *key - character pointer or uint8_t* array, 12 bytes, no null-termination
*
* Returns:      value associated with the given key, or NULL if not found.
**/
void *ht_lookup(struct ht *ht, char *key);

/**
* Function:     ht_destroy()
* Description:  frees memory allocated with the hashtable.
* Input:        *ht - pointer to a struct ht
*               free_func -  function aimed to free the value of the key-value set
* Returns:      Nothing.
**/
void ht_destroy(struct ht *ht);
/**
* Function:     get_num_entries()
* Description:
* Input:        *ht - pointer to a struct ht
*
* Returns:      the number of entries in the given hash table that contains data.
**/
int get_num_entries(struct ht *ht);
/**
* Function:     is_empty()
* Description:
* Input:        *ht - pointer to a struct ht
*
* Returns:      true if the table is empty, false otherwise.
**/
bool is_empty(struct ht *ht);
#endif
