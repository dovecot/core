/* GLIB - Library of useful routines for C programming
 * Copyright (C) 1995-1997  Peter Mattis, Spencer Kimball and Josh MacDonald
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	 See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

/*
 * Modified by the GLib Team and others 1997-1999.  See the AUTHORS
 * file for a list of people on the GLib Team.  See the ChangeLog
 * files for a list of changes.  These files are distributed with
 * GLib at ftp://ftp.gtk.org/pub/gtk/. 
 */

/* several modifications Copyright (C) 2002 by Timo Sirainen */

#include "lib.h"
#include "hash.h"
#include "primes.h"

#include <ctype.h>

#define HASH_TABLE_MIN_SIZE 11
#define HASH_TABLE_MAX_SIZE 13845163

struct hash_node {
	void *key;
	void *value;

	int destroyed;
	struct hash_node *next;
};

struct hash_table {
	pool_t pool;

	unsigned int size;
	unsigned int nodes_count, nodes_destroyed;
	int frozen;
	struct hash_node **nodes;

	HashFunc hash_func;
	HashCompareFunc key_compare_func;
};

static void hash_cleanup(struct hash_table *table);
static int hash_resize(struct hash_table *table);

static int foreach_stop;

static unsigned int direct_hash(const void *p)
{
	/* NOTE: may truncate the value, but that doesn't matter. */
	return POINTER_CAST_TO(p, unsigned int);
}

static struct hash_node *hash_node_create(pool_t pool, void *key, void *value)
{
	struct hash_node *node;

        node = p_new(pool, struct hash_node, 1);
	node->key = key;
	node->value = value;

	return node;
}

static void hash_nodes_destroy(struct hash_table *table, struct hash_node *node)
{
	struct hash_node *next;

	while (node != NULL) {
		next = node->next;
                p_free(table->pool, node);
                node = next;
	}
}

struct hash_table *hash_create(pool_t node_pool, pool_t table_pool,
			       unsigned int initial_size, HashFunc hash_func,
			       HashCompareFunc key_compare_func)
{
	struct hash_table *table;

        i_assert(pool != NULL);

	table = p_new(pool, struct hash_table, 1);
        table->node_pool = node_pool;
        table->table_pool = table_pool;
	table->size = CLAMP(primes_closest(initial_size),
			    HASH_TABLE_MIN_SIZE,
			    HASH_TABLE_MAX_SIZE);

	table->hash_func = hash_func != NULL ? hash_func : direct_hash;
	table->key_compare_func = key_compare_func;
	table->nodes = p_new(pool, struct hash_node *, table->size);

	return table;
}

void hash_destroy(struct hash_table *table)
{
	unsigned int i;

	if (table == NULL)
                return;

	for (i = 0; i < table->size; i++)
		hash_nodes_destroy(table, table->nodes[i]);

	p_free(table->pool, table->nodes);
	p_free(table->pool, table);
}

void hash_clear(struct hash_table *table)
{
	unsigned int i;

	i_assert(table != NULL);

	for (i = 0; i < table->size; i++) {
		hash_nodes_destroy(table, table->nodes[i]);
		table->nodes[i] = NULL;
	}
}

static inline struct hash_node **
hash_lookup_node(struct hash_table *table, const void *key)
{
	struct hash_node **node;

	node = &table->nodes[table->hash_func(key) % table->size];

	/* Hash table lookup needs to be fast.
	   We therefore remove the extra conditional of testing
	   whether to call the key_compare_func or not from
	   the inner loop. */
	if (table->key_compare_func) {
		while (*node != NULL) {
                        if (!(*node)->destroyed &&
			    table->key_compare_func((*node)->key, key) == 0)
                                break;
			node = &(*node)->next;
		}
	} else {
		while (*node != NULL && (*node)->key != key)
			node = &(*node)->next;
	}

	return node;
}

void *hash_lookup(struct hash_table *table, const void *key)
{
	struct hash_node *node;

	i_assert(table != NULL);

	node = *hash_lookup_node(table, key);
	return node != NULL && !node->destroyed ? node->value : NULL;
}

int hash_lookup_full(struct hash_table *table, const void *lookup_key,
		     void **orig_key, void **value)
{
	struct hash_node *node;

	i_assert(table != NULL);

	node = *hash_lookup_node(table, lookup_key);
	if (node == NULL || node->destroyed)
		return FALSE;

	if (orig_key != NULL)
		*orig_key = node->key;
	if (value != NULL)
		*value = node->value;
	return TRUE;
}

static void hash_insert_full(struct hash_table *table, void *key, void *value,
			     int replace_key)
{
	struct hash_node **node;

	i_assert(table != NULL);

	node = hash_lookup_node(table, key);
	if (*node == NULL) {
		*node = hash_node_create(table->pool, key, value);

		table->nodes_count++;
		if (!table->frozen)
			hash_resize(table);
	} else {
		if (replace_key || (*node)->destroyed) {
			(*node)->key = key;
			(*node)->destroyed = FALSE;
		}

		(*node)->value = value;
	}
}

void hash_insert(struct hash_table *table, void *key, void *value)
{
	hash_insert_full(table, key, value, TRUE);
}

void hash_update(struct hash_table *table, void *key, void *value)
{
	hash_insert_full(table, key, value, FALSE);
}

void hash_remove(struct hash_table *table, const void *key)
{
	struct hash_node **node, *old_node;

	i_assert(table != NULL);

	node = hash_lookup_node(table, key);
	if (*node != NULL && !(*node)->destroyed) {
		table->nodes_count--;

		if (table->frozen) {
			(*node)->destroyed = TRUE;
                        table->nodes_destroyed++;
		} else {
			old_node = *node;
			*node = old_node->next;
			p_free(table->pool, old_node);

			hash_resize(table);
		}
	}
}

void hash_freeze(struct hash_table *table)
{
	i_assert(table != NULL);

	table->frozen++;
}

void hash_thaw(struct hash_table *table)
{
	i_assert(table != NULL);
	i_assert(table->frozen > 0);

	if (--table->frozen == 0)
                hash_cleanup(table);
}

void hash_foreach(struct hash_table *table, HashForeachFunc func, void *context)
{
	struct hash_node *node;
	unsigned int i;

	i_assert(table != NULL);
	i_assert(func != NULL);

	hash_freeze(table);

        foreach_stop = FALSE;
	for (i = 0; i < table->size; i++) {
		for (node = table->nodes[i]; node; node = node->next) {
			if (!node->destroyed) {
				func(node->key, node->value, context);

				if (foreach_stop) {
					foreach_stop = FALSE;
					hash_thaw(table);
                                        return;
				}
			}
		}
	}
        hash_thaw(table);
}

void hash_foreach_stop(void)
{
        foreach_stop = TRUE;
}

/* Returns the number of elements contained in the hash table. */
unsigned int hash_size(struct hash_table *table)
{
	i_assert(table != NULL);

	return table->nodes_count;
}

static int hash_resize(struct hash_table *table)
{
        HashFunc hash_func;
	struct hash_node *node, *next, **new_nodes;
	float nodes_per_list;
	unsigned int hash_val, new_size, i;

	nodes_per_list = (float) table->nodes_count / (float) table->size;
	if ((nodes_per_list > 0.3 || table->size <= HASH_TABLE_MIN_SIZE) &&
	    (nodes_per_list < 3.0 || table->size >= HASH_TABLE_MAX_SIZE))
		return FALSE;

	new_size = CLAMP(primes_closest(table->nodes_count+1),
			 HASH_TABLE_MIN_SIZE,
			 HASH_TABLE_MAX_SIZE);

	new_nodes = p_new(table->pool, struct hash_node *, new_size);

        hash_func = table->hash_func;
	for (i = 0; i < table->size; i++) {
		for (node = table->nodes[i]; node != NULL; node = next) {
			next = node->next;

			if (node->destroyed) {
                                p_free(table->pool, node);
			} else {
				hash_val = hash_func(node->key) % new_size;

				node->next = new_nodes[hash_val];
				new_nodes[hash_val] = node;
			}
		}
	}

	p_free(table->pool, table->nodes);
	table->nodes = new_nodes;
	table->size = new_size;
	table->nodes_destroyed = 0;
        return TRUE;
}

static void hash_cleanup(struct hash_table *table)
{
	struct hash_node **node, **next, *old_node;
        unsigned int i;

	if (hash_resize(table))
		return;

	if (table->nodes_destroyed == 0)
                return;

        /* find the destroyed nodes from hash table and remove them */
	for (i = 0; i < table->size; i++) {
		for (node = &table->nodes[i]; *node != NULL; node = next) {
			next = &(*node)->next;

			if ((*node)->destroyed) {
                                old_node = *node;
				*node = *next;
				p_free(table->pool, old_node);

				/* next points to free'd memory area now,
				   fix it */
				next = node;

				if (--table->nodes_destroyed == 0)
                                        return;
			}
		}
	}
}

/* a char* hash function from ASU -- from glib */
unsigned int str_hash(const void *p)
{
        const unsigned char *s = p;
	unsigned int g, h = 0;

	while (*s != '\0') {
		h = (h << 4) + *s;
		if ((g = h & 0xf0000000UL)) {
			h = h ^ (g >> 24);
			h = h ^ g;
		}
		s++;
	}

	return h;
}

/* a char* hash function from ASU -- from glib */
unsigned int strcase_hash(const void *p)
{
        const unsigned char *s = p;
	unsigned int g, h = 0;

	while (*s != '\0') {
		h = (h << 4) + i_toupper(*s);
		if ((g = h & 0xf0000000UL)) {
			h = h ^ (g >> 24);
			h = h ^ g;
		}
		s++;
	}

	return h;
}
