/*
    Copyright (c) 2003 Timo Sirainen

    Permission is hereby granted, free of charge, to any person obtaining
    a copy of this software and associated documentation files (the
    "Software"), to deal in the Software without restriction, including
    without limitation the rights to use, copy, modify, merge, publish,
    distribute, sublicense, and/or sell copies of the Software, and to
    permit persons to whom the Software is furnished to do so, subject to
    the following conditions:

    The above copyright notice and this permission notice shall be
    included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
    OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
    MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
    IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
    CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
    TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
    SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

/* @UNSAFE: whole file */

#include "lib.h"
#include "hash.h"
#include "primes.h"

#include <ctype.h>

#define HASH_TABLE_MIN_SIZE 109
#define COLLISIONS_MIN_SIZE 37

struct hash_node {
	void *key;
	void *value;
};

struct collision_node {
	struct hash_node node;
	struct collision_node *next;
};

struct hash_table {
	pool_t table_pool, node_pool;

	int frozen;
	size_t nodes_count, removed_count;
#ifdef DEBUG
	size_t collisions_count;
#endif

	size_t size;
	struct hash_node *nodes;

	size_t collisions_size;
	struct collision_node *collisions;

	struct collision_node *free_cnodes;

	HashFunc hash_func;
	HashCompareFunc key_compare_func;
};

static int hash_resize(struct hash_table *table);

static int foreach_stop;

static int direct_cmp(const void *p1, const void *p2)
{
	return p1 == p2 ? 0 : 1;
}

static unsigned int direct_hash(const void *p)
{
	/* NOTE: may truncate the value, but that doesn't matter. */
	return POINTER_CAST_TO(p, unsigned int);
}

struct hash_table *hash_create(pool_t table_pool, pool_t node_pool,
			       size_t initial_size, HashFunc hash_func,
			       HashCompareFunc key_compare_func)
{
	struct hash_table *table;

	table = p_new(node_pool, struct hash_table, 1);
        table->table_pool = table_pool;
        table->node_pool = node_pool;
	table->size = I_MAX(primes_closest(initial_size),
			    HASH_TABLE_MIN_SIZE);

	table->hash_func = hash_func != NULL ? hash_func : direct_hash;
	table->key_compare_func = key_compare_func == NULL ?
		direct_cmp : key_compare_func;
	table->nodes = p_new(table_pool, struct hash_node, table->size);
	table->collisions_size = I_MAX(table->size / 10, COLLISIONS_MIN_SIZE);
	table->collisions = p_new(table_pool, struct collision_node,
				  table->collisions_size);

	return table;
}

static void free_cnode(struct hash_table *table, struct collision_node *cnode)
{
	if (!table->node_pool->alloconly_pool)
		p_free(table->node_pool, cnode);
	else {
		cnode->next = table->free_cnodes;
		table->free_cnodes = cnode;
	}
}

static void destroy_collision(struct hash_table *table,
			      struct collision_node *cnode)
{
	struct collision_node *next;

	while (cnode != NULL) {
		next = cnode->next;
		p_free(table->node_pool, cnode);
		cnode = next;
	}
}

static void hash_destroy_collision_nodes(struct hash_table *table)
{
	size_t i;

	for (i = 0; i < table->collisions_size; i++) {
		if (table->collisions[i].next != NULL)
			destroy_collision(table, table->collisions[i].next);
	}
}

void hash_destroy(struct hash_table *table)
{
	if (!table->node_pool->alloconly_pool) {
		hash_destroy_collision_nodes(table);
		destroy_collision(table, table->free_cnodes);
	}

	p_free(table->table_pool, table->nodes);
	p_free(table->table_pool, table->collisions);
	p_free(table->node_pool, table);
}

void hash_clear(struct hash_table *table)
{
	if (!table->node_pool->alloconly_pool)
		hash_destroy_collision_nodes(table);

	memset(table->nodes, 0, sizeof(struct hash_node) * table->size);
	memset(table->collisions, 0,
	       sizeof(struct collision_node) * table->collisions_size);

	table->nodes_count = 0;
	table->removed_count = 0;
#ifdef DEBUG
	table->collisions_count = 0;
#endif
}

static struct hash_node *
hash_lookup_collision(struct hash_table *table,
		      const void *key, unsigned int hash)
{
	struct collision_node *cnode;

	cnode = &table->collisions[hash % table->collisions_size];
	do {
		if (cnode->node.key != NULL) {
			if (table->key_compare_func(cnode->node.key, key) == 0)
				return &cnode->node;
		}
		cnode = cnode->next;
	} while (cnode != NULL);

	return NULL;
}

static struct hash_node *
hash_lookup_node(struct hash_table *table, const void *key, unsigned int hash)
{
	struct hash_node *node;

	node = &table->nodes[hash % table->size];

	if (node->key == NULL) {
		if (table->removed_count == 0)
			return NULL;
	} else {
		if (table->key_compare_func(node->key, key) == 0)
			return node;
	}

	return hash_lookup_collision(table, key, hash);
}

void *hash_lookup(struct hash_table *table, const void *key)
{
	struct hash_node *node;

	node = hash_lookup_node(table, key, table->hash_func(key));
	return node != NULL ? node->value : NULL;
}

int hash_lookup_full(struct hash_table *table, const void *lookup_key,
		     void **orig_key, void **value)
{
	struct hash_node *node;

	node = hash_lookup_node(table, lookup_key,
				table->hash_func(lookup_key));
	if (node == NULL)
		return FALSE;

	if (orig_key != NULL)
		*orig_key = node->key;
	if (value != NULL)
		*value = node->value;
	return TRUE;
}

static struct hash_node *
hash_insert_node(struct hash_table *table, void *key, void *value,
		 int check_existing)
{
	struct hash_node *node;
	struct collision_node *cnode, *prev;
	unsigned int hash;

	i_assert(key != NULL);

	hash = table->hash_func(key);

	if (check_existing && table->removed_count > 0) {
		/* there may be holes, have to check everything */
		node = hash_lookup_node(table, key, hash);
		if (node != NULL)
			return node;

                check_existing = FALSE;
	}

	/* a) primary hash */
	node = &table->nodes[hash % table->size];
	if (node->key == NULL) {
		table->nodes_count++;

		node->key = key;
		node->value = value;
		return node;
	}

	if (check_existing) {
		if (table->key_compare_func(node->key, key) == 0)
			return node;
	}

	/* b) collisions list */
	prev = NULL;
	cnode = &table->collisions[hash % table->collisions_size];

	do {
		if (cnode->node.key == NULL)
			break;

		if (check_existing) {
			if (table->key_compare_func(cnode->node.key, key) == 0)
				return node;
		}

		prev = cnode;
		cnode = cnode->next;
	} while (cnode != NULL);

	if (cnode == NULL) {
		if (table->frozen == 0 && hash_resize(table)) {
			/* resized table, try again */
			return hash_insert_node(table, key, value, FALSE);
		}

		if (table->free_cnodes == NULL) {
			cnode = p_new(table->node_pool,
				      struct collision_node, 1);
		} else {
			cnode = table->free_cnodes;
			table->free_cnodes = cnode->next;
			cnode->next = NULL;
		}
		prev->next = cnode;
	}

	cnode->node.key = key;
	cnode->node.value = value;;

#ifdef DEBUG
	table->collisions_count++;
#endif
	table->nodes_count++;
	return &cnode->node;
}

void hash_insert(struct hash_table *table, void *key, void *value)
{
	struct hash_node *node;

	node = hash_insert_node(table, key, value, TRUE);
	node->key = key;
}

void hash_update(struct hash_table *table, void *key, void *value)
{
	(void)hash_insert_node(table, key, value, TRUE);
}

static void hash_compress(struct hash_table *table,
			  unsigned int collision_idx,
			  unsigned int hash)
{
	struct collision_node *croot, *cnode, *next;
	struct hash_node *node;

	/* remove deleted nodes from the list */
	croot = cnode = &table->collisions[collision_idx];
	while (cnode->next != NULL) {
		next = cnode->next;

		if (next->node.key == NULL) {
			cnode->next = next->next;
			free_cnode(table, next);
#ifdef DEBUG
			table->collisions_count--;
#endif
		}
	}

	do {
		/* if root is marked as deleted, replace it with first node
		   from list */
		if (croot->node.key == NULL) {
			next = croot->next;
			if (next == NULL) {
				/* no collisions left - nothing to do */
				return;
			}

			memcpy(&croot->node, &next->node, sizeof(croot->node));
			croot->next = next->next;
			free_cnode(table, next);
#ifdef DEBUG
			table->collisions_count--;
#endif
		}

		/* see if node in primary table was deleted */
		if (hash == 0)
			hash = table->hash_func(croot->node.key);
		node = &table->nodes[hash % table->size];
		if (node->key == NULL) {
			memcpy(node, &croot->node, sizeof(*node));
			croot->node.key = NULL;
#ifdef DEBUG
			table->collisions_count--;
#endif
		}
	} while (croot->node.key == NULL);
}

static void hash_compress_collisions(struct hash_table *table)
{
	struct collision_node *cnode;
	size_t i;

	for (i = 0; i < table->collisions_size; i++) {
		cnode = &table->collisions[i];

		if (cnode->node.key != NULL || cnode->next != NULL)
			hash_compress(table, i, 0);
	}
}

void hash_remove(struct hash_table *table, const void *key)
{
	struct hash_node *node;
	unsigned int hash;

	hash = table->hash_func(key);

	node = hash_lookup_node(table, key, hash);
	node->key = NULL;

	if (table->frozen != 0)
		table->removed_count++;
	else if (!hash_resize(table))
		hash_compress(table, hash % table->collisions_size, hash);
}

size_t hash_size(struct hash_table *table)
{
	return table->nodes_count;
}

void hash_foreach(struct hash_table *table, HashForeachFunc func, void *context)
{
	struct hash_node *node;
	struct collision_node *cnode;
	size_t i;

	hash_freeze(table);

	foreach_stop = FALSE;

	for (i = 0; i < table->size; i++) {
		node = &table->nodes[i];

		if (node->key != NULL) {
			func(node->key, node->value, context);
			if (foreach_stop) {
				table->frozen--;
				return;
			}
		}
	}

	if (!foreach_stop) {
		for (i = 0; i < table->collisions_size; i++) {
			cnode = &table->collisions[i];

			do {
				if (cnode->node.key != NULL) {
					func(cnode->node.key, cnode->node.value,
					     context);
					if (foreach_stop) {
						table->frozen--;
						return;
					}
				}
				cnode = cnode->next;
			} while (cnode != NULL);
		}
	}

	hash_thaw(table);
}

void hash_foreach_stop(void)
{
        foreach_stop = TRUE;
}

void hash_freeze(struct hash_table *table)
{
	table->frozen++;
}

void hash_thaw(struct hash_table *table)
{
	i_assert(table->frozen > 0);
	if (--table->frozen > 0)
		return;

	if (table->removed_count > 0) {
		if (!hash_resize(table))
			hash_compress_collisions(table);
	}
}

static int hash_resize(struct hash_table *table)
{
	struct hash_node *old_nodes;
	struct collision_node *old_cnodes, *cnode;
	size_t old_size, old_csize, i;

	float nodes_per_list;

        nodes_per_list = (float) table->nodes_count / (float) table->size;
        if ((nodes_per_list > 0.3 || table->size <= HASH_TABLE_MIN_SIZE) &&
            (nodes_per_list < 2.0))
                return FALSE;

	/* recreate primary table */
	old_size = table->size;
	old_nodes = table->nodes;

	table->size = I_MAX(primes_closest(table->nodes_count+1),
			    HASH_TABLE_MIN_SIZE);
	table->nodes = p_new(table->table_pool, struct hash_node, table->size);

	/* recreate collisions table */
	old_csize = table->collisions_size;
	old_cnodes = table->collisions;

	table->collisions_size = I_MAX(table->size / 10, COLLISIONS_MIN_SIZE);
	table->collisions = p_new(table->table_pool, struct collision_node,
				  table->collisions_size);

	table->nodes_count = 0;
	table->removed_count = 0;
#ifdef DEBUG
	table->collisions_count = 0;
#endif

	table->frozen++;

	/* move the data */
	for (i = 0; i < old_size; i++) {
		if (old_nodes[i].key != NULL) {
			hash_insert_node(table, old_nodes[i].key,
					 old_nodes[i].value, FALSE);
		}
	}

	for (i = 0; i < old_csize; i++) {
		cnode = &old_cnodes[i];

		do {
			if (cnode->node.key != NULL) {
				hash_insert_node(table, cnode->node.key,
						 cnode->node.value, FALSE);
			}
			cnode = cnode->next;
		} while (cnode != NULL);
	}

	table->frozen--;

	p_free(table->table_pool, old_nodes);
	p_free(table->table_pool, old_cnodes);
	return TRUE;
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
