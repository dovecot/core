/* Copyright (c) 2002-2011 Dovecot authors, see the included COPYING file */

/* @UNSAFE: whole file */

#include "lib.h"
#include "hash.h"
#include "primes.h"

#include <ctype.h>

#define HASH_TABLE_MIN_SIZE 131

struct hash_node {
	struct hash_node *next;
	void *key;
	void *value;
};

struct hash_table {
	pool_t table_pool, node_pool;

	int frozen;
	unsigned int initial_size, nodes_count, removed_count;

	unsigned int size;
	struct hash_node *nodes;
	struct hash_node *free_nodes;

	hash_callback_t *hash_cb;
	hash_cmp_callback_t *key_compare_cb;
};

struct hash_iterate_context {
	struct hash_table *table;
	struct hash_node *next;
	unsigned int pos;
};

static bool hash_table_resize(struct hash_table *table, bool grow);

static int direct_cmp(const void *p1, const void *p2)
{
	return p1 == p2 ? 0 : 1;
}

static unsigned int direct_hash(const void *p)
{
	/* NOTE: may truncate the value, but that doesn't matter. */
	return POINTER_CAST_TO(p, unsigned int);
}

struct hash_table *
hash_table_create(pool_t table_pool, pool_t node_pool, unsigned int initial_size,
		  hash_callback_t *hash_cb, hash_cmp_callback_t *key_compare_cb)
{
	struct hash_table *table;

	table = p_new(table_pool, struct hash_table, 1);
        table->table_pool = table_pool;
	table->node_pool = node_pool;
	table->initial_size =
		I_MAX(primes_closest(initial_size), HASH_TABLE_MIN_SIZE);

	table->hash_cb = hash_cb != NULL ? hash_cb : direct_hash;
	table->key_compare_cb = key_compare_cb == NULL ?
		direct_cmp : key_compare_cb;

	table->size = table->initial_size;
	table->nodes = p_new(table_pool, struct hash_node, table->size);
	return table;
}

static void free_node(struct hash_table *table, struct hash_node *node)
{
	if (!table->node_pool->alloconly_pool)
		p_free(table->node_pool, node);
	else {
		node->next = table->free_nodes;
		table->free_nodes = node;
	}
}

static void destroy_node_list(struct hash_table *table, struct hash_node *node)
{
	struct hash_node *next;

	while (node != NULL) {
		next = node->next;
		p_free(table->node_pool, node);
		node = next;
	}
}

static void hash_table_destroy_nodes(struct hash_table *table)
{
	unsigned int i;

	for (i = 0; i < table->size; i++) {
		if (table->nodes[i].next != NULL)
			destroy_node_list(table, table->nodes[i].next);
	}
}

void hash_table_destroy(struct hash_table **_table)
{
	struct hash_table *table = *_table;

	*_table = NULL;

	if (!table->node_pool->alloconly_pool) {
		hash_table_destroy_nodes(table);
		destroy_node_list(table, table->free_nodes);
	}

	p_free(table->table_pool, table->nodes);
	p_free(table->table_pool, table);
}

void hash_table_clear(struct hash_table *table, bool free_nodes)
{
	if (!table->node_pool->alloconly_pool)
		hash_table_destroy_nodes(table);

	if (free_nodes) {
		if (!table->node_pool->alloconly_pool)
			destroy_node_list(table, table->free_nodes);
                table->free_nodes = NULL;
	}

	memset(table->nodes, 0, sizeof(struct hash_node) * table->size);

	table->nodes_count = 0;
	table->removed_count = 0;
}

static struct hash_node *
hash_table_lookup_node(const struct hash_table *table,
		       const void *key, unsigned int hash)
{
	struct hash_node *node;

	node = &table->nodes[hash % table->size];

	do {
		if (node->key != NULL) {
			if (table->key_compare_cb(node->key, key) == 0)
				return node;
		}
		node = node->next;
	} while (node != NULL);

	return NULL;
}

void *hash_table_lookup(const struct hash_table *table, const void *key)
{
	struct hash_node *node;

	node = hash_table_lookup_node(table, key, table->hash_cb(key));
	return node != NULL ? node->value : NULL;
}

bool hash_table_lookup_full(const struct hash_table *table,
			    const void *lookup_key,
			    void **orig_key, void **value)
{
	struct hash_node *node;

	node = hash_table_lookup_node(table, lookup_key,
				      table->hash_cb(lookup_key));
	if (node == NULL)
		return FALSE;

	if (orig_key != NULL)
		*orig_key = node->key;
	if (value != NULL)
		*value = node->value;
	return TRUE;
}

static struct hash_node *
hash_table_insert_node(struct hash_table *table, void *key, void *value,
		       bool check_existing)
{
	struct hash_node *node, *prev;
	unsigned int hash;

	i_assert(key != NULL);

	hash = table->hash_cb(key);

	if (check_existing && table->removed_count > 0) {
		/* there may be holes, have to check everything */
		node = hash_table_lookup_node(table, key, hash);
		if (node != NULL) {
			node->value = value;
			return node;
		}

                check_existing = FALSE;
	}

	/* a) primary node */
	node = &table->nodes[hash % table->size];
	if (node->key == NULL) {
		table->nodes_count++;

		node->key = key;
		node->value = value;
		return node;
	}

	if (check_existing) {
		if (table->key_compare_cb(node->key, key) == 0) {
			node->value = value;
			return node;
		}
	}

	/* b) collisions list */
	prev = node; node = node->next;
	while (node != NULL) {
		if (node->key == NULL)
			break;

		if (check_existing) {
			if (table->key_compare_cb(node->key, key) == 0) {
				node->value = value;
				return node;
			}
		}

		prev = node;
		node = node->next;
	}

	if (node == NULL) {
		if (table->frozen == 0 && hash_table_resize(table, TRUE)) {
			/* resized table, try again */
			return hash_table_insert_node(table, key, value, FALSE);
		}

		if (table->free_nodes == NULL)
			node = p_new(table->node_pool, struct hash_node, 1);
		else {
			node = table->free_nodes;
			table->free_nodes = node->next;
			node->next = NULL;
		}
		prev->next = node;
	}

	node->key = key;
	node->value = value;

	table->nodes_count++;
	return node;
}

void hash_table_insert(struct hash_table *table, void *key, void *value)
{
	struct hash_node *node;

	node = hash_table_insert_node(table, key, value, TRUE);
	node->key = key;
}

void hash_table_update(struct hash_table *table, void *key, void *value)
{
	(void)hash_table_insert_node(table, key, value, TRUE);
}

static void
hash_table_compress(struct hash_table *table, struct hash_node *root)
{
	struct hash_node *node, *next;

	/* remove deleted nodes from the list */
	for (node = root; node->next != NULL; ) {
		next = node->next;

		if (next->key == NULL) {
			node->next = next->next;
			free_node(table, next);
		} else {
			node = next;
		}
	}

	/* update root */
	if (root->key == NULL && root->next != NULL) {
		next = root->next;
		*root = *next;
		free_node(table, next);
	}
}

static void hash_table_compress_removed(struct hash_table *table)
{
	unsigned int i;

	for (i = 0; i < table->size; i++)
		hash_table_compress(table, &table->nodes[i]);

        table->removed_count = 0;
}

void hash_table_remove(struct hash_table *table, const void *key)
{
	struct hash_node *node;
	unsigned int hash;

	hash = table->hash_cb(key);

	node = hash_table_lookup_node(table, key, hash);
	if (unlikely(node == NULL))
		i_panic("key not found from hash");

	node->key = NULL;
	table->nodes_count--;

	if (table->frozen != 0)
		table->removed_count++;
	else if (!hash_table_resize(table, FALSE))
		hash_table_compress(table, &table->nodes[hash % table->size]);
}

unsigned int hash_table_count(const struct hash_table *table)
{
	return table->nodes_count;
}

struct hash_iterate_context *hash_table_iterate_init(struct hash_table *table)
{
	struct hash_iterate_context *ctx;

	hash_table_freeze(table);

	ctx = i_new(struct hash_iterate_context, 1);
	ctx->table = table;
	ctx->next = &table->nodes[0];
	return ctx;
}

static struct hash_node *
hash_table_iterate_next(struct hash_iterate_context *ctx,
			struct hash_node *node)
{
	do {
		node = node->next;
		if (node == NULL) {
			if (++ctx->pos == ctx->table->size) {
				ctx->pos--;
				return NULL;
			}
			node = &ctx->table->nodes[ctx->pos];
		}
	} while (node->key == NULL);

	return node;
}

bool hash_table_iterate(struct hash_iterate_context *ctx,
			void **key_r, void **value_r)
{
	struct hash_node *node;

	node = ctx->next;
	if (node != NULL && node->key == NULL)
		node = hash_table_iterate_next(ctx, node);
	if (node == NULL) {
		*key_r = *value_r = NULL;
		return FALSE;
	}
	*key_r = node->key;
	*value_r = node->value;

	ctx->next = hash_table_iterate_next(ctx, node);
	return TRUE;
}

void hash_table_iterate_deinit(struct hash_iterate_context **_ctx)
{
	struct hash_iterate_context *ctx = *_ctx;

	*_ctx = NULL;
	hash_table_thaw(ctx->table);
	i_free(ctx);
}

void hash_table_freeze(struct hash_table *table)
{
	table->frozen++;
}

void hash_table_thaw(struct hash_table *table)
{
	i_assert(table->frozen > 0);

	if (--table->frozen > 0)
		return;

	if (table->removed_count > 0) {
		if (!hash_table_resize(table, FALSE))
			hash_table_compress_removed(table);
	}
}

static bool hash_table_resize(struct hash_table *table, bool grow)
{
	struct hash_node *old_nodes, *node, *next;
	unsigned int next_size, old_size, i;
	float nodes_per_list;

        nodes_per_list = (float) table->nodes_count / (float) table->size;
	if (nodes_per_list > 0.3 && nodes_per_list < 2.0)
		return FALSE;

	next_size = I_MAX(primes_closest(table->nodes_count+1),
			  table->initial_size);
	if (next_size == table->size)
		return FALSE;

	if (grow && table->size >= next_size)
		return FALSE;

	/* recreate primary table */
	old_size = table->size;
	old_nodes = table->nodes;

	table->size = I_MAX(next_size, HASH_TABLE_MIN_SIZE);
	table->nodes = p_new(table->table_pool, struct hash_node, table->size);

	table->nodes_count = 0;
	table->removed_count = 0;

	table->frozen++;

	/* move the data */
	for (i = 0; i < old_size; i++) {
		node = &old_nodes[i];
		if (node->key != NULL) {
			hash_table_insert_node(table, node->key,
					       node->value, FALSE);
		}

		for (node = node->next; node != NULL; node = next) {
			next = node->next;

			if (node->key != NULL) {
				hash_table_insert_node(table, node->key,
						       node->value, FALSE);
			}
			free_node(table, node);
		}
	}

	table->frozen--;

	p_free(table->table_pool, old_nodes);
	return TRUE;
}

void hash_table_copy(struct hash_table *dest, struct hash_table *src)
{
	struct hash_iterate_context *iter;
	void *key, *value;

	hash_table_freeze(dest);

	iter = hash_table_iterate_init(src);
	while (hash_table_iterate(iter, &key, &value))
		hash_table_insert(dest, key, value);
	hash_table_iterate_deinit(&iter);

	hash_table_thaw(dest);
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
