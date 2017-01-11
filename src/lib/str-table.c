/* Copyright (c) 2014-2017 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "hash.h"
#include "str-table.h"

struct str_table {
	HASH_TABLE(char *, void *) hash;
};

struct str_table *str_table_init(void)
{
	struct str_table *table;

	table = i_new(struct str_table, 1);
	hash_table_create(&table->hash, default_pool, 0, str_hash, strcmp);
	return table;
}

void str_table_deinit(struct str_table **_table)
{
	struct str_table *table = *_table;
	struct hash_iterate_context *iter;
	char *key;
	void *value;

	*_table = NULL;

	iter = hash_table_iterate_init(table->hash);
	while (hash_table_iterate(iter, table->hash, &key, &value))
		i_free(key);
	hash_table_iterate_deinit(&iter);
	hash_table_destroy(&table->hash);
	i_free(table);
}

bool str_table_is_empty(struct str_table *table)
{
	return hash_table_count(table->hash) == 0;
}

const char *str_table_ref(struct str_table *table, const char *str)
{
	char *key;
	void *value;
	unsigned int ref;

	if (!hash_table_lookup_full(table->hash, str, &key, &value)) {
		key = i_strdup(str);
		ref = 1;
	} else {
		ref = POINTER_CAST_TO(value, unsigned int);
		i_assert(ref > 0);
		ref++;
	}
	hash_table_update(table->hash, key, POINTER_CAST(ref));
	return key;
}

void str_table_unref(struct str_table *table, const char **str)
{
	char *key;
	void *value;
	unsigned int ref;

	if (!hash_table_lookup_full(table->hash, *str, &key, &value))
		i_unreached();

	ref = POINTER_CAST_TO(value, unsigned int);
	i_assert(ref > 0);
	if (--ref > 0)
		hash_table_update(table->hash, key, POINTER_CAST(ref));
	else {
		hash_table_remove(table->hash, key);
		i_free(key);
	}
	*str = NULL;
}
