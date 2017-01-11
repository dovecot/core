/* Copyright (c) 2014-2017 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "str-table.h"

void test_str_table(void)
{
	struct str_table *table;
	const char *key1, *key2, *key1_copy, *key2_copy;

	test_begin("str_table");
	table = str_table_init();

	key1 = str_table_ref(table, "str1");
	key2 = str_table_ref(table, "str2");
	test_assert(key1 != key2);
	key1_copy = str_table_ref(table, "str1");
	test_assert(key1_copy == key1);
	key2_copy = str_table_ref(table, "str2");
	test_assert(key2_copy == key2);

	str_table_unref(table, &key1);
	test_assert(key1 == NULL);
	str_table_unref(table, &key1_copy);

	str_table_unref(table, &key2);
	str_table_unref(table, &key2_copy);
	test_assert(str_table_is_empty(table));

	str_table_deinit(&table);
	test_assert(table == NULL);
	test_end();
}
