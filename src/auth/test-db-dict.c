/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "auth-settings.h"
#include "test-auth.h"
#include "array.h"
#include "db-dict.h"

void test_db_dict_parse_cache_key(void)
{
	struct db_dict_key keys[] = {
		{ "key0", "%d and %n", NULL, NULL, 0 },
		{ "key1", "%{foo}%r%{bar}", NULL, NULL, 0 },
		{ "key2", "%{test1}/path", NULL, NULL, 0 },
		{ "key3", "path2/%{test2}", NULL, NULL, 0 },
		{ "key4", "%{plop}", NULL, NULL, 0 },
		{ "key5", "%{unused}", NULL, NULL, 0 }
	};
	struct db_dict_field fields[] = {
		{ "name1", "hello %{dict:key0} %l and %{dict:key1}" },
		{ "name2", "%{dict:key2} also %{extra} plus" }
	};
	const struct db_dict_key *objects[] = {
		&keys[3], &keys[4]
	};
	buffer_t keybuf, fieldbuf, objectbuf;
	ARRAY_TYPE(db_dict_key) keyarr;
	ARRAY_TYPE(db_dict_field) fieldarr;
	ARRAY_TYPE(db_dict_key_p) objectarr;

	test_begin("db dict parse cache key");

	buffer_create_from_const_data(&keybuf, keys, sizeof(keys));
	buffer_create_from_const_data(&fieldbuf, fields, sizeof(fields));
	buffer_create_from_const_data(&objectbuf, objects, sizeof(objects));
	array_create_from_buffer(&keyarr, &keybuf, sizeof(keys[0]));
	array_create_from_buffer(&fieldarr, &fieldbuf, sizeof(fields[0]));
	array_create_from_buffer(&objectarr, &objectbuf, sizeof(objects[0]));

	test_assert(strcmp(db_dict_parse_cache_key(&keyarr, &fieldarr, &objectarr),
			   "\t%d and %n\t%l\t%{foo}%r%{bar}\t%{test1}/path\t%{extra}\tpath2/%{test2}\t%{plop}") == 0);
	test_end();
}
