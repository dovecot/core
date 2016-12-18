/* Copyright (c) 2016 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "dict-private.h"

#include <stdio.h>

static int pending = 0;

static void lookup_callback(const struct dict_lookup_result *result,
			    void *context ATTR_UNUSED)
{
	if (result->error != NULL)
		i_error("%s", result->error);
	/*else if (result->ret == 0)
		i_info("not found");
	else
		i_info("%s", result->value);*/
	pending--;
}

static void commit_callback(const struct dict_commit_result *result,
			    void *context ATTR_UNUSED)
{
	if (result->ret < 0)
		i_error("commit %d", result->ret);
	pending--;
}

int main(int argc, char *argv[])
{
	const char *prefix, *uri;
	struct dict *dict;
	struct dict_settings set;
	struct ioloop *ioloop;
	const char *error;
	unsigned int i;
	char key[1000], value[100];

	lib_init();
	ioloop = io_loop_create();
	dict_driver_register(&dict_driver_client);

	if (argc < 3)
		i_fatal("Usage: <prefix> <uri>");
	prefix = argv[1];
	uri = argv[2];

	i_zero(&set);
	set.base_dir = "/var/run/dovecot";
	set.username = "testuser";

	if (dict_init(uri, &set, &dict, &error) < 0)
		i_fatal("dict_init(%s) failed: %s", argv[1], error);

	for (i = 0;; i++) {
		i_snprintf(key, sizeof(key), "%s/%02x", prefix, rand() % 0xff);
		i_snprintf(value, sizeof(value), "%04x", rand() % 0xffff);
		switch (rand() % 4) {
		case 0:
			pending++;
			dict_lookup_async(dict, key, lookup_callback, NULL);
			break;
		case 1: {
			struct dict_transaction_context *trans;

			pending++;
			trans = dict_transaction_begin(dict);
			dict_set(trans, key, value);
			dict_transaction_commit_async(&trans, commit_callback, NULL);
			break;
		}
		case 2: {
			struct dict_transaction_context *trans;

			pending++;
			trans = dict_transaction_begin(dict);
			dict_unset(trans, key);
			dict_transaction_commit_async(&trans, commit_callback, NULL);
			break;
		}
		case 3: {
			struct dict_iterate_context *iter;
			const char *k, *v;

			iter = dict_iterate_init(dict, prefix, DICT_ITERATE_FLAG_EXACT_KEY);
			while (dict_iterate(iter, &k, &v)) ;
			if (dict_iterate_deinit(&iter, &error) < 0)
				i_error("iter failed: %s", error);
			break;
		}
		}
		while (pending > 100) {
			dict_wait(dict);
			printf("%d\n", pending); fflush(stdout);
		}
	}
	dict_deinit(&dict);

	io_loop_destroy(&ioloop);
	lib_deinit();
}
