/* Copyright (c) 2014-2015 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "dict.h"
#include "doveadm.h"
#include "doveadm-print.h"

#include <stdio.h>
#include <unistd.h>

static void dict_cmd_help(doveadm_command_t *cmd);

static struct dict *
cmd_dict_init_full(int *argc, char **argv[], int own_arg_count, int key_arg_idx,
		   doveadm_command_t *cmd, enum dict_iterate_flags *iter_flags)
{
	const char *getopt_args = iter_flags == NULL ? "u:" : "1Ru:V";
	struct dict *dict;
	const char *error, *username = "";
	int c;

	while ((c = getopt(*argc, *argv, getopt_args)) > 0) {
		switch (c) {
		case '1':
			i_assert(iter_flags != NULL);
			*iter_flags |= DICT_ITERATE_FLAG_EXACT_KEY;
			break;
		case 'R':
			i_assert(iter_flags != NULL);
			*iter_flags |= DICT_ITERATE_FLAG_RECURSE;
			break;
		case 'V':
			i_assert(iter_flags != NULL);
			*iter_flags |= DICT_ITERATE_FLAG_NO_VALUE;
			break;
		case 'u':
			username = optarg;
			break;
		default:
			dict_cmd_help(cmd);
		}
	}
	*argc -= optind;
	*argv += optind;

	if (*argc != 1 + own_arg_count)
		dict_cmd_help(cmd);

	dict_drivers_register_builtin();
	if (dict_init((*argv)[0], DICT_DATA_TYPE_STRING, username,
		      doveadm_settings->base_dir, &dict, &error) < 0)
		i_fatal("dict_init(%s) failed: %s", (*argv)[0], error);

	*argc += 1;
	*argv += 1;

	if (key_arg_idx >= 0) {
		const char *key = (*argv)[key_arg_idx];

		if (strncmp(key, DICT_PATH_PRIVATE, strlen(DICT_PATH_PRIVATE)) != 0 &&
		    strncmp(key, DICT_PATH_SHARED, strlen(DICT_PATH_SHARED)) != 0) {
			i_fatal("Key must begin with '"DICT_PATH_PRIVATE
				"' or '"DICT_PATH_SHARED"': %s", key);
		}
		if (username[0] == '\0' &&
		    strncmp(key, DICT_PATH_PRIVATE, strlen(DICT_PATH_PRIVATE)) == 0)
			i_fatal("-u must be specified for "DICT_PATH_PRIVATE" keys");
	}
	return dict;
}

static struct dict *
cmd_dict_init(int *argc, char **argv[],
	      int own_arg_count, int key_arg_idx,
	      doveadm_command_t *cmd)
{
	return cmd_dict_init_full(argc, argv, own_arg_count,
				  key_arg_idx, cmd, NULL);
}

static void cmd_dict_get(int argc, char *argv[])
{
	struct dict *dict;
	const char *value;
	int ret;

	dict = cmd_dict_init(&argc, &argv, 1, 0, cmd_dict_get);

	doveadm_print_init(DOVEADM_PRINT_TYPE_TABLE);
	doveadm_print_header("value", "", DOVEADM_PRINT_HEADER_FLAG_HIDE_TITLE);

	ret = dict_lookup(dict, pool_datastack_create(), argv[0], &value);
	if (ret < 0) {
		i_error("dict_lookup(%s) failed", argv[0]);
		doveadm_exit_code = EX_TEMPFAIL;
	} else if (ret == 0) {
		i_error("%s doesn't exist", argv[0]);
		doveadm_exit_code = DOVEADM_EX_NOTFOUND;
	} else {
		doveadm_print(value);
	}
	dict_deinit(&dict);
}

static void cmd_dict_set(int argc, char *argv[])
{
	struct dict *dict;
	struct dict_transaction_context *trans;

	dict = cmd_dict_init(&argc, &argv, 2, 0, cmd_dict_set);
	trans = dict_transaction_begin(dict);
	dict_set(trans, argv[0], argv[1]);
	if (dict_transaction_commit(&trans) <= 0) {
		i_error("dict_transaction_commit() failed");
		doveadm_exit_code = EX_TEMPFAIL;
	}
	dict_deinit(&dict);
}

static void cmd_dict_unset(int argc, char *argv[])
{
	struct dict *dict;
	struct dict_transaction_context *trans;

	dict = cmd_dict_init(&argc, &argv, 1, 0, cmd_dict_unset);
	trans = dict_transaction_begin(dict);
	dict_unset(trans, argv[0]);
	if (dict_transaction_commit(&trans) <= 0) {
		i_error("dict_transaction_commit() failed");
		doveadm_exit_code = EX_TEMPFAIL;
	}
	dict_deinit(&dict);
}

static void cmd_dict_inc(int argc, char *argv[])
{
	struct dict *dict;
	struct dict_transaction_context *trans;
	long long diff;
	int ret;

	dict = cmd_dict_init(&argc, &argv, 2, 0, cmd_dict_inc);
	if (str_to_llong(argv[1], &diff) < 0)
		i_fatal("Invalid diff: %s", argv[1]);

	trans = dict_transaction_begin(dict);
	dict_atomic_inc(trans, argv[0], diff);
	ret = dict_transaction_commit(&trans);
	if (ret < 0) {
		i_error("dict_transaction_commit() failed");
		doveadm_exit_code = EX_TEMPFAIL;
	} else if (ret == 0) {
		i_error("%s doesn't exist", argv[0]);
		doveadm_exit_code = DOVEADM_EX_NOTFOUND;
	}
	dict_deinit(&dict);
}

static void cmd_dict_iter(int argc, char *argv[])
{
	struct dict *dict;
	struct dict_iterate_context *iter;
	enum dict_iterate_flags iter_flags = 0;
	const char *key, *value;

	dict = cmd_dict_init_full(&argc, &argv, 1, 0, cmd_dict_iter, &iter_flags);

	doveadm_print_init(DOVEADM_PRINT_TYPE_TAB);
	doveadm_print_header_simple("key");
	if ((iter_flags & DICT_ITERATE_FLAG_NO_VALUE) == 0)
		doveadm_print_header_simple("value");

	iter = dict_iterate_init(dict, argv[0], iter_flags);
	while (dict_iterate(iter, &key, &value)) {
		doveadm_print(key);
		if ((iter_flags & DICT_ITERATE_FLAG_NO_VALUE) == 0)
			doveadm_print(value);
	}
	if (dict_iterate_deinit(&iter) < 0) {
		i_error("dict_iterate_deinit(%s) failed", argv[0]);
		doveadm_exit_code = EX_TEMPFAIL;
	}
	dict_deinit(&dict);
}

struct doveadm_cmd doveadm_cmd_dict[] = {
	{ cmd_dict_get, "dict get", "[-u <user>] <dict uri> <key>" },
	{ cmd_dict_set, "dict set", "[-u <user>] <dict uri> <key> <value>" },
	{ cmd_dict_unset, "dict unset", "[-u <user>] <dict uri> <key>" },
	{ cmd_dict_inc, "dict inc", "[-u <user>] <dict uri> <key> <diff>" },
	{ cmd_dict_iter, "dict iter", "[-u <user>] [-1RV] <dict uri> <prefix>" }
};

static void dict_cmd_help(doveadm_command_t *cmd)
{
	unsigned int i;

	for (i = 0; i < N_ELEMENTS(doveadm_cmd_dict); i++) {
		if (doveadm_cmd_dict[i].cmd == cmd)
			help(&doveadm_cmd_dict[i]);
	}
	i_unreached();
}

void doveadm_register_dict_commands(void)
{
	unsigned int i;

	for (i = 0; i < N_ELEMENTS(doveadm_cmd_dict); i++)
		doveadm_register_cmd(&doveadm_cmd_dict[i]);
}
