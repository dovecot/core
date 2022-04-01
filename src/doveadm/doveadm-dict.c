/* Copyright (c) 2014-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "dict.h"
#include "doveadm.h"
#include "doveadm-print.h"

#include <stdio.h>
#include <unistd.h>

static int
cmd_dict_init_full(struct doveadm_cmd_context *cctx,
		   doveadm_command_ver2_t *cmd ATTR_UNUSED, enum dict_iterate_flags *iter_flags,
		   struct dict **dict_r, struct dict_op_settings *dopset_r)
{
	struct dict_settings dict_set;
	struct dict *dict;
	bool set = FALSE;
	const char *dict_uri, *error, *key, *username = "";
	i_zero(dopset_r);

	if (doveadm_cmd_param_bool(cctx, "exact", &set) && set)
		*iter_flags |= DICT_ITERATE_FLAG_EXACT_KEY;
	if (doveadm_cmd_param_bool(cctx, "recurse", &set) && set)
		*iter_flags |= DICT_ITERATE_FLAG_RECURSE;
	if (doveadm_cmd_param_bool(cctx, "no-value", &set) && set)
		*iter_flags |= DICT_ITERATE_FLAG_NO_VALUE;
	(void)doveadm_cmd_param_str(cctx, "user", &username);
	dopset_r->username = username;

	if (!doveadm_cmd_param_str(cctx, "dict-uri", &dict_uri)) {
		i_error("dictionary URI must be specified");
		doveadm_exit_code = EX_USAGE;
		return -1;
	}

	if (!doveadm_cmd_param_str(cctx, "prefix", &key) &&
	    !doveadm_cmd_param_str(cctx, "key", &key))
		key = "";

	if (!str_begins_with(key, DICT_PATH_PRIVATE) &&
	    !str_begins_with(key, DICT_PATH_SHARED)) {
		i_error("Key must begin with '"DICT_PATH_PRIVATE
			"' or '"DICT_PATH_SHARED"': %s", key);
		doveadm_exit_code = EX_USAGE;
		return -1;
	}
	if (username[0] == '\0' &&
	    str_begins_with(key, DICT_PATH_PRIVATE)) {
		i_error("-u must be specified for "DICT_PATH_PRIVATE" keys");
		doveadm_exit_code = EX_USAGE;
		return -1;
	}

	dict_drivers_register_builtin();
	i_zero(&dict_set);
	dict_set.base_dir = doveadm_settings->base_dir;
	if (dict_init(dict_uri, &dict_set, &dict, &error) < 0) {
		i_error("dict_init(%s) failed: %s", dict_uri, error);
		doveadm_exit_code = EX_TEMPFAIL;
		return -1;
	}
	*dict_r = dict;
	return 0;
}

static int
cmd_dict_init(struct doveadm_cmd_context *cctx,
	      doveadm_command_ver2_t *cmd, struct dict **dict_r,
	      struct dict_op_settings *set_r)
{
	enum dict_iterate_flags iter_flags = 0;
	return cmd_dict_init_full(cctx, cmd, &iter_flags, dict_r, set_r);
}

static int
cmd_dict_init_transaction(struct doveadm_cmd_context *cctx,
			  doveadm_command_ver2_t *cmd, struct dict **dict_r,
			  struct dict_transaction_context **trans_r)
{
	struct dict_op_settings set;
	int64_t timestamp;

	if (cmd_dict_init(cctx, cmd, dict_r, &set) < 0)
		return -1;

	*trans_r = dict_transaction_begin(*dict_r, &set);
	if (doveadm_cmd_param_int64(cctx, "timestamp", &timestamp)) {
		struct timespec ts = {
			.tv_sec = timestamp / 1000000000,
			.tv_nsec = timestamp % 1000000000,
		};
		dict_transaction_set_timestamp(*trans_r, &ts);
	}
	return 0;
}

struct doveadm_dict_ctx {
	pool_t pool;
	int ret;
	const char *const *values;
	const char *error;
};

static void dict_lookup_callback(const struct dict_lookup_result *result,
				 struct doveadm_dict_ctx *ctx)
{
	ctx->ret = result->ret;
	ctx->values = result->values == NULL ? NULL :
		p_strarray_dup(ctx->pool, result->values);
	ctx->error = p_strdup(ctx->pool, result->error);
}

static void cmd_dict_get(struct doveadm_cmd_context *cctx)
{
	struct doveadm_dict_ctx ctx;
	struct dict *dict;
	const char *key;
	struct dict_op_settings set;

	if (!doveadm_cmd_param_str(cctx, "key", &key)) {
		i_error("dict-get: Missing key");
		doveadm_exit_code = EX_USAGE;
		return;
	}

	if (cmd_dict_init(cctx, cmd_dict_get, &dict, &set) < 0)
		return;

	doveadm_print_init(DOVEADM_PRINT_TYPE_TABLE);
	doveadm_print_header("value", "", DOVEADM_PRINT_HEADER_FLAG_HIDE_TITLE);

	i_zero(&ctx);
	ctx.pool = pool_alloconly_create("doveadm dict lookup", 512);
	ctx.ret = -2;
	dict_lookup_async(dict, &set, key, dict_lookup_callback, &ctx);
	while (ctx.ret == -2)
		dict_wait(dict);
	if (ctx.ret < 0) {
		i_error("dict_lookup(%s) failed: %s", key, ctx.error);
		doveadm_exit_code = EX_TEMPFAIL;
	} else if (ctx.ret == 0) {
		i_error("%s doesn't exist", key);
		doveadm_exit_code = DOVEADM_EX_NOTFOUND;
	} else {
		unsigned int i, values_count = str_array_length(ctx.values);

		for (i = 1; i < values_count; i++)
			doveadm_print_header("value", "", DOVEADM_PRINT_HEADER_FLAG_HIDE_TITLE);
		for (i = 0; i < values_count; i++)
			doveadm_print(ctx.values[i]);
	}
	pool_unref(&ctx.pool);
	dict_deinit(&dict);
}

static void cmd_dict_set(struct doveadm_cmd_context *cctx)
{
	struct dict *dict;
	struct dict_transaction_context *trans;
	const char *error;
	const char *key, *value = "";

	if (!doveadm_cmd_param_str(cctx, "key", &key) ||
	    !doveadm_cmd_param_str(cctx, "value", &value)) {
		i_error("dict set: Missing parameters");
		doveadm_exit_code = EX_USAGE;
		return;
	}

	if (cmd_dict_init_transaction(cctx, cmd_dict_set, &dict, &trans) < 0)
		return;

	dict_set(trans, key, value);
	if (dict_transaction_commit(&trans, &error) <= 0) {
		i_error("dict_transaction_commit() failed: %s", error);
		doveadm_exit_code = EX_TEMPFAIL;
	}
	dict_deinit(&dict);
}

static void cmd_dict_unset(struct doveadm_cmd_context *cctx)
{
	struct dict *dict;
	struct dict_transaction_context *trans;
	const char *error;
	const char *key;

	if (!doveadm_cmd_param_str(cctx, "key", &key)) {
		i_error("dict unset: Missing key");
		doveadm_exit_code = EX_USAGE;
		return;
	}

	if (cmd_dict_init_transaction(cctx, cmd_dict_unset, &dict, &trans) < 0)
		return;

	dict_unset(trans, key);
	if (dict_transaction_commit(&trans, &error) <= 0) {
		i_error("dict_transaction_commit() failed: %s", error);
		doveadm_exit_code = EX_TEMPFAIL;
	}
	dict_deinit(&dict);
}

static void cmd_dict_inc(struct doveadm_cmd_context *cctx)
{
	struct dict *dict;
	struct dict_transaction_context *trans;
	const char *error;
	const char *key;
	int64_t diff;
	int ret;

	if (!doveadm_cmd_param_str(cctx, "key", &key) ||
	    !doveadm_cmd_param_int64(cctx, "difference", &diff)) {
		i_error("dict-inc: Missing parameters");
		doveadm_exit_code = EX_USAGE;
		return;
	}

	if (cmd_dict_init_transaction(cctx, cmd_dict_inc, &dict, &trans) < 0)
		return;

	dict_atomic_inc(trans, key, diff);
	ret = dict_transaction_commit(&trans, &error);
	if (ret < 0) {
		i_error("dict_transaction_commit() failed: %s", error);
		doveadm_exit_code = EX_TEMPFAIL;
	} else if (ret == 0) {
		i_error("%s doesn't exist", key);
		doveadm_exit_code = DOVEADM_EX_NOTFOUND;
	}
	dict_deinit(&dict);
}

static void cmd_dict_iter(struct doveadm_cmd_context *cctx)
{
	struct dict *dict;
	struct dict_iterate_context *iter;
	enum dict_iterate_flags iter_flags = 0;
	const char *prefix, *key, *const *values, *error;
	bool header_printed = FALSE;
	struct dict_op_settings set;

	if (!doveadm_cmd_param_str(cctx, "prefix", &prefix)) {
		i_error("dict-iter: Missing prefix");
		doveadm_exit_code = EX_USAGE;
		return;
	}

	if (cmd_dict_init_full(cctx, cmd_dict_iter, &iter_flags, &dict, &set) < 0)
		return;

	doveadm_print_init(DOVEADM_PRINT_TYPE_TAB);
	doveadm_print_header_simple("key");
	if ((iter_flags & DICT_ITERATE_FLAG_NO_VALUE) == 0)
		doveadm_print_header_simple("value");

	iter = dict_iterate_init(dict, &set, prefix, iter_flags);
	while (dict_iterate_values(iter, &key, &values)) {
		unsigned int values_count = str_array_length(values);
		if (!header_printed) {
			for (unsigned int i = 1; i < values_count; i++)
				doveadm_print_header_simple("value");
			header_printed = TRUE;
		}
		doveadm_print(key);
		if ((iter_flags & DICT_ITERATE_FLAG_NO_VALUE) == 0) {
			for (unsigned int i = 0; i < values_count; i++)
				doveadm_print(values[i]);
		}
	}
	if (dict_iterate_deinit(&iter, &error) < 0) {
		i_error("dict_iterate_deinit(%s) failed: %s", prefix, error);
		doveadm_exit_code = EX_TEMPFAIL;
	}
	dict_deinit(&dict);
}

static struct doveadm_cmd_ver2 doveadm_cmd_dict[] = {
{
	.name = "dict get",
	.cmd = cmd_dict_get,
	.usage = "[-u <user>] <dict uri> <key>",
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_PARAM('u', "user", CMD_PARAM_STR, 0)
DOVEADM_CMD_PARAM('\0', "dict-uri", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAM('\0', "key", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAMS_END
},
{
	.name = "dict set",
	.cmd = cmd_dict_set,
	.usage = "[-u <user>] [-t <timestamp-nsecs>] <dict uri> <key> <value>",
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_PARAM('u', "user", CMD_PARAM_STR, 0)
DOVEADM_CMD_PARAM('t', "timestamp", CMD_PARAM_INT64, 0)
DOVEADM_CMD_PARAM('\0', "dict-uri", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAM('\0', "key", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAM('\0', "value", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAMS_END
},
{
	.name = "dict unset",
	.cmd = cmd_dict_unset,
	.usage = "[-u <user>] [-t <timestamp-nsecs>] <dict uri> <key>",
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_PARAM('u', "user", CMD_PARAM_STR, 0)
DOVEADM_CMD_PARAM('t', "timestamp", CMD_PARAM_INT64, 0)
DOVEADM_CMD_PARAM('\0', "dict-uri", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAM('\0', "key", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAMS_END
},
{
	.name = "dict inc",
	.cmd = cmd_dict_inc,
	.usage = "[-u <user>] [-t <timestamp-nsecs>] <dict uri> <key> <diff>",
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_PARAM('u', "user", CMD_PARAM_STR, 0)
DOVEADM_CMD_PARAM('t', "timestamp", CMD_PARAM_INT64, 0)
DOVEADM_CMD_PARAM('\0', "dict-uri", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAM('\0', "key", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAM('\0', "difference", CMD_PARAM_INT64, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAMS_END
},
{
	.name = "dict iter",
	.cmd = cmd_dict_iter,
	.usage = "[-u <user>] [-1RV] <dict uri> <prefix>",
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_PARAM('u', "user", CMD_PARAM_STR, 0)
DOVEADM_CMD_PARAM('1', "exact", CMD_PARAM_BOOL, 0)
DOVEADM_CMD_PARAM('R', "recurse", CMD_PARAM_BOOL, 0)
DOVEADM_CMD_PARAM('V', "no-value", CMD_PARAM_BOOL, 0)
DOVEADM_CMD_PARAM('\0', "dict-uri", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAM('\0', "prefix", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAMS_END
}
};

void doveadm_register_dict_commands(void)
{
	unsigned int i;

	for (i = 0; i < N_ELEMENTS(doveadm_cmd_dict); i++)
		doveadm_cmd_register_ver2(&doveadm_cmd_dict[i]);
}
