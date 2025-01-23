/* Copyright (c) 2014-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "settings.h"
#include "dict.h"
#include "doveadm.h"
#include "doveadm-dict.h"
#include "doveadm-print.h"

#include <stdio.h>
#include <unistd.h>

static int
cmd_dict_init(struct doveadm_cmd_context *cctx,
	      struct dict **dict_r,
	      struct dict_op_settings *dopset_r)
{
	struct dict *dict;
	const char *filter_name, *error, *key, *username = "";
	i_zero(dopset_r);

	if (cctx->cmd->mail_cmd != NULL)
		username = cctx->username; /* doveadm mail dict command */
	else
		(void)doveadm_cmd_param_str(cctx, "user", &username);
	dopset_r->username = username;

	if (!doveadm_cmd_param_str(cctx, "filter-name", &filter_name)) {
		e_error(cctx->event, "filter-name must be specified");
		doveadm_exit_code = EX_USAGE;
		return -1;
	}

	if (!doveadm_cmd_param_str(cctx, "prefix", &key) &&
	    !doveadm_cmd_param_str(cctx, "key", &key))
		key = "";

	if (!str_begins_with(key, DICT_PATH_PRIVATE) &&
	    !str_begins_with(key, DICT_PATH_SHARED)) {
		e_error(cctx->event, "Key must begin with "
			"'"DICT_PATH_PRIVATE"' or '"DICT_PATH_SHARED"': %s",
			key);
		doveadm_exit_code = EX_USAGE;
		return -1;
	}
	if (username[0] == '\0' &&
	    str_begins_with(key, DICT_PATH_PRIVATE)) {
		e_error(cctx->event,
			"-u must be specified for "DICT_PATH_PRIVATE" keys");
		doveadm_exit_code = EX_USAGE;
		return -1;
	}

	dict_drivers_register_builtin();

	settings_event_add_filter_name(cctx->event, filter_name);
	if (dict_init_auto(cctx->event, &dict, &error) <= 0) {
		e_error(cctx->event,
			"dict_init() failed: %s", error);
		doveadm_exit_code = EX_TEMPFAIL;
		return -1;
	}
	*dict_r = dict;
	return 0;
}

static int
cmd_dict_init_transaction(struct doveadm_cmd_context *cctx,
			  struct dict **dict_r,
			  struct dict_transaction_context **trans_r)
{
	struct dict_op_settings set;
	int64_t timestamp, expire_secs;

	if (cmd_dict_init(cctx, dict_r, &set) < 0)
		return -1;
	if (doveadm_cmd_param_int64(cctx, "expire-secs", &expire_secs))
		set.expire_secs = expire_secs;

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
	const char *key;

	if (!doveadm_cmd_param_str(cctx, "key", &key)) {
		e_error(cctx->event, "dict-get: Missing key");
		doveadm_exit_code = EX_USAGE;
		return;
	}

	doveadm_print_init(DOVEADM_PRINT_TYPE_TABLE);
	doveadm_print_header("value", "", DOVEADM_PRINT_HEADER_FLAG_HIDE_TITLE);
	doveadm_dict_get(cctx, key);
}

void doveadm_dict_get(struct doveadm_cmd_context *cctx, const char *key)
{
	struct doveadm_dict_ctx ctx;
	struct dict *dict;
	struct dict_op_settings set;

	if (cmd_dict_init(cctx, &dict, &set) < 0)
		return;

	i_zero(&ctx);
	ctx.pool = pool_alloconly_create("doveadm dict lookup", 512);
	ctx.ret = -2;
	dict_lookup_async(dict, &set, key, dict_lookup_callback, &ctx);
	while (ctx.ret == -2)
		dict_wait(dict);
	if (ctx.ret < 0) {
		e_error(cctx->event,
			"dict_lookup(%s) failed: %s", key, ctx.error);
		doveadm_exit_code = EX_TEMPFAIL;
	} else if (ctx.ret == 0) {
		e_error(cctx->event, "%s doesn't exist", key);
		doveadm_exit_code = DOVEADM_EX_NOTFOUND;
	} else {
		unsigned int i, values_count = str_array_length(ctx.values);

		/* We don't know beforehand how many values there are,
		   so allow adding headers at this stage, even though
		   it's not correct. */
		doveadm_print_header_disallow(FALSE);
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
	const char *key, *value = "";

	if (!doveadm_cmd_param_str(cctx, "key", &key) ||
	    !doveadm_cmd_param_str(cctx, "value", &value)) {
		e_error(cctx->event, "dict set: Missing parameters");
		doveadm_exit_code = EX_USAGE;
		return;
	}
	doveadm_dict_set(cctx, key, value);
}

void doveadm_dict_set(struct doveadm_cmd_context *cctx, const char *key,
		      const char *value)
{
	struct dict *dict;
	struct dict_transaction_context *trans;
	const char *error;

	if (cmd_dict_init_transaction(cctx, &dict, &trans) < 0)
		return;

	dict_set(trans, key, value);
	if (dict_transaction_commit(&trans, &error) <= 0) {
		e_error(cctx->event,
			"dict_transaction_commit() failed: %s", error);
		doveadm_exit_code = EX_TEMPFAIL;
	}
	dict_deinit(&dict);
}

static void cmd_dict_unset(struct doveadm_cmd_context *cctx)
{
	const char *key;

	if (!doveadm_cmd_param_str(cctx, "key", &key)) {
		e_error(cctx->event, "dict unset: Missing key");
		doveadm_exit_code = EX_USAGE;
		return;
	}
	doveadm_dict_unset(cctx, key);
}

void doveadm_dict_unset(struct doveadm_cmd_context *cctx, const char *key)
{
	struct dict *dict;
	struct dict_transaction_context *trans;
	const char *error;

	if (cmd_dict_init_transaction(cctx, &dict, &trans) < 0)
		return;

	dict_unset(trans, key);
	if (dict_transaction_commit(&trans, &error) <= 0) {
		e_error(cctx->event,
			"dict_transaction_commit() failed: %s", error);
		doveadm_exit_code = EX_TEMPFAIL;
	}
	dict_deinit(&dict);
}

static void cmd_dict_inc(struct doveadm_cmd_context *cctx)
{
	const char *key;
	int64_t diff;

	if (!doveadm_cmd_param_str(cctx, "key", &key) ||
	    !doveadm_cmd_param_int64(cctx, "difference", &diff)) {
		e_error(cctx->event, "dict-inc: Missing parameters");
		doveadm_exit_code = EX_USAGE;
		return;
	}
	doveadm_dict_inc(cctx, key, diff);
}

void doveadm_dict_inc(struct doveadm_cmd_context *cctx, const char *key,
		      int64_t diff)
{
	struct dict *dict;
	struct dict_transaction_context *trans;
	const char *error;
	int ret;

	if (cmd_dict_init_transaction(cctx, &dict, &trans) < 0)
		return;

	dict_atomic_inc(trans, key, diff);
	ret = dict_transaction_commit(&trans, &error);
	if (ret < 0) {
		e_error(cctx->event,
			"dict_transaction_commit() failed: %s", error);
		doveadm_exit_code = EX_TEMPFAIL;
	} else if (ret == 0) {
		e_error(cctx->event, "%s doesn't exist", key);
		doveadm_exit_code = DOVEADM_EX_NOTFOUND;
	}
	dict_deinit(&dict);
}

static void cmd_dict_iter(struct doveadm_cmd_context *cctx)
{
	enum dict_iterate_flags iter_flags = 0;
	const char *prefix;

	if (!doveadm_cmd_param_str(cctx, "prefix", &prefix)) {
		e_error(cctx->event, "dict-iter: Missing prefix");
		doveadm_exit_code = EX_USAGE;
		return;
	}
	if (doveadm_cmd_param_flag(cctx, "exact"))
		iter_flags |= DICT_ITERATE_FLAG_EXACT_KEY;
	if (doveadm_cmd_param_flag(cctx, "recurse"))
		iter_flags |= DICT_ITERATE_FLAG_RECURSE;
	if (doveadm_cmd_param_flag(cctx, "no-value"))
		iter_flags |= DICT_ITERATE_FLAG_NO_VALUE;

	doveadm_print_init(DOVEADM_PRINT_TYPE_TAB);
	doveadm_print_header_simple("key");
	if ((iter_flags & DICT_ITERATE_FLAG_NO_VALUE) == 0)
		doveadm_print_header_simple("value");
	doveadm_dict_iter(cctx, iter_flags, prefix);
}

void doveadm_dict_iter(struct doveadm_cmd_context *cctx,
		       enum dict_iterate_flags iter_flags, const char *prefix)
{
	struct dict *dict;
	struct dict_iterate_context *iter;
	const char *key, *const *values, *error;
	bool header_printed = FALSE;
	struct dict_op_settings set;

	if (cmd_dict_init(cctx, &dict, &set) < 0)
		return;

	iter = dict_iterate_init(dict, &set, prefix, iter_flags);
	while (dict_iterate_values(iter, &key, &values)) {
		unsigned int values_count = str_array_length(values);
		if (!header_printed) {
			/* We don't know beforehand how many values there are,
			   so allow adding headers at this stage, even though
			   it's not correct. */
			doveadm_print_header_disallow(FALSE);
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
		e_error(cctx->event,
			"dict_iterate_deinit(%s) failed: %s", prefix, error);
		doveadm_exit_code = EX_TEMPFAIL;
	}
	dict_deinit(&dict);
}

static struct doveadm_cmd_ver2 doveadm_cmd_dict[] = {
{
	.name = "dict get",
	.cmd = cmd_dict_get,
	.usage = "[-u <user>] <config-filter-name> <key>",
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_PARAM('u', "user", CMD_PARAM_STR, 0)
DOVEADM_CMD_PARAM('\0', "filter-name", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAM('\0', "key", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAMS_END
},
{
	.name = "dict set",
	.cmd = cmd_dict_set,
	.usage = "[-u <user>] [-t <timestamp-nsecs>] [-e <expire-secs>] <config-filter-name> <key> <value>",
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_PARAM('u', "user", CMD_PARAM_STR, 0)
DOVEADM_CMD_PARAM('t', "timestamp", CMD_PARAM_INT64, CMD_PARAM_FLAG_UNSIGNED)
DOVEADM_CMD_PARAM('e', "expire-secs", CMD_PARAM_INT64, CMD_PARAM_FLAG_UNSIGNED)
DOVEADM_CMD_PARAM('\0', "filter-name", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAM('\0', "key", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAM('\0', "value", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAMS_END
},
{
	.name = "dict unset",
	.cmd = cmd_dict_unset,
	.usage = "[-u <user>] [-t <timestamp-nsecs>] <config-filter-name> <key>",
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_PARAM('u', "user", CMD_PARAM_STR, 0)
DOVEADM_CMD_PARAM('t', "timestamp", CMD_PARAM_INT64, CMD_PARAM_FLAG_UNSIGNED)
DOVEADM_CMD_PARAM('\0', "filter-name", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAM('\0', "key", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAMS_END
},
{
	.name = "dict inc",
	.cmd = cmd_dict_inc,
	.usage = "[-u <user>] [-t <timestamp-nsecs>] <config-filter-name> <key> <diff>",
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_PARAM('u', "user", CMD_PARAM_STR, 0)
DOVEADM_CMD_PARAM('t', "timestamp", CMD_PARAM_INT64, CMD_PARAM_FLAG_UNSIGNED)
DOVEADM_CMD_PARAM('\0', "filter-name", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAM('\0', "key", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAM('\0', "difference", CMD_PARAM_INT64, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAMS_END
},
{
	.name = "dict iter",
	.cmd = cmd_dict_iter,
	.usage = "[-u <user>] [-1RV] <config-filter-name> <prefix>",
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_PARAM('u', "user", CMD_PARAM_STR, 0)
DOVEADM_CMD_PARAM('1', "exact", CMD_PARAM_BOOL, 0)
DOVEADM_CMD_PARAM('R', "recurse", CMD_PARAM_BOOL, 0)
DOVEADM_CMD_PARAM('V', "no-value", CMD_PARAM_BOOL, 0)
DOVEADM_CMD_PARAM('\0', "filter-name", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
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
