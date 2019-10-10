/* Copyright (c) 2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "time-util.h"
#include "mail-index-private.h"
#include "mail-cache-private.h"
#include "mail-namespace.h"
#include "mail-storage-private.h"
#include "doveadm-print.h"
#include "doveadm-mail-iter.h"
#include "doveadm-mailbox-list-iter.h"
#include "doveadm-mail.h"

struct mailbox_cache_cmd_context {
	struct doveadm_mail_cmd_context ctx;

	const char *const *boxes;
	const char *const *fields;
	uint64_t last_used;
	enum mail_cache_decision_type decision;
	bool all_fields;
	bool set_decision;
	bool set_last_used;
	bool remove;
};

static int cmd_mailbox_cache_open_box(struct doveadm_mail_cmd_context *ctx,
				      struct mail_user *user,
				      const char *boxname,
				      struct mailbox **box_r)
{
	struct mailbox *box = doveadm_mailbox_find(user, boxname);

	if (mailbox_open(box) < 0 || mailbox_sync(box, 0) < 0) {
		i_error("Cannot open mailbox %s: %s",
			mailbox_get_vname(box),
			mailbox_get_last_internal_error(box, NULL));
		doveadm_mail_failed_mailbox(ctx, box);
		mailbox_free(&box);
		return -1;
	}

	*box_r = box;

	return 0;
}

static void cmd_mailbox_cache_decision_init(struct doveadm_mail_cmd_context *_ctx,
					    const char *const args[])
{
	struct mailbox_cache_cmd_context *ctx =
		container_of(_ctx, struct mailbox_cache_cmd_context, ctx);
	const char *fields;

	doveadm_print_header("mailbox", "mailbox", DOVEADM_PRINT_HEADER_FLAG_STICKY);
	doveadm_print_header_simple("field");
	doveadm_print_header_simple("decision");
	doveadm_print_header_simple("last-used");

	if (!ctx->all_fields &&
	    !doveadm_cmd_param_str(_ctx->cctx, "fieldstr", &fields)) {
		i_fatal("Missing fields parameter");
	} else if (!ctx->all_fields) {
		ctx->fields = t_strsplit_spaces(fields, ", ");
	}

	ctx->boxes = args;
}

static bool
cmd_mailbox_cache_parse_arg(struct doveadm_mail_cmd_context *_ctx, int c)
{
	struct mailbox_cache_cmd_context *ctx =
		container_of(_ctx, struct mailbox_cache_cmd_context, ctx);

	switch(c) {
	case 'a':
		ctx->all_fields = TRUE;
		return TRUE;
	/* this is handled in doveadm-mail as 'fieldstr' field */
	case 'f':
		return TRUE;
	case 'l':
		if (str_to_uint64(optarg, &ctx->last_used) < 0) {
			i_error("Invalid last-used '%s': not a number", optarg);
			return FALSE;
		}
		ctx->set_last_used = TRUE;
		return TRUE;
	case 'd':
		if (ctx->set_decision) {
			i_error("Only one decision flag allowed");
			return FALSE;
		}
		if (strcmp(optarg, "no") == 0) {
			ctx->decision = MAIL_CACHE_DECISION_NO;
		} else if (strcmp(optarg, "temp") == 0) {
			ctx->decision = MAIL_CACHE_DECISION_TEMP;
		} else if (strcmp(optarg, "yes") == 0) {
			ctx->decision = MAIL_CACHE_DECISION_YES;
		} else {
			i_error("Invalid decision '%s': " \
				"must be one of yes, temp, no",
				optarg);
			return FALSE;
		}
		ctx->set_decision = TRUE;
		return TRUE;
	}
	return FALSE;
}

static const char *
cmd_mailbox_cache_decision_to_str(enum mail_cache_decision_type decision)
{
	string_t *ret = t_str_new(10);
	switch((decision & ~MAIL_CACHE_DECISION_FORCED)) {
	case MAIL_CACHE_DECISION_NO:
		str_append(ret, "no");
		break;
	case MAIL_CACHE_DECISION_TEMP:
		str_append(ret, "temp");
		break;
	case MAIL_CACHE_DECISION_YES:
		str_append(ret, "yes");
		break;
	}
	return str_c(ret);
}

static void
cmd_mailbox_cache_decision_process_field(struct mailbox_cache_cmd_context *ctx,
					 struct mail_cache_field_private *field)
{
	if (ctx->set_decision) {
		field->field.decision = ctx->decision;
		field->decision_dirty = TRUE;
	}

	if (ctx->set_last_used) {
		field->field.last_used = (time_t)ctx->last_used;
		field->decision_dirty = TRUE;
	}

	doveadm_print(cmd_mailbox_cache_decision_to_str(field->field.decision));
	doveadm_print(t_strflocaltime("%F %T %Z", field->field.last_used));
}

static void
cmd_mailbox_cache_decision_run_per_field(struct mailbox_cache_cmd_context *ctx,
					 struct mail_cache *cache)
{
	const char *const *field_name;
	for(field_name = ctx->fields; *field_name != NULL; field_name++) {
		doveadm_print(*field_name);
		/* see if the field exists */
		unsigned int idx = mail_cache_register_lookup(cache,
							      *field_name);
		if (idx == UINT_MAX) {
			doveadm_print("<not found>");
			doveadm_print("");
			continue;
		}

		cmd_mailbox_cache_decision_process_field(ctx, &cache->fields[idx]);
	}
}

static void
cmd_mailbox_cache_decision_run_all_fields(struct mailbox_cache_cmd_context *ctx,
					  struct mail_cache *cache)
{
	/* get all fields */
	for(unsigned int i = 0; i < cache->fields_count; i++) {
		doveadm_print(cache->fields[i].field.name);
		cmd_mailbox_cache_decision_process_field(ctx, &cache->fields[i]);
	}
}

static int cmd_mailbox_cache_decision_run_box(struct mailbox_cache_cmd_context *ctx,
					      struct mailbox *box)
{
	struct mailbox_transaction_context *t =
		mailbox_transaction_begin(box, 0, "mailbox cache decision");
	struct mail_cache *cache = t->box->cache;
	struct mail_cache_view *view;

	if (mail_cache_open_and_verify(cache) < 0 ||
	    MAIL_CACHE_IS_UNUSABLE(cache)) {
		mailbox_transaction_rollback(&t);
		i_error("Cache is unusable");
		ctx->ctx.exit_code = EX_TEMPFAIL;
		return -1;
	}

	view = mail_cache_view_open(cache, t->box->view);

	if (ctx->all_fields)
		cmd_mailbox_cache_decision_run_all_fields(ctx, cache);
	else
		cmd_mailbox_cache_decision_run_per_field(ctx, cache);

	/* update headers */
	if (ctx->set_decision || ctx->set_last_used)
		mail_cache_header_fields_update(cache);

	mail_cache_view_close(&view);

	if (mailbox_transaction_commit(&t) < 0) {
		i_error("mailbox_transaction_commit() failed: %s",
			mailbox_get_last_internal_error(box, NULL));
		doveadm_mail_failed_mailbox(&ctx->ctx, box);
		return -1;
	}
	return 0;
}

static int cmd_mailbox_cache_decision_run(struct doveadm_mail_cmd_context *_ctx,
					  struct mail_user *user)
{
	struct mailbox_cache_cmd_context *ctx =
		container_of(_ctx, struct mailbox_cache_cmd_context, ctx);
	const char *const *boxname;
	int ret = 0;

	if (_ctx->exit_code != 0)
		return -1;

	for(boxname = ctx->boxes; ret == 0 && *boxname != NULL; boxname++) {
		struct mailbox *box;
		if ((ret = cmd_mailbox_cache_open_box(_ctx, user, *boxname, &box)) < 0)
			break;
		doveadm_print_sticky("mailbox", mailbox_get_vname(box));
		ret = cmd_mailbox_cache_decision_run_box(ctx, box);
		mailbox_free(&box);
	}

	return ret;
}

static int cmd_mailbox_cache_remove_box(struct mailbox_cache_cmd_context *ctx,
					const struct mailbox_info *info)
{
	struct doveadm_mail_iter *iter;
	struct mailbox *box;
	struct mail *mail;
	void *empty = NULL;
	int ret = 0, count = 0;

	if (doveadm_mail_iter_init(&ctx->ctx, info, ctx->ctx.search_args,
				   0, NULL, FALSE, &iter) < 0)
		return -1;

	box = doveadm_mail_iter_get_mailbox(iter);

	struct mail_index_transaction *t =
		mail_index_transaction_begin(box->view, MAIL_INDEX_TRANSACTION_FLAG_EXTERNAL);
	struct mail_cache_view *view =
		mail_cache_view_open(box->cache, box->view);

	while (doveadm_mail_iter_next(iter, &mail)) {
		count++;
		doveadm_print(mailbox_get_vname(box));
		doveadm_print(dec2str(mail->uid));
	        /* drop cache pointer */
	        mail_index_update_ext(t, mail->seq, view->cache->ext_id, &empty, NULL);
		doveadm_print("ok");
	}

	if (mail_index_transaction_commit(&t) < 0) {
		i_error("mail_index_transaction_commit() failed: %s",
			mailbox_get_last_internal_error(box, NULL));
		doveadm_mail_failed_mailbox(&ctx->ctx, box);
		ret = -1;
	} else {
		 mail_cache_expunge_count(view->cache, count);
	}

	mail_cache_view_close(&view);

	if (doveadm_mail_iter_deinit(&iter) < 0)
		ret = -1;

	return ret;
}

static int cmd_mailbox_cache_remove_run(struct doveadm_mail_cmd_context *_ctx,
					struct mail_user *user)
{
	struct mailbox_cache_cmd_context *ctx =
		container_of(_ctx, struct mailbox_cache_cmd_context, ctx);
	const enum mailbox_list_iter_flags iter_flags =
		MAILBOX_LIST_ITER_NO_AUTO_BOXES |
		MAILBOX_LIST_ITER_RETURN_NO_FLAGS;
	struct doveadm_mailbox_list_iter *iter;
	const struct mailbox_info *info;
	int ret = 0;

	iter = doveadm_mailbox_list_iter_init(&ctx->ctx, user, ctx->ctx.search_args,
					      iter_flags);
	while ((info = doveadm_mailbox_list_iter_next(iter)) != NULL) T_BEGIN {
		if (cmd_mailbox_cache_remove_box(ctx, info) < 0)
			ret = -1;
	} T_END;
	if (doveadm_mailbox_list_iter_deinit(&iter) < 0)
		ret = -1;
	return ret;
}

static void cmd_mailbox_cache_remove_init(struct doveadm_mail_cmd_context *_ctx,
					  const char *const args[])
{
	struct mailbox_cache_cmd_context *ctx =
		container_of(_ctx, struct mailbox_cache_cmd_context, ctx);

	if (args[0] == NULL)
		doveadm_mail_help_name("mailbox cache remove");

	doveadm_print_header_simple("mailbox");
	doveadm_print_header_simple("uid");
	doveadm_print_header_simple("result");

	ctx->ctx.search_args = doveadm_mail_build_search_args(args);
}

static int cmd_mailbox_cache_purge_run_box(struct mailbox_cache_cmd_context *ctx,
					   struct mailbox *box)
{
	struct mailbox_transaction_context *t =
		mailbox_transaction_begin(box,
					  MAILBOX_TRANSACTION_FLAG_EXTERNAL,
					  "mailbox cache purge");
	struct mail_cache *cache = t->box->cache;
	struct mail_cache_compress_lock *lock;
	int ret = 0;

	if (mail_cache_open_and_verify(cache) < 0 ||
	    MAIL_CACHE_IS_UNUSABLE(cache)) {
		mailbox_transaction_rollback(&t);
		i_error("Cache is unusable");
		ctx->ctx.exit_code = EX_TEMPFAIL;
		return -1;
	}

	cache->need_compress_file_seq = UINT_MAX;
	if (mail_cache_compress_forced(cache, t->itrans, &lock) < 0) {
		mailbox_set_index_error(t->box);
		doveadm_mail_failed_mailbox(&ctx->ctx, box);
		ret = -1;
	}

	if (mailbox_transaction_commit(&t) < 0) {
		i_error("mailbox_transaction_commit() failed: %s",
			mailbox_get_last_internal_error(box, NULL));
		doveadm_mail_failed_mailbox(&ctx->ctx, box);
		ret = -1;
	}
	mail_cache_compress_unlock(&lock);
	return ret;
}

static int cmd_mailbox_cache_purge_run(struct doveadm_mail_cmd_context *_ctx,
				       struct mail_user *user)
{
	struct mailbox_cache_cmd_context *ctx =
		container_of(_ctx, struct mailbox_cache_cmd_context, ctx);
	const char *const *boxname;
	int ret = 0;

	if (_ctx->exit_code != 0)
		return -1;

	for(boxname = ctx->boxes; ret == 0 && *boxname != NULL; boxname++) {
		struct mailbox *box;
		if ((ret = cmd_mailbox_cache_open_box(_ctx, user, *boxname, &box)) < 0)
			break;
		ret = cmd_mailbox_cache_purge_run_box(ctx, box);
		mailbox_free(&box);
	}

	return ret;
}

static void cmd_mailbox_cache_purge_init(struct doveadm_mail_cmd_context *_ctx,
					 const char *const args[])
{
	struct mailbox_cache_cmd_context *ctx =
		container_of(_ctx, struct mailbox_cache_cmd_context, ctx);

	ctx->boxes = args;
}

static struct doveadm_mail_cmd_context *cmd_mailbox_cache_decision_alloc(void)
{
	struct mailbox_cache_cmd_context *ctx =
		doveadm_mail_cmd_alloc(struct mailbox_cache_cmd_context);
	ctx->ctx.v.init = cmd_mailbox_cache_decision_init;
	ctx->ctx.v.parse_arg = cmd_mailbox_cache_parse_arg;
	ctx->ctx.v.run = cmd_mailbox_cache_decision_run;
	ctx->ctx.getopt_args = "al:f:d:";
	doveadm_print_init(DOVEADM_PRINT_TYPE_TABLE);
	return &ctx->ctx;
}

static struct doveadm_mail_cmd_context *cmd_mailbox_cache_remove_alloc(void)
{
	struct mailbox_cache_cmd_context *ctx =
		doveadm_mail_cmd_alloc(struct mailbox_cache_cmd_context);
	ctx->ctx.v.init = cmd_mailbox_cache_remove_init;
	ctx->ctx.v.parse_arg = cmd_mailbox_cache_parse_arg;
	ctx->ctx.v.run = cmd_mailbox_cache_remove_run;
	ctx->ctx.getopt_args = "";
	doveadm_print_init(DOVEADM_PRINT_TYPE_TABLE);
	return &ctx->ctx;
}

static struct doveadm_mail_cmd_context *cmd_mailbox_cache_purge_alloc(void)
{
	struct mailbox_cache_cmd_context *ctx =
		doveadm_mail_cmd_alloc(struct mailbox_cache_cmd_context);
	ctx->ctx.v.init = cmd_mailbox_cache_purge_init;
	ctx->ctx.v.run = cmd_mailbox_cache_purge_run;
	ctx->ctx.getopt_args = "";
	doveadm_print_init(DOVEADM_PRINT_TYPE_TABLE);
	return &ctx->ctx;
}

struct doveadm_cmd_ver2 doveadm_cmd_mailbox_cache_decision = {
	.name = "mailbox cache decision",
	.mail_cmd = cmd_mailbox_cache_decision_alloc,
	.usage = DOVEADM_CMD_MAIL_USAGE_PREFIX"--all --fields <fields> " \
			"--last-used <timestamp> --decision <decision> " \
			"<mailbox> [<mailbox> ... ]",
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_MAIL_COMMON
DOVEADM_CMD_PARAM('a', "all", CMD_PARAM_BOOL, 0)
DOVEADM_CMD_PARAM('f', "fieldstr", CMD_PARAM_STR, 0)
DOVEADM_CMD_PARAM('l', "last-used", CMD_PARAM_INT64, 0)
DOVEADM_CMD_PARAM('d', "decision", CMD_PARAM_STR, 0)
DOVEADM_CMD_PARAM('\0', "mailbox", CMD_PARAM_ARRAY, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAMS_END
};

struct doveadm_cmd_ver2 doveadm_cmd_mailbox_cache_remove = {
	.name = "mailbox cache remove",
	.mail_cmd = cmd_mailbox_cache_remove_alloc,
	.usage = DOVEADM_CMD_MAIL_USAGE_PREFIX"<search string>",
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_MAIL_COMMON
DOVEADM_CMD_PARAM('\0', "query", CMD_PARAM_ARRAY, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAMS_END
};

struct doveadm_cmd_ver2 doveadm_cmd_mailbox_cache_purge = {
	.name = "mailbox cache purge",
	.mail_cmd = cmd_mailbox_cache_purge_alloc,
	.usage = DOVEADM_CMD_MAIL_USAGE_PREFIX"<mailbox> [...]",
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_MAIL_COMMON
DOVEADM_CMD_PARAM('\0', "mailbox", CMD_PARAM_ARRAY, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAMS_END
};
