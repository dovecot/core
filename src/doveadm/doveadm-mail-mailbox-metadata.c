/* Copyright (c) 2014-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "mail-namespace.h"
#include "mail-storage.h"
#include "doveadm-print.h"
#include "doveadm-mail.h"
#include "doveadm-mailbox-list-iter.h"

struct metadata_cmd_context {
	struct doveadm_mail_cmd_context ctx;
	const char *mailbox;
	enum mail_attribute_type key_type;
	const char *key;
	struct mail_attribute_value value;
	bool empty_mailbox_name;
	bool allow_empty_mailbox_name;
};

static int
cmd_mailbox_metadata_open_mailbox(struct metadata_cmd_context *mctx,
				  struct mail_user *user,
				  const char *op,
				  struct mail_namespace **ns_r,
				  struct mailbox **box_r)
{
	mctx->empty_mailbox_name = mctx->mailbox[0] == '\0';

	if (mctx->empty_mailbox_name) {
		if (!mctx->allow_empty_mailbox_name) {
			i_error("Failed to %s: %s", op,
				"mailbox name cannot be empty");
			mctx->ctx.exit_code = EX_USAGE;
			return -1;
		}

		/* Server attribute. It shouldn't depend on INBOX's ACLs,
		   so ignore them. */
		*ns_r = mail_namespace_find_inbox(user->namespaces);
		*box_r = mailbox_alloc((*ns_r)->list, "INBOX",
				       MAILBOX_FLAG_IGNORE_ACLS |
				       MAILBOX_FLAG_ATTRIBUTE_SESSION);

		mctx->key = t_strconcat(MAILBOX_ATTRIBUTE_PREFIX_DOVECOT_PVT_SERVER,
					mctx->key, NULL);
	} else {
		/* mailbox attributes */
		*ns_r = mail_namespace_find(user->namespaces, mctx->mailbox);
		*box_r = mailbox_alloc((*ns_r)->list, mctx->mailbox,
				       MAILBOX_FLAG_ATTRIBUTE_SESSION);
	}
	mailbox_set_reason(*box_r, mctx->ctx.cmd->name);

	if (mailbox_open(*box_r) < 0) {
		i_error("Failed to open mailbox: %s",
			mailbox_get_last_internal_error(*box_r, NULL));
		doveadm_mail_failed_mailbox(&mctx->ctx, *box_r);
		mailbox_free(box_r);
		return -1;
	}

	return 0;
}

static int
cmd_mailbox_metadata_set_run(struct doveadm_mail_cmd_context *_ctx,
			     struct mail_user *user)
{
	struct metadata_cmd_context *ctx = (struct metadata_cmd_context *)_ctx;
	struct mail_namespace *ns;
	struct mailbox *box;
	struct mailbox_transaction_context *trans;
	int ret;

	ret = cmd_mailbox_metadata_open_mailbox(ctx, user, "set attribute",
						&ns, &box);
	if (ret != 0)
		return ret;

	trans = mailbox_transaction_begin(box, (ctx->empty_mailbox_name ?
					  MAILBOX_TRANSACTION_FLAG_EXTERNAL : 0) |
					  ctx->ctx.transaction_flags, __func__);

	ret = ctx->value.value == NULL ?
		mailbox_attribute_unset(trans, ctx->key_type, ctx->key) :
		mailbox_attribute_set(trans, ctx->key_type, ctx->key, &ctx->value);
	if (ret < 0) {
		i_error("Failed to set attribute: %s",
			mailbox_get_last_internal_error(box, NULL));
		doveadm_mail_failed_mailbox(_ctx, box);
		mailbox_transaction_rollback(&trans);
	} else if (mailbox_transaction_commit(&trans) < 0) {
		i_error("Failed to commit transaction: %s",
			mailbox_get_last_internal_error(box, NULL));
		doveadm_mail_failed_mailbox(_ctx, box);
		ret = -1;
	}

	mailbox_free(&box);
	return ret;
}

static void
cmd_mailbox_metadata_parse_key(const char *arg,
			       enum mail_attribute_type *type_r,
			       const char **key_r)
{
	arg = t_str_lcase(arg);

	if (str_begins(arg, "/private/")) {
		*type_r = MAIL_ATTRIBUTE_TYPE_PRIVATE;
		*key_r = arg + 9;
	} else if (str_begins(arg, "/shared/")) {
		*type_r = MAIL_ATTRIBUTE_TYPE_SHARED;
		*key_r = arg + 8;
	} else if (strcmp(arg, "/private") == 0) {
		*type_r = MAIL_ATTRIBUTE_TYPE_PRIVATE;
		*key_r = "";
	} else if (strcmp(arg, "/shared") == 0) {
		*type_r = MAIL_ATTRIBUTE_TYPE_SHARED;
		*key_r = "";
	} else {
		i_fatal_status(EX_USAGE, "Invalid metadata key '%s': "
			       "Must begin with /private or /shared", arg);
	}
}

static void
cmd_mailbox_metadata_set_init(struct doveadm_mail_cmd_context *_ctx,
			      const char *const args[])
{
	struct metadata_cmd_context *ctx = (struct metadata_cmd_context *)_ctx;
	const char *key;

	if (str_array_length(args) != 3)
		doveadm_mail_help_name("mailbox metadata set");
	cmd_mailbox_metadata_parse_key(args[1], &ctx->key_type, &key);

	ctx->mailbox = p_strdup(_ctx->pool, args[0]);
	ctx->key = p_strdup(_ctx->pool, key);
	ctx->value.value = p_strdup(_ctx->pool, args[2]);
}

static bool
cmd_mailbox_metadata_parse_arg(struct doveadm_mail_cmd_context *_ctx, int c)
{
	struct metadata_cmd_context *ctx =
		(struct metadata_cmd_context *)_ctx;

	switch (c) {
	case 's':
		ctx->allow_empty_mailbox_name = TRUE;
		break;
	default:
		return FALSE;
	}
	return TRUE;
}

static struct doveadm_mail_cmd_context *cmd_mailbox_metadata_set_alloc(void)
{
	struct metadata_cmd_context *ctx;

	ctx = doveadm_mail_cmd_alloc(struct metadata_cmd_context);
	ctx->ctx.v.init = cmd_mailbox_metadata_set_init;
	ctx->ctx.v.parse_arg = cmd_mailbox_metadata_parse_arg;
	ctx->ctx.v.run = cmd_mailbox_metadata_set_run;
	return &ctx->ctx;
}

static void
cmd_mailbox_metadata_unset_init(struct doveadm_mail_cmd_context *_ctx,
				const char *const args[])
{
	struct metadata_cmd_context *ctx = (struct metadata_cmd_context *)_ctx;
	const char *key;

	if (str_array_length(args) != 2)
		doveadm_mail_help_name("mailbox metadata unset");
	cmd_mailbox_metadata_parse_key(args[1], &ctx->key_type, &key);

	ctx->mailbox = p_strdup(_ctx->pool, args[0]);
	ctx->key = p_strdup(_ctx->pool, key);
}

static struct doveadm_mail_cmd_context *cmd_mailbox_metadata_unset_alloc(void)
{
	struct metadata_cmd_context *ctx;

	ctx = doveadm_mail_cmd_alloc(struct metadata_cmd_context);
	ctx->ctx.v.init = cmd_mailbox_metadata_unset_init;
	ctx->ctx.v.parse_arg = cmd_mailbox_metadata_parse_arg;
	ctx->ctx.v.run = cmd_mailbox_metadata_set_run;
	return &ctx->ctx;
}

static int
cmd_mailbox_metadata_get_run(struct doveadm_mail_cmd_context *_ctx,
			     struct mail_user *user)
{
	struct metadata_cmd_context *ctx = (struct metadata_cmd_context *)_ctx;
	struct mail_namespace *ns;
	struct mailbox *box;
	struct mail_attribute_value value;
	int ret;

	ret = cmd_mailbox_metadata_open_mailbox(ctx, user, "get attribute",
						&ns, &box);
	if (ret != 0)
		return ret;

	ret = mailbox_attribute_get_stream(box, ctx->key_type, ctx->key, &value);
	if (ret < 0) {
		i_error("Failed to get attribute: %s",
			mailbox_get_last_internal_error(box, NULL));
		doveadm_mail_failed_mailbox(_ctx, box);
	} else if (ret == 0) {
		/* not found, print as empty */
		doveadm_print("");
	} else if (value.value_stream != NULL) {
		doveadm_print_istream(value.value_stream);
	} else {
		doveadm_print(value.value);
	}

	mailbox_free(&box);
	return ret;
}

static void
cmd_mailbox_metadata_get_init(struct doveadm_mail_cmd_context *_ctx,
			      const char *const args[])
{
	struct metadata_cmd_context *ctx = (struct metadata_cmd_context *)_ctx;
	const char *key;

	if (str_array_length(args) != 2)
		doveadm_mail_help_name("mailbox metadata get");
	cmd_mailbox_metadata_parse_key(args[1], &ctx->key_type, &key);

	ctx->mailbox = p_strdup(_ctx->pool, args[0]);
	ctx->key = p_strdup(_ctx->pool, key);
	doveadm_print_header("value", "value",
			     DOVEADM_PRINT_HEADER_FLAG_HIDE_TITLE);
}

static struct doveadm_mail_cmd_context *cmd_mailbox_metadata_get_alloc(void)
{
	struct metadata_cmd_context *ctx;

	ctx = doveadm_mail_cmd_alloc(struct metadata_cmd_context);
	ctx->ctx.v.init = cmd_mailbox_metadata_get_init;
	ctx->ctx.v.parse_arg = cmd_mailbox_metadata_parse_arg;
	ctx->ctx.v.run = cmd_mailbox_metadata_get_run;
	doveadm_print_init(DOVEADM_PRINT_TYPE_FLOW);
	return &ctx->ctx;
}

static int
cmd_mailbox_metadata_list_run_iter(struct metadata_cmd_context *ctx,
				   struct mailbox *box,
				   enum mail_attribute_type type)
{
	struct mailbox_attribute_iter *iter;
	const char *key;

	iter = mailbox_attribute_iter_init(box, type, ctx->key);
	while ((key = mailbox_attribute_iter_next(iter)) != NULL)
		doveadm_print(key);
	if (mailbox_attribute_iter_deinit(&iter) < 0) {
		i_error("Mailbox %s: Failed to iterate mailbox attributes: %s",
			mailbox_get_vname(box),
			mailbox_get_last_internal_error(box, NULL));
		return -1;
	}
	return 0;
}

static int
cmd_mailbox_metadata_list_run(struct doveadm_mail_cmd_context *_ctx,
			      struct mail_user *user)
{
	struct metadata_cmd_context *ctx = (struct metadata_cmd_context *)_ctx;
	struct mail_namespace *ns;
	struct mailbox *box;
	int ret = 0;

	ret = cmd_mailbox_metadata_open_mailbox(ctx, user, "list attributes",
						&ns, &box);
	if (ret != 0)
		return ret;

	if (ctx->key[0] == '\0' || ctx->key_type == MAIL_ATTRIBUTE_TYPE_PRIVATE) {
		if (cmd_mailbox_metadata_list_run_iter(ctx, box, MAIL_ATTRIBUTE_TYPE_PRIVATE) < 0) {
			doveadm_mail_failed_mailbox(_ctx, box);
			ret = -1;
		}
	}
	if (ctx->key[0] == '\0' || ctx->key_type == MAIL_ATTRIBUTE_TYPE_SHARED) {
		if (cmd_mailbox_metadata_list_run_iter(ctx, box, MAIL_ATTRIBUTE_TYPE_SHARED) < 0) {
			doveadm_mail_failed_mailbox(_ctx, box);
			ret = -1;
		}
	}
	mailbox_free(&box);
	return ret;
}

static void
cmd_mailbox_metadata_list_init(struct doveadm_mail_cmd_context *_ctx,
			       const char *const args[])
{
	struct metadata_cmd_context *ctx = (struct metadata_cmd_context *)_ctx;
	const char *key = NULL;

	if (args[0] == NULL)
		doveadm_mail_help_name("mailbox metadata list");
	if (args[1] != NULL)
		cmd_mailbox_metadata_parse_key(args[1], &ctx->key_type, &key);
	ctx->mailbox = p_strdup(_ctx->pool, args[0]);
	ctx->key = key == NULL ? "" : p_strdup(_ctx->pool, key);
	doveadm_print_header("key", "key",
			     DOVEADM_PRINT_HEADER_FLAG_HIDE_TITLE);
}

static struct doveadm_mail_cmd_context *cmd_mailbox_metadata_list_alloc(void)
{
	struct metadata_cmd_context *ctx;

	ctx = doveadm_mail_cmd_alloc(struct metadata_cmd_context);
	ctx->ctx.v.init = cmd_mailbox_metadata_list_init;
	ctx->ctx.v.parse_arg = cmd_mailbox_metadata_parse_arg;
	ctx->ctx.v.run = cmd_mailbox_metadata_list_run;
	doveadm_print_init(DOVEADM_PRINT_TYPE_FLOW);
	return &ctx->ctx;
}

struct doveadm_cmd_ver2 doveadm_cmd_mailbox_metadata_set_ver2 = {
	.name = "mailbox metadata set",
	.mail_cmd = cmd_mailbox_metadata_set_alloc,
	.usage = DOVEADM_CMD_MAIL_USAGE_PREFIX"[-s] <mailbox> <key> <value>",
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_MAIL_COMMON
DOVEADM_CMD_PARAM('s', "allow-empty-mailbox-name", CMD_PARAM_BOOL, 0)
DOVEADM_CMD_PARAM('\0', "mailbox", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAM('\0', "key", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAM('\0', "value", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAMS_END
};

struct doveadm_cmd_ver2 doveadm_cmd_mailbox_metadata_unset_ver2 = {
	.name = "mailbox metadata unset",
	.mail_cmd = cmd_mailbox_metadata_unset_alloc,
	.usage = DOVEADM_CMD_MAIL_USAGE_PREFIX"[-s] <mailbox> <key>",
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_MAIL_COMMON
DOVEADM_CMD_PARAM('s', "allow-empty-mailbox-name", CMD_PARAM_BOOL, 0)
DOVEADM_CMD_PARAM('\0', "mailbox", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAM('\0', "key", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAMS_END
};

struct doveadm_cmd_ver2 doveadm_cmd_mailbox_metadata_get_ver2 = {
	.name = "mailbox metadata get",
	.mail_cmd = cmd_mailbox_metadata_get_alloc,
	.usage = DOVEADM_CMD_MAIL_USAGE_PREFIX"[-s] <mailbox> <key>",
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_MAIL_COMMON
DOVEADM_CMD_PARAM('s', "allow-empty-mailbox-name", CMD_PARAM_BOOL, 0)
DOVEADM_CMD_PARAM('\0', "mailbox", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAM('\0', "key", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAMS_END
};

struct doveadm_cmd_ver2 doveadm_cmd_mailbox_metadata_list_ver2 = {
	.name = "mailbox metadata list",
	.mail_cmd = cmd_mailbox_metadata_list_alloc,
	.usage = DOVEADM_CMD_MAIL_USAGE_PREFIX"[-s] <mailbox> [<key prefix>]",
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_MAIL_COMMON
DOVEADM_CMD_PARAM('s', "allow-empty-mailbox-name", CMD_PARAM_BOOL, 0)
DOVEADM_CMD_PARAM('\0', "mailbox", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAM('\0', "key-prefix", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAMS_END
};
