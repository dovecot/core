/* Copyright (c) 2014-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "istream.h"
#include "mail-namespace.h"
#include "mail-storage.h"
#include "doveadm-print.h"
#include "doveadm-mail.h"
#include "doveadm-mailbox-list-iter.h"
#include "imap-metadata.h"

enum doveadm_metadata_op {
	DOVEADM_METADATA_OP_SET = 0,
	DOVEADM_METADATA_OP_GET,
	DOVEADM_METADATA_OP_LIST,
};

const char *doveadm_metadata_op_names[] = {
	"set attribute",
	"get attribute",
	"list attribute",
};

struct metadata_cmd_context {
	struct doveadm_mail_cmd_context ctx;
	const char *mailbox;
	enum mail_attribute_type key_type;
	const char *key;
	struct mail_attribute_value value;
	bool empty_mailbox_name;
	bool allow_empty_mailbox_name;
	bool prepend_prefix;
};

static int
cmd_mailbox_metadata_get_mailbox(struct metadata_cmd_context *mctx,
				  struct mail_user *user,
				  enum doveadm_metadata_op op,
				  struct mail_namespace **ns_r,
				  struct mailbox **box_r)
{
	mctx->empty_mailbox_name = mctx->mailbox[0] == '\0';

	if (mctx->empty_mailbox_name) {
		if (!mctx->allow_empty_mailbox_name) {
			const char *op_str = doveadm_metadata_op_names[op];
			e_error(mctx->ctx.cctx->event, "Failed to %s: %s", op_str,
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

	if (op == DOVEADM_METADATA_OP_SET &&
	    mailbox_open(*box_r) < 0) {
		e_error(mctx->ctx.cctx->event, "Failed to open mailbox: %s",
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
	struct metadata_cmd_context *ctx =
		container_of(_ctx, struct metadata_cmd_context, ctx);

	struct mail_namespace *ns;
	struct mailbox *box;
	struct mailbox_transaction_context *trans;
	int ret;

	ret = cmd_mailbox_metadata_get_mailbox(ctx, user, DOVEADM_METADATA_OP_SET,
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
		e_error(ctx->ctx.cctx->event, "Failed to set attribute: %s",
			mailbox_get_last_internal_error(box, NULL));
		doveadm_mail_failed_mailbox(_ctx, box);
		mailbox_transaction_rollback(&trans);
	} else if (mailbox_transaction_commit(&trans) < 0) {
		e_error(ctx->ctx.cctx->event, "Failed to commit transaction: %s",
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

	if (str_begins(arg, "/private/", key_r)) {
		*type_r = MAIL_ATTRIBUTE_TYPE_PRIVATE;
	} else if (str_begins(arg, "/shared/", key_r)) {
		*type_r = MAIL_ATTRIBUTE_TYPE_SHARED;
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
parse_args_common(struct doveadm_mail_cmd_context *_ctx)
{
	struct doveadm_cmd_context *cctx = _ctx->cctx;
	struct metadata_cmd_context *ctx =
		container_of(_ctx, struct metadata_cmd_context, ctx);

	ctx->allow_empty_mailbox_name =
		doveadm_cmd_param_flag(cctx, "allow-empty-mailbox-name");
	ctx->prepend_prefix = doveadm_cmd_param_flag(cctx, "prepend-prefix");
}

static bool
parse_args_key(struct doveadm_mail_cmd_context *_ctx,
				    const char *field, const char **value_r)
{
	struct doveadm_cmd_context *cctx = _ctx->cctx;
	struct metadata_cmd_context *ctx =
		container_of(_ctx, struct metadata_cmd_context, ctx);

	const char *value;
	*value_r = "";
	bool found = doveadm_cmd_param_str(cctx, field, &value);
	if (found) {
		const char *parsed;
		cmd_mailbox_metadata_parse_key(value, &ctx->key_type, &parsed);
		*value_r = p_strdup(_ctx->pool, parsed);
	}
	return found;
}

static void
cmd_mailbox_metadata_set_init(struct doveadm_mail_cmd_context *_ctx)
{
	struct doveadm_cmd_context *cctx = _ctx->cctx;
	struct metadata_cmd_context *ctx =
		container_of(_ctx, struct metadata_cmd_context, ctx);

	parse_args_common(_ctx);
	if (!doveadm_cmd_param_str(cctx, "mailbox", &ctx->mailbox) ||
	    !parse_args_key(_ctx, "key", &ctx->key) ||
	    !doveadm_cmd_param_str(cctx, "value", &ctx->value.value))
		doveadm_mail_help_name("mailbox metadata set");
}

static struct doveadm_mail_cmd_context *cmd_mailbox_metadata_set_alloc(void)
{
	struct metadata_cmd_context *ctx;

	ctx = doveadm_mail_cmd_alloc(struct metadata_cmd_context);
	ctx->ctx.v.init = cmd_mailbox_metadata_set_init;
	ctx->ctx.v.run = cmd_mailbox_metadata_set_run;
	return &ctx->ctx;
}

static void
cmd_mailbox_metadata_unset_init(struct doveadm_mail_cmd_context *_ctx)
{
	struct doveadm_cmd_context *cctx = _ctx->cctx;
	struct metadata_cmd_context *ctx =
		container_of(_ctx, struct metadata_cmd_context, ctx);

	parse_args_common(_ctx);
	if (!doveadm_cmd_param_str(cctx, "mailbox", &ctx->mailbox) ||
	    !parse_args_key(_ctx, "key", &ctx->key))
		doveadm_mail_help_name("mailbox metadata unset");
}

static struct doveadm_mail_cmd_context *cmd_mailbox_metadata_unset_alloc(void)
{
	struct metadata_cmd_context *ctx;

	ctx = doveadm_mail_cmd_alloc(struct metadata_cmd_context);
	ctx->ctx.v.init = cmd_mailbox_metadata_unset_init;
	ctx->ctx.v.run = cmd_mailbox_metadata_set_run;
	return &ctx->ctx;
}

static int
cmd_mailbox_metadata_get_run(struct doveadm_mail_cmd_context *_ctx,
			     struct mail_user *user)
{
	struct metadata_cmd_context *ctx =
		container_of(_ctx, struct metadata_cmd_context, ctx);

	struct mail_namespace *ns;
	struct mailbox *box;
	struct mail_attribute_value value;
	int ret;

	ret = cmd_mailbox_metadata_get_mailbox(ctx, user, DOVEADM_METADATA_OP_GET,
						&ns, &box);
	if (ret != 0)
		return ret;

	ret = mailbox_attribute_get_stream(box, ctx->key_type, ctx->key, &value);
	if (ret < 0) {
		e_error(ctx->ctx.cctx->event, "Failed to get attribute: %s",
			mailbox_get_last_internal_error(box, NULL));
		doveadm_mail_failed_mailbox(_ctx, box);
	} else if (ret == 0) {
		/* not found, print as empty */
		doveadm_print("");
	} else if (value.value_stream != NULL) {
		if (doveadm_print_istream(value.value_stream) < 0) {
			e_error(ctx->ctx.cctx->event, "read(%s) failed: %s",
				i_stream_get_name(value.value_stream),
				i_stream_get_error(value.value_stream));
			ret = -1;
		}
	} else {
		doveadm_print(value.value);
	}

	mailbox_free(&box);
	return ret;
}

static void
cmd_mailbox_metadata_get_init(struct doveadm_mail_cmd_context *_ctx)
{
	struct doveadm_cmd_context *cctx = _ctx->cctx;
	struct metadata_cmd_context *ctx =
		container_of(_ctx, struct metadata_cmd_context, ctx);

	parse_args_common(_ctx);
	if (!doveadm_cmd_param_str(cctx, "mailbox", &ctx->mailbox) ||
	    !parse_args_key(_ctx, "key", &ctx->key))
		doveadm_mail_help_name("mailbox metadata get");

	doveadm_print_header("value", "value",
			     DOVEADM_PRINT_HEADER_FLAG_HIDE_TITLE);
}

static struct doveadm_mail_cmd_context *cmd_mailbox_metadata_get_alloc(void)
{
	struct metadata_cmd_context *ctx;

	ctx = doveadm_mail_cmd_alloc(struct metadata_cmd_context);
	ctx->ctx.v.init = cmd_mailbox_metadata_get_init;
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
	string_t *outp = t_str_new(64);

	iter = mailbox_attribute_iter_init(box, type, ctx->key);
	while ((key = mailbox_attribute_iter_next(iter)) != NULL) {
		if (ctx->prepend_prefix) {
			if (type == MAIL_ATTRIBUTE_TYPE_PRIVATE)
				str_append(outp, IMAP_METADATA_PRIVATE_PREFIX"/");
			else if (type == MAIL_ATTRIBUTE_TYPE_SHARED)
				str_append(outp, IMAP_METADATA_SHARED_PREFIX"/");
			else
				i_unreached();
			str_append(outp, key);
			doveadm_print(str_c(outp));
			str_truncate(outp, 0);
		} else {
			doveadm_print(key);
		}
	}
	if (mailbox_attribute_iter_deinit(&iter) < 0) {
		e_error(ctx->ctx.cctx->event, "Mailbox %s: Failed to iterate mailbox attributes: %s",
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
	struct metadata_cmd_context *ctx =
		container_of(_ctx, struct metadata_cmd_context, ctx);

	struct mail_namespace *ns;
	struct mailbox *box;
	int ret = 0;

	ret = cmd_mailbox_metadata_get_mailbox(ctx, user, DOVEADM_METADATA_OP_LIST,
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
cmd_mailbox_metadata_list_init(struct doveadm_mail_cmd_context *_ctx)
{
	struct doveadm_cmd_context *cctx = _ctx->cctx;
	struct metadata_cmd_context *ctx =
		container_of(_ctx, struct metadata_cmd_context, ctx);

	parse_args_common(_ctx);
	if (!doveadm_cmd_param_str(cctx, "mailbox", &ctx->mailbox))
		doveadm_mail_help_name("mailbox metadata list");
	parse_args_key(_ctx, "key-prefix", &ctx->key);

	doveadm_print_header("key", "key",
			     DOVEADM_PRINT_HEADER_FLAG_HIDE_TITLE);
}

static struct doveadm_mail_cmd_context *cmd_mailbox_metadata_list_alloc(void)
{
	struct metadata_cmd_context *ctx;

	ctx = doveadm_mail_cmd_alloc(struct metadata_cmd_context);
	ctx->ctx.v.init = cmd_mailbox_metadata_list_init;
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
	.usage = DOVEADM_CMD_MAIL_USAGE_PREFIX"[-s] [-p] <mailbox> [<key prefix>]",
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_MAIL_COMMON
DOVEADM_CMD_PARAM('s', "allow-empty-mailbox-name", CMD_PARAM_BOOL, 0)
DOVEADM_CMD_PARAM('p', "prepend-prefix", CMD_PARAM_BOOL, 0)
DOVEADM_CMD_PARAM('\0', "mailbox", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAM('\0', "key-prefix", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAMS_END
};
