/* Copyright (c) 2010-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "mail-storage.h"
#include "mail-storage-service.h"
#include "mail-namespace.h"
#include "doveadm-mailbox-list-iter.h"
#include "doveadm-mail-iter.h"
#include "doveadm-mail.h"

struct import_cmd_context {
	struct doveadm_mail_cmd_context ctx;

	const char *src_location;
	const char *src_username;
	struct mail_user *src_user;
	const char *dest_parent;
	bool subscribe;
};

static const char *
convert_vname_separators(const char *vname, char src_sep, char dest_sep)
{
	string_t *str = t_str_new(128);

	for (; *vname != '\0'; vname++) {
		if (*vname == src_sep)
			str_append_c(str, dest_sep);
		else if (*vname == dest_sep)
			str_append_c(str, '_');
		else
			str_append_c(str, *vname);
	}
	return str_c(str);
}

static int
dest_mailbox_open_or_create(struct import_cmd_context *ctx,
			    struct mail_user *user,
			    const struct mailbox_info *info,
			    struct mailbox **box_r)
{
	struct mail_namespace *ns;
	struct mailbox *box;
	enum mail_error error;
	const char *name, *errstr;

	if (*ctx->dest_parent != '\0') {
		/* prefix destination mailbox name with given parent mailbox */
		ns = mail_namespace_find(user->namespaces, ctx->dest_parent);
	} else {
		ns = mail_namespace_find(user->namespaces, info->vname);
	}
	name = convert_vname_separators(info->vname,
					mail_namespace_get_sep(info->ns),
					mail_namespace_get_sep(ns));

	if (*ctx->dest_parent != '\0') {
		name = t_strdup_printf("%s%c%s", ctx->dest_parent,
				       mail_namespace_get_sep(ns), name);
	}

	box = mailbox_alloc(ns->list, name, MAILBOX_FLAG_SAVEONLY);
	mailbox_set_reason(box, ctx->ctx.cmd->name);
	if (mailbox_create(box, NULL, FALSE) < 0) {
		errstr = mailbox_get_last_internal_error(box, &error);
		if (error != MAIL_ERROR_EXISTS) {
			i_error("Couldn't create mailbox %s: %s", name, errstr);
			doveadm_mail_failed_mailbox(&ctx->ctx, box);
			mailbox_free(&box);
			return -1;
		}
	}
	if (ctx->subscribe) {
		if (mailbox_set_subscribed(box, TRUE) < 0) {
			i_error("Couldn't subscribe to mailbox %s: %s",
				name, mailbox_get_last_internal_error(box, NULL));
		}
	}
	if (mailbox_sync(box, MAILBOX_SYNC_FLAG_FULL_READ) < 0) {
		i_error("Syncing mailbox %s failed: %s", name,
			mailbox_get_last_internal_error(box, NULL));
		doveadm_mail_failed_mailbox(&ctx->ctx, box);
		mailbox_free(&box);
		return -1;
	}
	*box_r = box;
	return 0;
}

static int
cmd_import_box_contents(struct doveadm_mail_iter *iter, struct mail *src_mail,
			struct mailbox *dest_box)
{
	struct mail_save_context *save_ctx;
	struct mailbox_transaction_context *dest_trans;
	const char *mailbox = mailbox_get_vname(dest_box);
	int ret = 0;

	dest_trans = mailbox_transaction_begin(dest_box,
					MAILBOX_TRANSACTION_FLAG_EXTERNAL,
					__func__);
	do {
		if (doveadm_debug) {
			i_debug("import: box=%s uid=%u",
				mailbox, src_mail->uid);
		}
		save_ctx = mailbox_save_alloc(dest_trans);
		mailbox_save_copy_flags(save_ctx, src_mail);
		if (mailbox_copy(&save_ctx, src_mail) < 0) {
			i_error("Copying box=%s uid=%u failed: %s",
				mailbox, src_mail->uid,
				mailbox_get_last_internal_error(dest_box, NULL));
			ret = -1;
		}
	} while (doveadm_mail_iter_next(iter, &src_mail));

	if (mailbox_transaction_commit(&dest_trans) < 0) {
		i_error("Committing copied mails to %s failed: %s", mailbox,
			mailbox_get_last_internal_error(dest_box, NULL));
		ret = -1;
	}
	return ret;
}

static int
cmd_import_box(struct import_cmd_context *ctx, struct mail_user *dest_user,
	       const struct mailbox_info *info,
	       struct mail_search_args *search_args)
{
	struct doveadm_mail_iter *iter;
	struct mailbox *box;
	struct mail *mail;
	int ret = 0;

	if (doveadm_mail_iter_init(&ctx->ctx, info, search_args, 0, NULL, TRUE,
				   &iter) < 0)
		return -1;

	if (doveadm_mail_iter_next(iter, &mail)) {
		/* at least one mail matches in this mailbox */
		if (dest_mailbox_open_or_create(ctx, dest_user, info, &box) < 0)
			ret = -1;
		else {
			if (cmd_import_box_contents(iter, mail, box) < 0) {
				doveadm_mail_failed_mailbox(&ctx->ctx, mail->box);
				ret = -1;
			}
			mailbox_free(&box);
		}
	}
	if (doveadm_mail_iter_deinit_sync(&iter) < 0)
		ret = -1;
	return ret;
}

static void cmd_import_init_source_user(struct import_cmd_context *ctx, struct mail_user *dest_user)
{
	struct mail_storage_service_input input;
	struct mail_storage_service_user *service_user;
	struct mail_user *user;
	const char *error;

	/* create a user for accessing the source storage */
	i_zero(&input);
	input.module = "mail";
	input.username = ctx->src_username != NULL ?
			 ctx->src_username :
			 dest_user->username;

	input.flags_override_add = MAIL_STORAGE_SERVICE_FLAG_NO_NAMESPACES |
		MAIL_STORAGE_SERVICE_FLAG_NO_RESTRICT_ACCESS;
	if (mail_storage_service_lookup_next(ctx->ctx.storage_service, &input,
					     &service_user, &user, &error) < 0)
		i_fatal("Import user initialization failed: %s", error);
	if (mail_namespaces_init_location(user, ctx->src_location, &error) < 0)
		i_fatal("Import namespace initialization failed: %s", error);

	ctx->src_user = user;
	mail_storage_service_user_unref(&service_user);
}

static int
cmd_import_run(struct doveadm_mail_cmd_context *_ctx, struct mail_user *user)
{
	struct import_cmd_context *ctx = (struct import_cmd_context *)_ctx;
	const enum mailbox_list_iter_flags iter_flags =
		MAILBOX_LIST_ITER_NO_AUTO_BOXES |
		MAILBOX_LIST_ITER_RETURN_NO_FLAGS;
	struct doveadm_mailbox_list_iter *iter;
	const struct mailbox_info *info;
	int ret = 0;

	if (ctx->src_user == NULL)
		cmd_import_init_source_user(ctx, user);

	iter = doveadm_mailbox_list_iter_init(_ctx, ctx->src_user,
					      _ctx->search_args, iter_flags);
	while ((info = doveadm_mailbox_list_iter_next(iter)) != NULL) T_BEGIN {
		if (cmd_import_box(ctx, user, info, _ctx->search_args) < 0)
			ret = -1;
	} T_END;
	if (doveadm_mailbox_list_iter_deinit(&iter) < 0)
		ret = -1;
	return ret;
}

static void cmd_import_init(struct doveadm_mail_cmd_context *_ctx,
			    const char *const args[])
{
	struct import_cmd_context *ctx = (struct import_cmd_context *)_ctx;

	if (str_array_length(args) < 3)
		doveadm_mail_help_name("import");
	ctx->src_location = p_strdup(_ctx->pool, args[0]);
	ctx->dest_parent = p_strdup(_ctx->pool, args[1]);
	ctx->ctx.search_args = doveadm_mail_build_search_args(args+2);
}

static void cmd_import_deinit(struct doveadm_mail_cmd_context *_ctx)
{
	struct import_cmd_context *ctx = (struct import_cmd_context *)_ctx;

	if (ctx->src_user != NULL)
		mail_user_deinit(&ctx->src_user);
}

static bool cmd_import_parse_arg(struct doveadm_mail_cmd_context *_ctx, int c)
{
	struct import_cmd_context *ctx = (struct import_cmd_context *)_ctx;

	switch (c) {
	case 'U':
		ctx->src_username = p_strdup(_ctx->pool, optarg);
		break;
	case 's':
		ctx->subscribe = TRUE;
		break;
	default:
		return FALSE;
	}
	return TRUE;
}

static struct doveadm_mail_cmd_context *cmd_import_alloc(void)
{
	struct import_cmd_context *ctx;

	ctx = doveadm_mail_cmd_alloc(struct import_cmd_context);
	ctx->ctx.getopt_args = "s";
	ctx->ctx.v.parse_arg = cmd_import_parse_arg;
	ctx->ctx.v.init = cmd_import_init;
	ctx->ctx.v.deinit = cmd_import_deinit;
	ctx->ctx.v.run = cmd_import_run;
	return &ctx->ctx;
}

struct doveadm_cmd_ver2 doveadm_cmd_import_ver2 = {
	.name = "import",
	.mail_cmd = cmd_import_alloc,
	.usage = DOVEADM_CMD_MAIL_USAGE_PREFIX "[-U source-user] [-s] <source mail location> <dest parent mailbox> <search query>",
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_MAIL_COMMON
DOVEADM_CMD_PARAM('U', "source-user", CMD_PARAM_STR, 0)
DOVEADM_CMD_PARAM('s', "subscribe", CMD_PARAM_BOOL, 0)
DOVEADM_CMD_PARAM('\0', "source-location", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAM('\0', "dest-parent-mailbox", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAM('\0', "query", CMD_PARAM_ARRAY, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAMS_END
};
