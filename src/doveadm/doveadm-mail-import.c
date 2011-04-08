/* Copyright (c) 2010-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "mail-storage.h"
#include "mail-storage-service.h"
#include "mail-namespace.h"
#include "doveadm-mail-list-iter.h"
#include "doveadm-mail-iter.h"
#include "doveadm-mail.h"

struct import_cmd_context {
	struct doveadm_mail_cmd_context ctx;

	struct mail_user *src_user;
	const char *dest_parent;
};

static int
dest_mailbox_open_or_create(struct import_cmd_context *ctx,
			    struct mail_user *user, const char *name,
			    struct mailbox **box_r)
{
	struct mail_namespace *ns;
	struct mailbox *box;
	enum mail_error error;
	const char *errstr, *storage_name;

	if (*ctx->dest_parent != '\0') {
		/* prefix destination mailbox name with given parent mailbox */
		storage_name = ctx->dest_parent;
		ns = mail_namespace_find(user->namespaces, &storage_name);
		if (ns == NULL) {
			i_error("Can't find namespace for parent mailbox %s",
				ctx->dest_parent);
			return -1;
		}
		name = t_strdup_printf("%s%c%s", ctx->dest_parent,
				       ns->sep, name);
	}

	storage_name = name;
	ns = mail_namespace_find(user->namespaces, &storage_name);
	if (ns == NULL) {
		i_error("Can't find namespace for mailbox %s", name);
		return -1;
	}

	box = mailbox_alloc(ns->list, storage_name, MAILBOX_FLAG_SAVEONLY |
			    MAILBOX_FLAG_KEEP_RECENT);
	if (mailbox_create(box, NULL, FALSE) < 0) {
		errstr = mail_storage_get_last_error(mailbox_get_storage(box),
						     &error);
		if (error != MAIL_ERROR_EXISTS) {
			i_error("Couldn't create mailbox %s: %s", name, errstr);
			mailbox_free(&box);
			return -1;
		}
	}
	if (mailbox_sync(box, MAILBOX_SYNC_FLAG_FULL_READ) < 0) {
		i_error("Syncing mailbox %s failed: %s", name,
			mail_storage_get_last_error(mailbox_get_storage(box),
						    NULL));
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
	struct mail_storage *dest_storage = mailbox_get_storage(dest_box);
	struct mail_save_context *save_ctx;
	struct mailbox_transaction_context *dest_trans;
	const char *mailbox = mailbox_get_vname(dest_box);
	int ret = 0;

	dest_trans = mailbox_transaction_begin(dest_box,
				MAILBOX_TRANSACTION_FLAG_EXTERNAL);
	do {
		if (doveadm_debug) {
			i_debug("import: box=%s uid=%u",
				mailbox, src_mail->uid);
		}
		save_ctx = mailbox_save_alloc(dest_trans);
		if (mailbox_copy(&save_ctx, src_mail) < 0) {
			i_error("Copying box=%s uid=%u failed: %s",
				mailbox, src_mail->uid,
				mail_storage_get_last_error(dest_storage, NULL));
			ret = -1;
		}
	} while (doveadm_mail_iter_next(iter, src_mail));

	if (mailbox_transaction_commit(&dest_trans) < 0) {
		i_error("Committing copied mails to %s failed: %s", mailbox,
			mail_storage_get_last_error(dest_storage, NULL));
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
	struct mailbox_transaction_context *trans;
	struct mailbox *box;
	struct mail *mail;
	int ret = 0;

	if (doveadm_mail_iter_init(info, search_args, &trans, &iter) < 0)
		return -1;

	mail = mail_alloc(trans, 0, NULL);
	if (doveadm_mail_iter_next(iter, mail)) {
		/* at least one mail matches in this mailbox */
		if (dest_mailbox_open_or_create(ctx, dest_user, info->name,
						&box) == 0) {
			if (cmd_import_box_contents(iter, mail, box) < 0)
				ret = -1;
			mailbox_free(&box);
		}
	}
	mail_free(&mail);
	if (doveadm_mail_iter_deinit_sync(&iter) < 0)
		ret = -1;
	return ret;
}

static void
cmd_import_run(struct doveadm_mail_cmd_context *_ctx, struct mail_user *user)
{
	struct import_cmd_context *ctx = (struct import_cmd_context *)_ctx;
	const enum mailbox_list_iter_flags iter_flags =
		MAILBOX_LIST_ITER_RAW_LIST |
		MAILBOX_LIST_ITER_NO_AUTO_INBOX |
		MAILBOX_LIST_ITER_RETURN_NO_FLAGS;
	struct doveadm_mail_list_iter *iter;
	const struct mailbox_info *info;

	iter = doveadm_mail_list_iter_init(ctx->src_user,
					   _ctx->search_args, iter_flags);
	while ((info = doveadm_mail_list_iter_next(iter)) != NULL) T_BEGIN {
		(void)cmd_import_box(ctx, user, info, _ctx->search_args);
	} T_END;
	doveadm_mail_list_iter_deinit(&iter);
}

static void cmd_import_init(struct doveadm_mail_cmd_context *_ctx,
			    const char *const args[])
{
	struct import_cmd_context *ctx = (struct import_cmd_context *)_ctx;
	struct mail_storage_service_input input;
	struct mail_storage_service_user *service_user;
	struct mail_user *user;
	const char *src_location, *error;

	if (str_array_length(args) < 3)
		doveadm_mail_help_name("import");
	src_location = args[0];
	ctx->dest_parent = p_strdup(_ctx->pool, args[1]);
	ctx->ctx.search_args = doveadm_mail_build_search_args(args+2);

	/* create a user for accessing the source storage */
	memset(&input, 0, sizeof(input));
	input.module = "mail";
	input.username = "doveadm";
	input.flags_override_add = MAIL_STORAGE_SERVICE_FLAG_NO_NAMESPACES |
		MAIL_STORAGE_SERVICE_FLAG_NO_RESTRICT_ACCESS;
	input.flags_override_remove = MAIL_STORAGE_SERVICE_FLAG_USERDB_LOOKUP;
	if (mail_storage_service_lookup_next(ctx->ctx.storage_service, &input,
					     &service_user, &user, &error) < 0)
		i_fatal("Import user initialization failed: %s", error);
	if (mail_namespaces_init_location(user, src_location, &error) < 0)
		i_fatal("Import namespace initialization failed: %s", error);

	ctx->src_user = user;
	mail_storage_service_user_free(&service_user);
}

static void cmd_import_deinit(struct doveadm_mail_cmd_context *_ctx)
{
	struct import_cmd_context *ctx = (struct import_cmd_context *)_ctx;

	mail_user_unref(&ctx->src_user);
}

static struct doveadm_mail_cmd_context *cmd_import_alloc(void)
{
	struct import_cmd_context *ctx;

	ctx = doveadm_mail_cmd_alloc(struct import_cmd_context);
	ctx->ctx.v.init = cmd_import_init;
	ctx->ctx.v.deinit = cmd_import_deinit;
	ctx->ctx.v.run = cmd_import_run;
	return &ctx->ctx;
}

struct doveadm_mail_cmd cmd_import = {
	cmd_import_alloc, "import",
	"<source mail location> <dest parent mailbox> <search query>"
};
