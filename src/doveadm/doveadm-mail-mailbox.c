/* Copyright (c) 2010 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "mail-namespace.h"
#include "mail-storage.h"
#include "mail-search-build.h"
#include "doveadm-mail-list-iter.h"
#include "doveadm-mail.h"

#include <stdio.h>

struct mailbox_cmd_context {
	struct doveadm_mail_cmd_context ctx;
	ARRAY_TYPE(const_string) mailboxes;
};

struct rename_cmd_context {
	struct doveadm_mail_cmd_context ctx;
	const char *oldname, *newname;
};

struct list_cmd_context {
	struct doveadm_mail_cmd_context ctx;
	struct mail_search_args *search_args;
};

static void
cmd_mailbox_list_run(struct doveadm_mail_cmd_context *_ctx,
		     struct mail_user *user)
{
	struct list_cmd_context *ctx = (struct list_cmd_context *)_ctx;
	const enum mailbox_list_iter_flags iter_flags =
		MAILBOX_LIST_ITER_RAW_LIST |
		MAILBOX_LIST_ITER_VIRTUAL_NAMES |
		MAILBOX_LIST_ITER_NO_AUTO_INBOX |
		MAILBOX_LIST_ITER_RETURN_NO_FLAGS;
	struct doveadm_mail_list_iter *iter;
	const struct mailbox_info *info;

	iter = doveadm_mail_list_iter_init(user, ctx->search_args, iter_flags);
	while ((info = doveadm_mail_list_iter_next(iter)) != NULL) {
		printf("%s\n", info->name);
	}
	doveadm_mail_list_iter_deinit(&iter);
}

struct doveadm_mail_cmd_context *cmd_mailbox_list(const char *const args[])
{
	struct list_cmd_context *ctx;
	struct mail_search_arg *arg;
	unsigned int i;

	ctx = doveadm_mail_cmd_init(struct list_cmd_context);
	ctx->ctx.run = cmd_mailbox_list_run;

	ctx->search_args = mail_search_build_init();
	for (i = 0; args[i] != NULL; i++) {
		arg = mail_search_build_add(ctx->search_args,
					    SEARCH_MAILBOX_GLOB);
		arg->value.str = p_strdup(ctx->search_args->pool, args[i]);
	}
	if (i > 1) {
		struct mail_search_arg *subargs = ctx->search_args->args;

		ctx->search_args->args = NULL;
		arg = mail_search_build_add(ctx->search_args, SEARCH_OR);
		arg->value.subargs = subargs;
	}
	return &ctx->ctx;
}

static void
cmd_mailbox_create_run(struct doveadm_mail_cmd_context *_ctx,
		       struct mail_user *user)
{
	struct mailbox_cmd_context *ctx = (struct mailbox_cmd_context *)_ctx;
	struct mail_namespace *ns;
	struct mailbox *box;
	const char *const *namep;

	array_foreach(&ctx->mailboxes, namep) {
		const char *storage_name = *namep;
		unsigned int len;
		bool directory = FALSE;

		ns = mail_namespace_find(user->namespaces, &storage_name);
		if (ns == NULL)
			i_fatal("Can't find namespace for: %s", *namep);

		len = strlen(storage_name);
		if (len > 0 && storage_name[len-1] == ns->real_sep) {
			storage_name = t_strndup(storage_name, len-1);
			directory = TRUE;
		}

		box = mailbox_alloc(ns->list, storage_name, 0);
		if (mailbox_create(box, NULL, directory) < 0) {
			struct mail_storage *storage = mailbox_get_storage(box);

			i_error("Can't create mailbox %s: %s", *namep,
				mail_storage_get_last_error(storage, NULL));
		}
		mailbox_free(&box);
	}
}

struct doveadm_mail_cmd_context *cmd_mailbox_create(const char *const args[])
{
	struct mailbox_cmd_context *ctx;
	const char *name;
	unsigned int i;

	if (args[0] == NULL)
		doveadm_mail_help_name("mailbox create");

	ctx = doveadm_mail_cmd_init(struct mailbox_cmd_context);
	ctx->ctx.run = cmd_mailbox_create_run;
	p_array_init(&ctx->mailboxes, ctx->ctx.pool, 16);

	for (i = 0; args[i] != NULL; i++) {
		name = p_strdup(ctx->ctx.pool, args[i]);
		array_append(&ctx->mailboxes, &name, 1);
	}
	return &ctx->ctx;
}

static void
cmd_mailbox_delete_run(struct doveadm_mail_cmd_context *_ctx,
		       struct mail_user *user)
{
	struct mailbox_cmd_context *ctx = (struct mailbox_cmd_context *)_ctx;
	struct mail_namespace *ns;
	struct mailbox *box;
	const char *const *namep;

	array_foreach(&ctx->mailboxes, namep) {
		const char *storage_name = *namep;

		ns = mail_namespace_find(user->namespaces, &storage_name);
		if (ns == NULL)
			i_fatal("Can't find namespace for: %s", *namep);

		box = mailbox_alloc(ns->list, storage_name, 0);
		if (mailbox_delete(box) < 0) {
			struct mail_storage *storage = mailbox_get_storage(box);

			i_error("Can't delete mailbox %s: %s", *namep,
				mail_storage_get_last_error(storage, NULL));
		}
		mailbox_free(&box);
	}
}

struct doveadm_mail_cmd_context *cmd_mailbox_delete(const char *const args[])
{
	struct mailbox_cmd_context *ctx;
	const char *name;
	unsigned int i;

	if (args[0] == NULL)
		doveadm_mail_help_name("mailbox delete");

	ctx = doveadm_mail_cmd_init(struct mailbox_cmd_context);
	ctx->ctx.run = cmd_mailbox_delete_run;
	p_array_init(&ctx->mailboxes, ctx->ctx.pool, 16);

	for (i = 0; args[i] != NULL; i++) {
		name = p_strdup(ctx->ctx.pool, args[i]);
		array_append(&ctx->mailboxes, &name, 1);
	}
	return &ctx->ctx;
}

static void
cmd_mailbox_rename_run(struct doveadm_mail_cmd_context *_ctx,
		       struct mail_user *user)
{
	struct rename_cmd_context *ctx = (struct rename_cmd_context *)_ctx;
	struct mail_namespace *oldns, *newns;
	struct mailbox *oldbox, *newbox;
	const char *oldname = ctx->oldname;
	const char *newname = ctx->newname;

	oldns = mail_namespace_find(user->namespaces, &oldname);
	if (oldns == NULL)
		i_fatal("Can't find namespace for: %s", oldname);
	newns = mail_namespace_find(user->namespaces, &newname);
	if (newns == NULL)
		i_fatal("Can't find namespace for: %s", newname);

	oldbox = mailbox_alloc(oldns->list, oldname, 0);
	newbox = mailbox_alloc(newns->list, newname, 0);
	if (mailbox_rename(oldbox, newbox, TRUE) < 0) {
		struct mail_storage *storage = mailbox_get_storage(oldbox);

		i_error("Can't rename mailbox %s to %s: %s", oldname, newname,
			mail_storage_get_last_error(storage, NULL));
	}
	mailbox_free(&oldbox);
	mailbox_free(&newbox);
}

struct doveadm_mail_cmd_context *cmd_mailbox_rename(const char *const args[])
{
	struct rename_cmd_context *ctx;

	if (str_array_length(args) != 2)
		doveadm_mail_help_name("mailbox rename");

	ctx = doveadm_mail_cmd_init(struct rename_cmd_context);
	ctx->ctx.run = cmd_mailbox_rename_run;

	ctx->oldname = p_strdup(ctx->ctx.pool, args[0]);
	ctx->newname = p_strdup(ctx->ctx.pool, args[1]);
	return &ctx->ctx;
}
