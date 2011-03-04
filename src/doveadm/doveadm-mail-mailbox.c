/* Copyright (c) 2010-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "imap-utf7.h"
#include "mail-namespace.h"
#include "mail-storage.h"
#include "mail-search-build.h"
#include "doveadm-print.h"
#include "doveadm-mail-list-iter.h"
#include "doveadm-mail.h"

#include <stdio.h>

struct doveadm_mailbox_cmd_context {
	struct doveadm_mail_cmd_context ctx;
	bool subscriptions;
};

struct mailbox_cmd_context {
	struct doveadm_mailbox_cmd_context ctx;
	ARRAY_TYPE(const_string) mailboxes;
};

struct rename_cmd_context {
	struct doveadm_mailbox_cmd_context ctx;
	const char *oldname, *newname;
};

struct list_cmd_context {
	struct doveadm_mailbox_cmd_context ctx;
	struct mail_search_args *search_args;
	bool mutf7;
};

const char *const *doveadm_mailbox_args_to_mutf7(const char *const args[])
{
	ARRAY_TYPE(const_string) dest;
	string_t *str;
	const char *mutf7;
	unsigned int i;

	str = t_str_new(128);
	t_array_init(&dest, 8);
	for (i = 0; args[i] != NULL; i++) {
		str_truncate(str, 0);
		if (imap_utf8_to_utf7(args[i], str) < 0)
			i_fatal("Mailbox name not valid UTF-8: %s", args[i]);
		mutf7 = t_strdup(str_c(str));
		array_append(&dest, &mutf7, 1);
	}
	(void)array_append_space(&dest);
	return array_idx(&dest, 0);
}

static bool cmd_mailbox_parse_arg(struct doveadm_mail_cmd_context *_ctx, int c)
{
	struct doveadm_mailbox_cmd_context *ctx =
		(struct doveadm_mailbox_cmd_context *)_ctx;

	switch (c) {
	case 's':
		ctx->subscriptions = TRUE;
		break;
	default:
		return FALSE;
	}
	return TRUE;
}

#define doveadm_mailbox_cmd_alloc(type) \
	(type *)doveadm_mailbox_cmd_alloc_size(sizeof(type))
static struct doveadm_mail_cmd_context *
doveadm_mailbox_cmd_alloc_size(size_t size)
{
	struct doveadm_mail_cmd_context *ctx;

	ctx = doveadm_mail_cmd_alloc_size(size);
	ctx->getopt_args = "s";
	ctx->v.parse_arg = cmd_mailbox_parse_arg;
	return ctx;
}

static bool
cmd_mailbox_list_parse_arg(struct doveadm_mail_cmd_context *_ctx, int c)
{
	struct list_cmd_context *ctx = (struct list_cmd_context *)_ctx;

	switch (c) {
	case '7':
		ctx->mutf7 = TRUE;
		break;
	case '8':
		ctx->mutf7 = FALSE;
		break;
	case 's':
		ctx->ctx.subscriptions = TRUE;
		break;
	default:
		return FALSE;
	}
	return TRUE;
}

static void
cmd_mailbox_list_run(struct doveadm_mail_cmd_context *_ctx,
		     struct mail_user *user)
{
	struct list_cmd_context *ctx = (struct list_cmd_context *)_ctx;
	enum mailbox_list_iter_flags iter_flags =
		MAILBOX_LIST_ITER_RAW_LIST |
		MAILBOX_LIST_ITER_NO_AUTO_INBOX |
		MAILBOX_LIST_ITER_RETURN_NO_FLAGS;
	struct doveadm_mail_list_iter *iter;
	const struct mailbox_info *info;
	string_t *str = t_str_new(256);

	if (ctx->ctx.subscriptions)
		iter_flags |= MAILBOX_LIST_ITER_SELECT_SUBSCRIBED;

	iter = doveadm_mail_list_iter_full_init(user, ctx->search_args,
						iter_flags);
	while ((info = doveadm_mail_list_iter_next(iter)) != NULL) {
		str_truncate(str, 0);
		if (ctx->mutf7 || imap_utf7_to_utf8(info->name, str) < 0)
			doveadm_print(info->name);
		else
			doveadm_print(str_c(str));
	}
	doveadm_mail_list_iter_deinit(&iter);
}

struct mail_search_args *
doveadm_mail_mailbox_search_args_build(const char *const args[])
{
	struct mail_search_args *search_args;
	struct mail_search_arg *arg;
	unsigned int i;

	args = doveadm_mailbox_args_to_mutf7(args);
	search_args = mail_search_build_init();
	for (i = 0; args[i] != NULL; i++) {
		arg = mail_search_build_add(search_args, SEARCH_MAILBOX_GLOB);
		arg->value.str = p_strdup(search_args->pool, args[i]);
	}
	if (i > 1) {
		struct mail_search_arg *subargs = search_args->args;

		search_args->args = NULL;
		arg = mail_search_build_add(search_args, SEARCH_OR);
		arg->value.subargs = subargs;
	}
	return search_args;
}

static void cmd_mailbox_list_init(struct doveadm_mail_cmd_context *_ctx,
				  const char *const args[])
{
	struct list_cmd_context *ctx = (struct list_cmd_context *)_ctx;

	doveadm_print_header("mailbox", "mailbox",
			     DOVEADM_PRINT_HEADER_FLAG_HIDE_TITLE);
	ctx->search_args = doveadm_mail_mailbox_search_args_build(args);
}

static struct doveadm_mail_cmd_context *cmd_mailbox_list_alloc(void)
{
	struct list_cmd_context *ctx;

	ctx = doveadm_mailbox_cmd_alloc(struct list_cmd_context);
	ctx->ctx.ctx.v.init = cmd_mailbox_list_init;
	ctx->ctx.ctx.v.run = cmd_mailbox_list_run;
	ctx->ctx.ctx.v.parse_arg = cmd_mailbox_list_parse_arg;
	ctx->ctx.ctx.getopt_args = "78s";
	doveadm_print_init(DOVEADM_PRINT_TYPE_FLOW);
	return &ctx->ctx.ctx;
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
		if (ctx->ctx.subscriptions) {
			if (mailbox_list_set_subscribed(ns->list, storage_name,
							TRUE) < 0) {
				i_error("Can't subscribe to mailbox %s: %s", *namep,
					mailbox_list_get_last_error(ns->list, NULL));
			}
		}
		mailbox_free(&box);
	}
}

static void cmd_mailbox_create_init(struct doveadm_mail_cmd_context *_ctx,
				    const char *const args[])
{
	struct mailbox_cmd_context *ctx = (struct mailbox_cmd_context *)_ctx;
	const char *name;
	unsigned int i;

	if (args[0] == NULL)
		doveadm_mail_help_name("mailbox create");
	args = doveadm_mailbox_args_to_mutf7(args);

	for (i = 0; args[i] != NULL; i++) {
		name = p_strdup(ctx->ctx.ctx.pool, args[i]);
		array_append(&ctx->mailboxes, &name, 1);
	}
}

static struct doveadm_mail_cmd_context *cmd_mailbox_create_alloc(void)
{
	struct mailbox_cmd_context *ctx;

	ctx = doveadm_mailbox_cmd_alloc(struct mailbox_cmd_context);
	ctx->ctx.ctx.v.init = cmd_mailbox_create_init;
	ctx->ctx.ctx.v.run = cmd_mailbox_create_run;
	p_array_init(&ctx->mailboxes, ctx->ctx.ctx.pool, 16);
	return &ctx->ctx.ctx;
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
		if (ctx->ctx.subscriptions) {
			if (mailbox_list_set_subscribed(ns->list, storage_name,
							FALSE) < 0) {
				i_error("Can't unsubscribe mailbox %s: %s", *namep,
					mailbox_list_get_last_error(ns->list, NULL));
			}
		}
		mailbox_free(&box);
	}
}

static void cmd_mailbox_delete_init(struct doveadm_mail_cmd_context *_ctx,
				    const char *const args[])
{
	struct mailbox_cmd_context *ctx = (struct mailbox_cmd_context *)_ctx;
	const char *name;
	unsigned int i;

	if (args[0] == NULL)
		doveadm_mail_help_name("mailbox delete");
	args = doveadm_mailbox_args_to_mutf7(args);

	for (i = 0; args[i] != NULL; i++) {
		name = p_strdup(ctx->ctx.ctx.pool, args[i]);
		array_append(&ctx->mailboxes, &name, 1);
	}
}

static struct doveadm_mail_cmd_context *cmd_mailbox_delete_alloc(void)
{
	struct mailbox_cmd_context *ctx;

	ctx = doveadm_mailbox_cmd_alloc(struct mailbox_cmd_context);
	ctx->ctx.ctx.v.init = cmd_mailbox_delete_init;
	ctx->ctx.ctx.v.run = cmd_mailbox_delete_run;
	p_array_init(&ctx->mailboxes, ctx->ctx.ctx.pool, 16);
	return &ctx->ctx.ctx;
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
	if (ctx->ctx.subscriptions) {
		if (mailbox_list_set_subscribed(oldns->list, oldname, FALSE) < 0) {
			i_error("Can't unsubscribe mailbox %s: %s", ctx->oldname,
				mailbox_list_get_last_error(oldns->list, NULL));
		}
		if (mailbox_list_set_subscribed(newns->list, newname, TRUE) < 0) {
			i_error("Can't subscribe to mailbox %s: %s", ctx->newname,
				mailbox_list_get_last_error(newns->list, NULL));
		}
	}

	mailbox_free(&oldbox);
	mailbox_free(&newbox);
}

static void cmd_mailbox_rename_init(struct doveadm_mail_cmd_context *_ctx,
				    const char *const args[])
{
	struct rename_cmd_context *ctx = (struct rename_cmd_context *)_ctx;

	if (str_array_length(args) != 2)
		doveadm_mail_help_name("mailbox rename");
	args = doveadm_mailbox_args_to_mutf7(args);

	ctx->oldname = p_strdup(ctx->ctx.ctx.pool, args[0]);
	ctx->newname = p_strdup(ctx->ctx.ctx.pool, args[1]);
}

static struct doveadm_mail_cmd_context *cmd_mailbox_rename_alloc(void)
{
	struct rename_cmd_context *ctx;

	ctx = doveadm_mailbox_cmd_alloc(struct rename_cmd_context);
	ctx->ctx.ctx.v.init = cmd_mailbox_rename_init;
	ctx->ctx.ctx.v.run = cmd_mailbox_rename_run;
	return &ctx->ctx.ctx;
}

static void
cmd_mailbox_subscribe_run(struct doveadm_mail_cmd_context *_ctx,
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
		if (mailbox_list_set_subscribed(ns->list, storage_name,
						ctx->ctx.subscriptions) < 0) {
			i_error("Can't %s mailbox %s: %s", *namep,
				ctx->ctx.subscriptions ? "subscribe to" :
				"unsubscribe",
				mailbox_list_get_last_error(ns->list, NULL));
		}
		mailbox_free(&box);
	}
}

static void cmd_mailbox_subscribe_init(struct doveadm_mail_cmd_context *_ctx,
				       const char *const args[])
{
	struct mailbox_cmd_context *ctx = (struct mailbox_cmd_context *)_ctx;
	const char *name;
	unsigned int i;

	if (args[0] == NULL) {
		doveadm_mail_help_name(ctx->ctx.subscriptions ?
				       "mailbox subscribe" :
				       "mailbox unsubscribe");
	}
	args = doveadm_mailbox_args_to_mutf7(args);

	for (i = 0; args[i] != NULL; i++) {
		name = p_strdup(ctx->ctx.ctx.pool, args[i]);
		array_append(&ctx->mailboxes, &name, 1);
	}
}

static struct doveadm_mail_cmd_context *
cmd_mailbox_subscriptions_alloc(bool subscriptions)
{
	struct mailbox_cmd_context *ctx;

	ctx = doveadm_mail_cmd_alloc(struct mailbox_cmd_context);
	ctx->ctx.subscriptions = subscriptions;

	ctx->ctx.ctx.v.parse_arg = cmd_mailbox_parse_arg;
	ctx->ctx.ctx.v.init = cmd_mailbox_subscribe_init;
	ctx->ctx.ctx.v.run = cmd_mailbox_subscribe_run;
	p_array_init(&ctx->mailboxes, ctx->ctx.ctx.pool, 16);
	return &ctx->ctx.ctx;
}

static struct doveadm_mail_cmd_context *cmd_mailbox_subscribe_alloc(void)
{
	return cmd_mailbox_subscriptions_alloc(TRUE);
}

static struct doveadm_mail_cmd_context *cmd_mailbox_unsubscribe_alloc(void)
{
	return cmd_mailbox_subscriptions_alloc(FALSE);
}

struct doveadm_mail_cmd cmd_mailbox_list = {
	cmd_mailbox_list_alloc, "mailbox list",
	"[-7|-8] [-s] [<mailbox mask> [...]]"
};
struct doveadm_mail_cmd cmd_mailbox_create = {
	cmd_mailbox_create_alloc, "mailbox create",
	"[-s] <mailbox> [...]"
};
struct doveadm_mail_cmd cmd_mailbox_delete = {
	cmd_mailbox_delete_alloc, "mailbox delete",
	"[-s] <mailbox> [...]"
};
struct doveadm_mail_cmd cmd_mailbox_rename = {
	cmd_mailbox_rename_alloc, "mailbox rename",
	"[-s] <old name> <new name>"
};
struct doveadm_mail_cmd cmd_mailbox_subscribe = {
	cmd_mailbox_subscribe_alloc, "mailbox subscribe",
	"<mailbox> [...]"
};
struct doveadm_mail_cmd cmd_mailbox_unsubscribe = {
	cmd_mailbox_unsubscribe_alloc, "mailbox unsubscribe",
	"<mailbox> [...]"
};
