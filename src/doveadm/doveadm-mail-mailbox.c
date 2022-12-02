/* Copyright (c) 2010-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "unichar.h"
#include "imap-utf7.h"
#include "mail-namespace.h"
#include "mail-storage.h"
#include "mail-search-build.h"
#include "doveadm-print.h"
#include "doveadm-mailbox-list-iter.h"
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

struct create_cmd_context {
	struct doveadm_mailbox_cmd_context ctx;
	ARRAY_TYPE(const_string) mailboxes;
	struct mailbox_update update;
};

struct delete_cmd_context {
	struct doveadm_mailbox_cmd_context ctx;
	ARRAY_TYPE(const_string) mailboxes;
	bool recursive;
	bool require_empty;
	bool unsafe;
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

struct update_cmd_context {
	struct doveadm_mailbox_cmd_context ctx;
	const char *mailbox;
	struct mailbox_update update;
};

struct path_cmd_context {
	struct doveadm_mailbox_cmd_context ctx;
	const char *mailbox;
	enum mailbox_list_path_type path_type;
};

static const char *mailbox_list_path_type_names[] = {
	"dir", "alt-dir", "mailbox", "alt-mailbox",
	"control", "index", "index-private", "index-cache", "list-index",
};
static_assert_array_size(mailbox_list_path_type_names, MAILBOX_LIST_PATH_TYPE_COUNT);

static void doveadm_mailbox_arg_check(const char *arg)
{
	if (!uni_utf8_str_is_valid(arg)) {
		i_fatal_status(EX_DATAERR,
			"Mailbox name not valid UTF-8: %s", arg);
	}
}

void doveadm_mailbox_args_check_array(ARRAY_TYPE(const_string) *args)
{
	const char *arg;
	array_foreach_elem(args, arg)
		doveadm_mailbox_arg_check(arg);
}

void doveadm_mailbox_args_check(const char *const args[])
{
	for (; *args != NULL; args++)
		doveadm_mailbox_arg_check(*args);
}

#define doveadm_mailbox_cmd_alloc(type) \
	((type *) doveadm_mail_cmd_alloc_size(sizeof(type)))

static int
cmd_mailbox_list_run(struct doveadm_mail_cmd_context *_ctx,
		     struct mail_user *user)
{
	struct list_cmd_context *ctx =
		container_of(_ctx, struct list_cmd_context, ctx.ctx);

	enum mailbox_list_iter_flags iter_flags =
		MAILBOX_LIST_ITER_RETURN_NO_FLAGS;
	struct doveadm_mailbox_list_iter *iter;
	const struct mailbox_info *info;
	string_t *str = t_str_new(256);

	if (ctx->ctx.subscriptions)
		iter_flags |= MAILBOX_LIST_ITER_SELECT_SUBSCRIBED;

	iter = doveadm_mailbox_list_iter_full_init(_ctx, user, ctx->search_args,
						   iter_flags);
	while ((info = doveadm_mailbox_list_iter_next(iter)) != NULL) {
		if (!ctx->mutf7)
			doveadm_print(info->vname);
		else {
			str_truncate(str, 0);
			if (imap_utf8_to_utf7(info->vname, str) < 0)
				i_unreached();
			doveadm_print(str_c(str));
		}
	}
	if (doveadm_mailbox_list_iter_deinit(&iter) < 0)
		return -1;
	return 0;
}

struct mail_search_args *
doveadm_mail_mailbox_search_args_build(const char *const args[])
{
	struct mail_search_args *search_args;
	struct mail_search_arg *arg;
	enum mail_search_arg_type type;
	unsigned int i;

	doveadm_mailbox_args_check(args);
	search_args = mail_search_build_init();
	for (i = 0; args[i] != NULL; i++) {
		if (strchr(args[i], '*') != NULL ||
		    strchr(args[i], '%') != NULL)
			type = SEARCH_MAILBOX_GLOB;
		else
			type = SEARCH_MAILBOX;
		arg = mail_search_build_add(search_args, type);
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

static void cmd_mailbox_list_init(struct doveadm_mail_cmd_context *_ctx)
{
	struct doveadm_cmd_context *cctx = _ctx->cctx;
	struct list_cmd_context *ctx =
		container_of(_ctx, struct list_cmd_context, ctx.ctx);

	ctx->ctx.subscriptions = doveadm_cmd_param_flag(cctx, "subscriptions");
	ctx->mutf7 = doveadm_cmd_param_flag(cctx, "mutf7");
	if (doveadm_cmd_param_flag(cctx, "utf8")) ctx->mutf7 = FALSE;

	const char *const *args = empty_str_array;
	(void)doveadm_cmd_param_array(cctx, "mailbox-mask", &args);
	ctx->search_args = doveadm_mail_mailbox_search_args_build(args);
	doveadm_print_header("mailbox", "mailbox",
			     DOVEADM_PRINT_HEADER_FLAG_HIDE_TITLE);
}

static void cmd_mailbox_list_deinit(struct doveadm_mail_cmd_context *_ctx)
{
	struct list_cmd_context *ctx =
		container_of(_ctx, struct list_cmd_context, ctx.ctx);

	if (ctx->search_args != NULL)
		mail_search_args_unref(&ctx->search_args);
}

static struct doveadm_mail_cmd_context *cmd_mailbox_list_alloc(void)
{
	struct list_cmd_context *ctx;

	ctx = doveadm_mailbox_cmd_alloc(struct list_cmd_context);
	ctx->ctx.ctx.v.init = cmd_mailbox_list_init;
	ctx->ctx.ctx.v.deinit = cmd_mailbox_list_deinit;
	ctx->ctx.ctx.v.run = cmd_mailbox_list_run;
	doveadm_print_init(DOVEADM_PRINT_TYPE_FLOW);
	return &ctx->ctx.ctx;
}

static int
cmd_mailbox_create_run(struct doveadm_mail_cmd_context *_ctx,
		       struct mail_user *user)
{
	struct create_cmd_context *ctx =
		container_of(_ctx, struct create_cmd_context, ctx.ctx);

	struct mail_namespace *ns;
	struct mailbox *box;
	const char *name;
	int ret = 0;

	array_foreach_elem(&ctx->mailboxes, name) {
		size_t len;
		bool directory = FALSE;

		ns = mail_namespace_find(user->namespaces, name);
		len = strlen(name);
		if (len > 0 && name[len-1] == mail_namespace_get_sep(ns)) {
			name = t_strndup(name, len-1);
			directory = TRUE;
		}

		box = mailbox_alloc(ns->list, name, 0);
		if (mailbox_create(box, &ctx->update, directory) < 0) {
			e_error(ctx->ctx.ctx.cctx->event,
				"Can't create mailbox %s: %s", name,
				mailbox_get_last_internal_error(box, NULL));
			doveadm_mail_failed_mailbox(_ctx, box);
			ret = -1;
		}
		if (ctx->ctx.subscriptions) {
			if (mailbox_set_subscribed(box, TRUE) < 0) {
				e_error(ctx->ctx.ctx.cctx->event,
					"Can't subscribe to mailbox %s: %s", name,
					mailbox_get_last_internal_error(box, NULL));
				doveadm_mail_failed_mailbox(_ctx, box);
				ret = -1;
			}
		}
		mailbox_free(&box);
	}
	return ret;
}

static void cmd_mailbox_create_init(struct doveadm_mail_cmd_context *_ctx)
{
	struct doveadm_cmd_context *cctx = _ctx->cctx;
	struct create_cmd_context *ctx =
		container_of(_ctx, struct create_cmd_context, ctx.ctx);

	ctx->ctx.subscriptions = doveadm_cmd_param_flag(cctx, "subscriptions");

	const char *guid;
	if (doveadm_cmd_param_str(cctx, "guid", &guid) &&
	    guid_128_from_string(guid, ctx->update.mailbox_guid) < 0)
		doveadm_mail_help_name("mailbox create");

	if (!doveadm_cmd_param_array_append(cctx, "mailbox", &ctx->mailboxes))
		doveadm_mail_help_name("mailbox create");

	doveadm_mailbox_args_check_array(&ctx->mailboxes);
}

static struct doveadm_mail_cmd_context *cmd_mailbox_create_alloc(void)
{
	struct create_cmd_context *ctx;

	ctx = doveadm_mailbox_cmd_alloc(struct create_cmd_context);
	ctx->ctx.ctx.v.init = cmd_mailbox_create_init;
	ctx->ctx.ctx.v.run = cmd_mailbox_create_run;
	p_array_init(&ctx->mailboxes, ctx->ctx.ctx.pool, 16);
	return &ctx->ctx.ctx;
}

static int i_strcmp_reverse_p(const char *const *s1, const char *const *s2)
{
	return -strcmp(*s1, *s2);
}

static int
get_child_mailboxes(struct mail_user *user, ARRAY_TYPE(const_string) *mailboxes,
		    const char *name)
{
	struct mailbox_list_iterate_context *iter;
	struct mail_namespace *ns;
	const struct mailbox_info *info;
	const char *pattern, *child_name;

	ns = mail_namespace_find(user->namespaces, name);
	pattern = name[0] == '\0' ? "*" :
		t_strdup_printf("%s%c*", name, mail_namespace_get_sep(ns));
	iter = mailbox_list_iter_init(ns->list, pattern,
				      MAILBOX_LIST_ITER_RETURN_NO_FLAGS);
	while ((info = mailbox_list_iter_next(iter)) != NULL) {
		child_name = t_strdup(info->vname);
		array_push_back(mailboxes, &child_name);
	}
	return mailbox_list_iter_deinit(&iter);
}

static int
cmd_mailbox_delete_run(struct doveadm_mail_cmd_context *_ctx,
		       struct mail_user *user)
{
	struct delete_cmd_context *ctx =
		container_of(_ctx, struct delete_cmd_context, ctx.ctx);

	struct mail_namespace *ns;
	struct mailbox *box;
	struct mail_storage *storage;
	const char *name;
	ARRAY_TYPE(const_string) recursive_mailboxes;
	const ARRAY_TYPE(const_string) *mailboxes = &ctx->mailboxes;
	enum mailbox_flags mailbox_flags = 0;
	int ret = 0, ret2;

	if (ctx->unsafe)
		mailbox_flags |= MAILBOX_FLAG_DELETE_UNSAFE;
	if (ctx->recursive) {
		t_array_init(&recursive_mailboxes, 32);
		array_foreach_elem(&ctx->mailboxes, name) {
			if (get_child_mailboxes(user, &recursive_mailboxes,
						name) < 0) {
				doveadm_mail_failed_error(_ctx, MAIL_ERROR_TEMP);
				ret = -1;
			}
			if (name[0] != '\0')
				array_push_back(&recursive_mailboxes, &name);
		}
		array_sort(&recursive_mailboxes, i_strcmp_reverse_p);
		mailboxes = &recursive_mailboxes;
	}

	array_foreach_elem(mailboxes, name) {
		ns = mail_namespace_find(user->namespaces, name);
		box = mailbox_alloc(ns->list, name, mailbox_flags);
		storage = mailbox_get_storage(box);
		ret2 = ctx->require_empty ? mailbox_delete_empty(box) :
			mailbox_delete(box);
		if (ret2 < 0) {
			e_error(ctx->ctx.ctx.cctx->event,
				"Can't delete mailbox %s: %s", name,
				mailbox_get_last_internal_error(box, NULL));
			doveadm_mail_failed_mailbox(_ctx, box);
			ret = -1;
		}
		if (ctx->ctx.subscriptions) {
			if (mailbox_set_subscribed(box, FALSE) < 0) {
				e_error(ctx->ctx.ctx.cctx->event,
					"Can't unsubscribe mailbox %s: %s", name,
					mail_storage_get_last_internal_error(storage, NULL));
				doveadm_mail_failed_mailbox(_ctx, box);
				ret = -1;
			}
		}
		mailbox_free(&box);
	}
	return ret;
}

static void cmd_mailbox_delete_init(struct doveadm_mail_cmd_context *_ctx)
{
	struct doveadm_cmd_context *cctx = _ctx->cctx;
	struct delete_cmd_context *ctx =
		container_of(_ctx, struct delete_cmd_context, ctx.ctx);

	ctx->recursive = doveadm_cmd_param_flag(cctx, "recursive");
	ctx->require_empty = doveadm_cmd_param_flag(cctx, "require-empty");
	ctx->ctx.subscriptions = doveadm_cmd_param_flag(cctx, "subscriptions");
	ctx->unsafe = doveadm_cmd_param_flag(cctx, "unsafe");

	if (!doveadm_cmd_param_array_append(cctx, "mailbox", &ctx->mailboxes))
		doveadm_mail_help_name("mailbox delete");

	doveadm_mailbox_args_check_array(&ctx->mailboxes);
	array_sort(&ctx->mailboxes, i_strcmp_reverse_p);
}

static struct doveadm_mail_cmd_context *cmd_mailbox_delete_alloc(void)
{
	struct delete_cmd_context *ctx;

	ctx = doveadm_mailbox_cmd_alloc(struct delete_cmd_context);
	ctx->ctx.ctx.v.init = cmd_mailbox_delete_init;
	ctx->ctx.ctx.v.run = cmd_mailbox_delete_run;
	p_array_init(&ctx->mailboxes, ctx->ctx.ctx.pool, 16);
	return &ctx->ctx.ctx;
}

static int
cmd_mailbox_rename_run(struct doveadm_mail_cmd_context *_ctx,
		       struct mail_user *user)
{
	struct rename_cmd_context *ctx =
		container_of(_ctx, struct rename_cmd_context, ctx.ctx);

	struct mail_namespace *oldns, *newns;
	struct mailbox *oldbox, *newbox;
	const char *oldname = ctx->oldname;
	const char *newname = ctx->newname;
	int ret = 0;

	oldns = mail_namespace_find(user->namespaces, oldname);
	newns = mail_namespace_find(user->namespaces, newname);
	oldbox = mailbox_alloc(oldns->list, oldname, 0);
	newbox = mailbox_alloc(newns->list, newname, 0);
	if (mailbox_rename(oldbox, newbox) < 0) {
		e_error(ctx->ctx.ctx.cctx->event,
			"Can't rename mailbox %s to %s: %s", oldname, newname,
			mailbox_get_last_internal_error(oldbox, NULL));
		doveadm_mail_failed_mailbox(_ctx, oldbox);
		ret = -1;
	}
	if (ctx->ctx.subscriptions) {
		if (mailbox_set_subscribed(oldbox, FALSE) < 0) {
			e_error(ctx->ctx.ctx.cctx->event,
				"Can't unsubscribe mailbox %s: %s", ctx->oldname,
				mailbox_get_last_internal_error(oldbox, NULL));
			doveadm_mail_failed_mailbox(_ctx, oldbox);
			ret = -1;
		}
		if (mailbox_set_subscribed(newbox, TRUE) < 0) {
			e_error(ctx->ctx.ctx.cctx->event,
				"Can't subscribe to mailbox %s: %s", ctx->newname,
				mailbox_get_last_internal_error(newbox, NULL));
			doveadm_mail_failed_mailbox(_ctx, newbox);
			ret = -1;
		}
	}

	mailbox_free(&oldbox);
	mailbox_free(&newbox);
	return ret;
}

static void cmd_mailbox_rename_init(struct doveadm_mail_cmd_context *_ctx)
{
	struct doveadm_cmd_context *cctx = _ctx->cctx;
	struct rename_cmd_context *ctx =
		container_of(_ctx, struct rename_cmd_context, ctx.ctx);

	ctx->ctx.subscriptions = doveadm_cmd_param_flag(cctx, "subscriptions");
	if (!doveadm_cmd_param_str(cctx, "mailbox", &ctx->oldname) ||
	    !doveadm_cmd_param_str(cctx, "new-name", &ctx->newname))
		doveadm_mail_help_name("mailbox rename");
	doveadm_mailbox_arg_check(ctx->oldname);
	doveadm_mailbox_arg_check(ctx->newname);
}

static struct doveadm_mail_cmd_context *cmd_mailbox_rename_alloc(void)
{
	struct rename_cmd_context *ctx;

	ctx = doveadm_mailbox_cmd_alloc(struct rename_cmd_context);
	ctx->ctx.ctx.v.init = cmd_mailbox_rename_init;
	ctx->ctx.ctx.v.run = cmd_mailbox_rename_run;
	return &ctx->ctx.ctx;
}

static int
cmd_mailbox_subscribe_run(struct doveadm_mail_cmd_context *_ctx,
			  struct mail_user *user)
{
	struct mailbox_cmd_context *ctx =
		container_of(_ctx, struct mailbox_cmd_context, ctx.ctx);

	struct mail_namespace *ns;
	struct mailbox *box;
	const char *name;
	int ret = 0;

	array_foreach_elem(&ctx->mailboxes, name) {
		ns = mail_namespace_find(user->namespaces, name);
		box = mailbox_alloc(ns->list, name, 0);
		if (mailbox_set_subscribed(box, ctx->ctx.subscriptions) < 0) {
			e_error(ctx->ctx.ctx.cctx->event,
				"Can't %s mailbox %s: %s", name,
				ctx->ctx.subscriptions ?
					"subscribe to" : "unsubscribe",
				mailbox_get_last_internal_error(box, NULL));
			doveadm_mail_failed_mailbox(_ctx, box);
			ret = -1;
		}
		mailbox_free(&box);
	}
	return ret;
}

static void cmd_mailbox_subscribe_init(struct doveadm_mail_cmd_context *_ctx)
{
	struct doveadm_cmd_context *cctx = _ctx->cctx;
	struct mailbox_cmd_context *ctx =
		container_of(_ctx, struct mailbox_cmd_context, ctx.ctx);

	if (!doveadm_cmd_param_array_append(cctx, "mailbox", &ctx->mailboxes))
		doveadm_mail_help_name(ctx->ctx.subscriptions ?
				       "mailbox subscribe" :
				       "mailbox unsubscribe");

	doveadm_mailbox_args_check_array(&ctx->mailboxes);
}

static struct doveadm_mail_cmd_context *
cmd_mailbox_subscriptions_alloc(bool subscriptions)
{
	struct mailbox_cmd_context *ctx;

	ctx = doveadm_mail_cmd_alloc(struct mailbox_cmd_context);
	ctx->ctx.subscriptions = subscriptions;

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

static
void cmd_mailbox_update_init(struct doveadm_mail_cmd_context *_ctx)
{
	struct doveadm_cmd_context *cctx = _ctx->cctx;
	struct update_cmd_context *ctx =
		container_of(_ctx, struct update_cmd_context, ctx.ctx);

	const char *value_str;
	if (doveadm_cmd_param_str(cctx, "mailbox-guid", &value_str) &&
	    guid_128_from_string(value_str, ctx->update.mailbox_guid) < 0)
		doveadm_mail_help_name("mailbox update");

	(void)doveadm_cmd_param_uint32(cctx, "uid-validity", &ctx->update.uid_validity);
	(void)doveadm_cmd_param_uint32(cctx, "min-next-uid", &ctx->update.min_next_uid);
	(void)doveadm_cmd_param_uint32(cctx, "min-first-recent-uid", &ctx->update.min_first_recent_uid);
	(void)doveadm_cmd_param_uint64(cctx, "min-highest-modseq", &ctx->update.min_highest_modseq);
	(void)doveadm_cmd_param_uint64(cctx, "min-highest-pvt-modseq", &ctx->update.min_highest_pvt_modseq);

	if (ctx->update.min_first_recent_uid > ctx->update.min_next_uid &&
	    ctx->update.min_first_recent_uid + ctx->update.min_next_uid > 0)
		i_fatal_status(EX_DATAERR, "min_first_recent_uid > min_next_uid");

	if (!doveadm_cmd_param_str(cctx, "mailbox", &ctx->mailbox))
		doveadm_mail_help_name("mailbox update");
	doveadm_mailbox_arg_check(ctx->mailbox);
}

static
int cmd_mailbox_update_run(struct doveadm_mail_cmd_context *_ctx,
			   struct mail_user *user)
{
	struct update_cmd_context *ctx =
		container_of(_ctx, struct update_cmd_context, ctx.ctx);

	struct mail_namespace *ns;
	struct mailbox *box;
	enum mail_error mail_error;
	int ret = 0;

	ns = mail_namespace_find(user->namespaces, ctx->mailbox);
	box = mailbox_alloc(ns->list, ctx->mailbox, 0);

	if ((ret = mailbox_update(box, &(ctx->update))) != 0) {
		const char *error = mailbox_get_last_internal_error(
			box, &mail_error);
		e_error(ctx->ctx.ctx.cctx->event,
			"Cannot update %s: %s", ctx->mailbox, error);
		doveadm_mail_failed_error(_ctx, mail_error);
	}

	mailbox_free(&box);

	return ret;
}

static
struct doveadm_mail_cmd_context *cmd_mailbox_update_alloc(void)
{
	struct update_cmd_context *ctx;
	ctx = doveadm_mail_cmd_alloc(struct update_cmd_context);
	ctx->ctx.ctx.v.init = cmd_mailbox_update_init;
	ctx->ctx.ctx.v.run = cmd_mailbox_update_run;
	return &ctx->ctx.ctx;
}

static bool
mailbox_list_path_type_name_parse(const char *name,
				  enum mailbox_list_path_type *type_r)
{
	enum mailbox_list_path_type type;

	for (type = 0; type < N_ELEMENTS(mailbox_list_path_type_names); type++) {
		if (strcmp(mailbox_list_path_type_names[type], name) == 0) {
			*type_r = type;
			return TRUE;
		}
	}
	return FALSE;
}

static void
cmd_mailbox_path_init(struct doveadm_mail_cmd_context *_ctx)
{
	struct doveadm_cmd_context *cctx = _ctx->cctx;
	struct path_cmd_context *ctx =
		container_of(_ctx, struct path_cmd_context, ctx.ctx);

	const char *value_str;
	if (doveadm_cmd_param_str(cctx, "type", &value_str) &&
	    !mailbox_list_path_type_name_parse(value_str, &ctx->path_type))
		doveadm_mail_help_name("mailbox path");

	const char *const *args;
	if (!doveadm_cmd_param_array(cctx, "mailbox", &args) ||
	    args[1] != NULL)
		doveadm_mail_help_name("mailbox path");
	ctx->mailbox = args[0];

	doveadm_mailbox_arg_check(ctx->mailbox);
	doveadm_print_header("path", "path", DOVEADM_PRINT_HEADER_FLAG_HIDE_TITLE);
}

static int
cmd_mailbox_path_run(struct doveadm_mail_cmd_context *_ctx,
		     struct mail_user *user)
{
	struct path_cmd_context *ctx =
		container_of(_ctx, struct path_cmd_context, ctx.ctx);

	struct mail_namespace *ns;
	enum mail_error mail_error;
	const char *storage_name, *path;
	int ret;

	ns = mail_namespace_find(user->namespaces, ctx->mailbox);
	storage_name = mailbox_list_get_storage_name(ns->list, ctx->mailbox);
	ret = mailbox_list_get_path(ns->list, storage_name, ctx->path_type, &path);
	if (ret < 0) {
		const char *error = mailbox_list_get_last_internal_error(
			ns->list, &mail_error);
		e_error(ctx->ctx.ctx.cctx->event,
			"Failed to lookup mailbox %s path: %s",
			ctx->mailbox, error);
		doveadm_mail_failed_error(_ctx, mail_error);
	} else if (ret > 0) {
		doveadm_print(path);
	}
	return ret;
}

static struct doveadm_mail_cmd_context *cmd_mailbox_path_alloc(void)
{
	struct path_cmd_context *ctx;

	ctx = doveadm_mail_cmd_alloc(struct path_cmd_context);
	ctx->path_type = MAILBOX_LIST_PATH_TYPE_INDEX;
	ctx->ctx.ctx.v.init = cmd_mailbox_path_init;
	ctx->ctx.ctx.v.run = cmd_mailbox_path_run;
	doveadm_print_init(DOVEADM_PRINT_TYPE_FLOW);
	return &ctx->ctx.ctx;
}

struct doveadm_cmd_ver2 doveadm_cmd_mailbox_list_ver2 = {
	.name = "mailbox list",
	.mail_cmd = cmd_mailbox_list_alloc,
	.usage = DOVEADM_CMD_MAIL_USAGE_PREFIX"[-7|-8] [-s] [<mailbox mask> [...]]",
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_MAIL_COMMON
DOVEADM_CMD_PARAM('7', "mutf7", CMD_PARAM_BOOL, 0)
DOVEADM_CMD_PARAM('8', "utf8", CMD_PARAM_BOOL, 0)
DOVEADM_CMD_PARAM('s', "subscriptions", CMD_PARAM_BOOL, 0)
DOVEADM_CMD_PARAM('\0', "mailbox-mask", CMD_PARAM_ARRAY, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAMS_END
};

struct doveadm_cmd_ver2 doveadm_cmd_mailbox_create_ver2 = {
	.name = "mailbox create",
	.mail_cmd = cmd_mailbox_create_alloc,
	.usage = DOVEADM_CMD_MAIL_USAGE_PREFIX"[-s] [-g <guid>] <mailbox> [...]",
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_MAIL_COMMON
DOVEADM_CMD_PARAM('s', "subscriptions", CMD_PARAM_BOOL, 0)
DOVEADM_CMD_PARAM('g', "guid", CMD_PARAM_STR, 0)
DOVEADM_CMD_PARAM('\0', "mailbox", CMD_PARAM_ARRAY, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAMS_END
};

struct doveadm_cmd_ver2 doveadm_cmd_mailbox_delete_ver2 = {
	.name = "mailbox delete",
	.mail_cmd = cmd_mailbox_delete_alloc,
	.usage = DOVEADM_CMD_MAIL_USAGE_PREFIX"[-e] [-r] [-s] [-Z] <mailbox> [...]",
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_MAIL_COMMON
DOVEADM_CMD_PARAM('e', "require-empty", CMD_PARAM_BOOL, 0)
DOVEADM_CMD_PARAM('s', "subscriptions", CMD_PARAM_BOOL, 0)
DOVEADM_CMD_PARAM('r', "recursive", CMD_PARAM_BOOL, 0)
DOVEADM_CMD_PARAM('Z', "unsafe", CMD_PARAM_BOOL, 0)
DOVEADM_CMD_PARAM('\0', "mailbox", CMD_PARAM_ARRAY, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAMS_END
};

struct doveadm_cmd_ver2 doveadm_cmd_mailbox_rename_ver2 = {
	.name = "mailbox rename",
	.mail_cmd = cmd_mailbox_rename_alloc,
	.usage = DOVEADM_CMD_MAIL_USAGE_PREFIX"[-s] <old name> <new name>",
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_MAIL_COMMON
DOVEADM_CMD_PARAM('s', "subscriptions", CMD_PARAM_BOOL, 0)
DOVEADM_CMD_PARAM('\0', "mailbox", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAM('\0', "new-name", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAMS_END
};

struct doveadm_cmd_ver2 doveadm_cmd_mailbox_subscribe_ver2 = {
	.name = "mailbox subscribe",
	.mail_cmd = cmd_mailbox_subscribe_alloc,
	.usage = DOVEADM_CMD_MAIL_USAGE_PREFIX"<mailbox> [...]",
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_MAIL_COMMON
DOVEADM_CMD_PARAM('\0', "mailbox", CMD_PARAM_ARRAY, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAMS_END
};

struct doveadm_cmd_ver2 doveadm_cmd_mailbox_unsubscribe_ver2 = {
	.name = "mailbox unsubscribe",
	.mail_cmd = cmd_mailbox_unsubscribe_alloc,
	.usage = DOVEADM_CMD_MAIL_USAGE_PREFIX"<mailbox> [...]",
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_MAIL_COMMON
DOVEADM_CMD_PARAM('\0', "mailbox", CMD_PARAM_ARRAY, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAMS_END
};

struct doveadm_cmd_ver2 doveadm_cmd_mailbox_update_ver2 = {
	.name = "mailbox update",
	.mail_cmd = cmd_mailbox_update_alloc,
	.usage = DOVEADM_CMD_MAIL_USAGE_PREFIX"[--mailbox-guid guid] [--uid-validity uid] [--min-next-uid uid] [--min-first-recent-uid uid] [--min-highest-modseq seq] [--min-highest-pvt-modseq seq] <mailbox>",
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_MAIL_COMMON
DOVEADM_CMD_PARAM('g', "mailbox-guid", CMD_PARAM_STR, 0)
DOVEADM_CMD_PARAM('V', "uid-validity", CMD_PARAM_INT64, CMD_PARAM_FLAG_UNSIGNED)
DOVEADM_CMD_PARAM('N', "min-next-uid", CMD_PARAM_INT64, CMD_PARAM_FLAG_UNSIGNED)
DOVEADM_CMD_PARAM('R', "min-first-recent-uid", CMD_PARAM_INT64, CMD_PARAM_FLAG_UNSIGNED)
DOVEADM_CMD_PARAM('H', "min-highest-modseq", CMD_PARAM_INT64, CMD_PARAM_FLAG_UNSIGNED)
DOVEADM_CMD_PARAM('P', "min-highest-pvt-modseq", CMD_PARAM_INT64, CMD_PARAM_FLAG_UNSIGNED)
DOVEADM_CMD_PARAM('\0', "mailbox", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAMS_END
};

struct doveadm_cmd_ver2 doveadm_cmd_mailbox_path_ver2 = {
	.name = "mailbox path",
	.mail_cmd = cmd_mailbox_path_alloc,
	.usage = DOVEADM_CMD_MAIL_USAGE_PREFIX"[-t <type>] <mailbox>",
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_MAIL_COMMON
/* should be CMD_PARAM_STR but it would break the http API */
DOVEADM_CMD_PARAM('\0', "mailbox", CMD_PARAM_ARRAY, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAM('t', "type", CMD_PARAM_STR, 0)
DOVEADM_CMD_PARAMS_END
};

