/* Copyright (c) 2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "imap-arg.h"
#include "imap-match.h"
#include "mailbox-tree.h"
#include "imapc-client.h"
#include "imapc-storage.h"
#include "imapc-list.h"

struct imapc_mailbox_list_iterate_context {
	struct mailbox_list_iterate_context ctx;
	struct mailbox_tree_iterate_context *iter;
	struct imap_match_glob *glob;
	struct mailbox_info info;
	bool failed;
};

extern struct mailbox_list imapc_mailbox_list;

static struct mailbox_list *imapc_list_alloc(void)
{
	struct imapc_mailbox_list *list;
	pool_t pool;

	pool = pool_alloconly_create("imapc mailbox list", 1024);
	list = p_new(pool, struct imapc_mailbox_list, 1);
	list->list = imapc_mailbox_list;
	list->list.pool = pool;
	return &list->list;
}

static void imapc_list_deinit(struct mailbox_list *_list)
{
	struct imapc_mailbox_list *list = (struct imapc_mailbox_list *)_list;

	if (list->mailboxes != NULL)
		mailbox_tree_deinit(&list->mailboxes);
	if (list->subscriptions != NULL)
		mailbox_tree_deinit(&list->subscriptions);
	pool_unref(&list->list.pool);
}

static void imapc_list_simple_callback(const struct imapc_command_reply *reply,
				       void *context)
{
	struct imapc_simple_context *ctx = context;
	const char *str;
	enum mail_error error;

	imapc_simple_callback(reply, context);
	if (ctx->ret < 0) {
		str = mail_storage_get_last_error(&ctx->storage->storage, &error);
		mailbox_list_set_error(&ctx->storage->list->list, error, str);
	}
}

static struct mailbox_node *
imapc_list_update_tree(struct mailbox_tree_context *tree,
		       const struct imap_arg *args)
{
	struct mailbox_node *node;
	const struct imap_arg *flags;
	const char *name, *flag;
	enum mailbox_info_flags info_flags = 0;
	bool created;

	if (!imap_arg_get_list(&args[0], &flags) ||
	    args[1].type == IMAP_ARG_EOL ||
	    !imap_arg_get_astring(&args[2], &name))
		return NULL;

	while (imap_arg_get_atom(flags, &flag)) {
		if (strcasecmp(flag, "\\NoSelect") == 0)
			info_flags |= MAILBOX_NOSELECT;
		else if (strcasecmp(flag, "\\NonExistent") == 0)
			info_flags |= MAILBOX_NONEXISTENT;
		else if (strcasecmp(flag, "\\NoInferiors") == 0)
			info_flags |= MAILBOX_NOINFERIORS;
		else if (strcasecmp(flag, "\\Subscribed") == 0)
			info_flags |= MAILBOX_SUBSCRIBED;
		flags++;
	}

	if ((info_flags & MAILBOX_NONEXISTENT) != 0)
		node = mailbox_tree_lookup(tree, name);
	else
		node = mailbox_tree_get(tree, name, &created);
	if (node != NULL)
		node->flags = info_flags;
	return node;
}

static void imapc_untagged_list(const struct imapc_untagged_reply *reply,
				struct imapc_storage *storage)
{
	struct imapc_mailbox_list *list = storage->list;
	const struct imap_arg *args = reply->args;
	const char *sep, *name;

	if (list->sep == '\0') {
		/* we haven't asked for the separator yet.
		   lets see if this is the reply for its request. */
		if (args[0].type == IMAP_ARG_EOL ||
		    !imap_arg_get_nstring(&args[1], &sep) ||
		    !imap_arg_get_astring(&args[2], &name))
			return;

		/* we can't handle NIL separator yet */
		list->sep = sep == NULL ? '/' : sep[0];
		return;
	}
	(void)imapc_list_update_tree(list->mailboxes, args);
}

static void imapc_untagged_lsub(const struct imapc_untagged_reply *reply,
				struct imapc_storage *storage)
{
	struct imapc_mailbox_list *list = storage->list;
	const struct imap_arg *args = reply->args;
	struct mailbox_node *node;

	if (list->sep == '\0') {
		/* we haven't asked for the separator yet */
		return;
	}
	node = imapc_list_update_tree(list->subscriptions, args);
	if (node != NULL)
		node->flags |= MAILBOX_SUBSCRIBED;
}

void imapc_list_register_callbacks(struct imapc_mailbox_list *list)
{
	imapc_storage_register_untagged(list->storage, "LIST",
					imapc_untagged_list);
	imapc_storage_register_untagged(list->storage, "LSUB",
					imapc_untagged_lsub);
}

static int imapc_list_refresh(struct imapc_mailbox_list *list,
			      enum mailbox_list_iter_flags flags)
{
	struct imapc_simple_context ctx;

	ctx.storage = list->storage;
	if ((flags & MAILBOX_LIST_ITER_SELECT_SUBSCRIBED) == 0) {
		imapc_client_cmdf(list->storage->client,
				  imapc_list_simple_callback, &ctx,
				  "LIST \"\" *");
		if (list->mailboxes != NULL)
			mailbox_tree_deinit(&list->mailboxes);
		list->mailboxes = mailbox_tree_init(list->sep);
	} else {
		imapc_client_cmdf(list->storage->client,
				  imapc_list_simple_callback, &ctx,
				  "LSUB \"\" *");
		if (list->subscriptions != NULL)
			mailbox_tree_deinit(&list->subscriptions);
		list->subscriptions = mailbox_tree_init(list->sep);
	}

	imapc_client_run(list->storage->client);
	return ctx.ret;
}

static bool
imapc_is_valid_pattern(struct mailbox_list *list ATTR_UNUSED,
		       const char *pattern ATTR_UNUSED)
{
	return TRUE;
}

static bool
imapc_is_valid_existing_name(struct mailbox_list *list ATTR_UNUSED,
			     const char *name ATTR_UNUSED)
{
	return TRUE;
}

static bool
imapc_is_valid_create_name(struct mailbox_list *list ATTR_UNUSED,
			   const char *name ATTR_UNUSED)
{
	return TRUE;
}

static char imapc_list_get_hierarchy_sep(struct mailbox_list *_list)
{
	struct imapc_mailbox_list *list = (struct imapc_mailbox_list *)_list;
	struct imapc_simple_context ctx;

	if (list->sep == '\0') {
		ctx.storage = list->storage;
		imapc_client_cmdf(list->storage->client,
				  imapc_list_simple_callback, &ctx,
				  "LIST \"\" \"\"");
		imapc_client_run(list->storage->client);
		if (ctx.ret < 0) {
			list->broken = TRUE;
			return '/';
		}
	}
	return list->sep;
}

static const char *
imapc_list_get_path(struct mailbox_list *list ATTR_UNUSED,
		    const char *name ATTR_UNUSED,
		    enum mailbox_list_path_type type)
{
	if (type == MAILBOX_LIST_PATH_TYPE_INDEX)
		return "";
	return NULL;
}

static const char *
imapc_list_get_temp_prefix(struct mailbox_list *list, bool global ATTR_UNUSED)
{
	i_panic("imapc: Can't return a temp prefix for '%s'",
		list->ns->prefix);
	return NULL;
}

static const char *
imapc_list_join_refpattern(struct mailbox_list *list ATTR_UNUSED,
			   const char *ref, const char *pattern)
{
	return t_strconcat(ref, pattern, NULL);
}

static struct mailbox_list_iterate_context *
imapc_list_iter_init(struct mailbox_list *_list, const char *const *patterns,
		     enum mailbox_list_iter_flags flags)
{
	struct imapc_mailbox_list *list = (struct imapc_mailbox_list *)_list;
	struct imapc_mailbox_list_iterate_context *ctx;
	struct mailbox_tree_context *tree;
	char sep;

	sep = mailbox_list_get_hierarchy_sep(_list);

	ctx = i_new(struct imapc_mailbox_list_iterate_context, 1);
	ctx->ctx.list = _list;
	ctx->ctx.flags = flags;
	ctx->info.ns = _list->ns;
	ctx->glob = imap_match_init_multiple(default_pool, patterns,
					     FALSE, sep);
	if (imapc_list_refresh(list, flags) < 0)
		ctx->failed = TRUE;
	else {
		tree = (flags & MAILBOX_LIST_ITER_SELECT_SUBSCRIBED) != 0 ?
			list->subscriptions : list->mailboxes;
		ctx->iter = mailbox_tree_iterate_init(tree, NULL, 0);
	}
	return &ctx->ctx;
}

static const struct mailbox_info *
imapc_list_iter_next(struct mailbox_list_iterate_context *_ctx)
{
	struct imapc_mailbox_list_iterate_context *ctx =
		(struct imapc_mailbox_list_iterate_context *)_ctx;
	struct mailbox_node *node;
	const char *name;

	if (ctx->failed)
		return NULL;

	while ((node = mailbox_tree_iterate_next(ctx->iter, &name)) != NULL) {
		if (imap_match(ctx->glob, name) == IMAP_MATCH_YES) {
			ctx->info.flags &= ~(MAILBOX_CHILDREN |
					     MAILBOX_NOCHILDREN);
			if (node->children == NULL)
				ctx->info.flags |= MAILBOX_NOCHILDREN;
			else
				ctx->info.flags |= MAILBOX_CHILDREN;
			ctx->info.name = name;
			return &ctx->info;
		}
	}
	return NULL;
}

static int imapc_list_iter_deinit(struct mailbox_list_iterate_context *_ctx)
{
	struct imapc_mailbox_list_iterate_context *ctx =
		(struct imapc_mailbox_list_iterate_context *)_ctx;
	int ret = ctx->failed ? -1 : 0;

	if (ctx->iter != NULL)
		mailbox_tree_iterate_deinit(&ctx->iter);
	imap_match_deinit(&ctx->glob);
	i_free(ctx);
	return ret;
}

static int imapc_list_set_subscribed(struct mailbox_list *_list,
				     const char *name, bool set)
{
	struct imapc_mailbox_list *list = (struct imapc_mailbox_list *)_list;
	struct imapc_simple_context ctx;

	ctx.storage = list->storage;
	imapc_client_cmdf(list->storage->client,
			  imapc_list_simple_callback, &ctx,
			  set ? "SUBSCRIBE %s" : "UNSUBSCRIBE %s", name);
	imapc_client_run(list->storage->client);
	return ctx.ret;
}

static int
imapc_list_create_mailbox_dir(struct mailbox_list *list ATTR_UNUSED,
			      const char *name ATTR_UNUSED,
			      enum mailbox_dir_create_type type ATTR_UNUSED)
{
	/* this gets called just before mailbox.create().
	   we don't need to do anything. */
	return 0;
}

static int
imapc_list_delete_mailbox(struct mailbox_list *_list, const char *name)
{
	struct imapc_mailbox_list *list = (struct imapc_mailbox_list *)_list;
	struct imapc_simple_context ctx;

	ctx.storage = list->storage;
	imapc_client_cmdf(list->storage->client,
			  imapc_list_simple_callback, &ctx, "DELETE %s", name);
	imapc_client_run(list->storage->client);
	return ctx.ret;
}

static int
imapc_list_delete_dir(struct mailbox_list *list ATTR_UNUSED,
		      const char *name ATTR_UNUSED)
{
	return 0;
}

static int
imapc_list_rename_mailbox(struct mailbox_list *oldlist, const char *oldname,
			  struct mailbox_list *newlist, const char *newname,
			  bool rename_children)
{
	struct imapc_mailbox_list *list = (struct imapc_mailbox_list *)oldlist;
	struct imapc_simple_context ctx;

	if (!rename_children) {
		mailbox_list_set_error(oldlist, MAIL_ERROR_NOTPOSSIBLE,
			"Renaming without children not supported.");
		return -1;
	}

	if (oldlist != newlist) {
		mailbox_list_set_error(oldlist, MAIL_ERROR_NOTPOSSIBLE,
			"Can't rename mailboxes across storages.");
		return -1;
	}

	ctx.storage = list->storage;
	imapc_client_cmdf(list->storage->client,
			  imapc_list_simple_callback, &ctx,
			  "RENAME %s %s", oldname, newname);
	imapc_client_run(list->storage->client);
	return ctx.ret;
}

struct mailbox_list imapc_mailbox_list = {
	.name = MAILBOX_LIST_NAME_IMAPC,
	.props = 0,
	.mailbox_name_max_length = MAILBOX_LIST_NAME_MAX_LENGTH,

	{
		imapc_list_alloc,
		imapc_list_deinit,
		NULL,
		imapc_is_valid_pattern,
		imapc_is_valid_existing_name,
		imapc_is_valid_create_name,
		imapc_list_get_hierarchy_sep,
		mailbox_list_default_get_vname,
		mailbox_list_default_get_storage_name,
		imapc_list_get_path,
		imapc_list_get_temp_prefix,
		imapc_list_join_refpattern,
		imapc_list_iter_init,
		imapc_list_iter_next,
		imapc_list_iter_deinit,
		NULL,
		NULL,
		imapc_list_set_subscribed,
		imapc_list_create_mailbox_dir,
		imapc_list_delete_mailbox,
		imapc_list_delete_dir,
		imapc_list_rename_mailbox
	}
};
