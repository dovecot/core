/* Copyright (c) 2011-2012 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "imap-arg.h"
#include "imap-match.h"
#include "imap-utf7.h"
#include "mailbox-tree.h"
#include "mailbox-list-subscriptions.h"
#include "imapc-client.h"
#include "imapc-storage.h"
#include "imapc-list.h"

struct imapc_mailbox_list_iterate_context {
	struct mailbox_list_iterate_context ctx;
	struct mailbox_tree_context *tree;
	struct mailbox_node *ns_root;

	struct mailbox_tree_iterate_context *iter;
	struct mailbox_info info;
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
	/* separator is set when storage is created */
	list->mailboxes = mailbox_tree_init('\0');
	mailbox_tree_set_parents_nonexistent(list->mailboxes);
	return &list->list;
}

static void imapc_list_deinit(struct mailbox_list *_list)
{
	struct imapc_mailbox_list *list = (struct imapc_mailbox_list *)_list;

	if (list->index_list != NULL)
		mailbox_list_destroy(&list->index_list);
	mailbox_tree_deinit(&list->mailboxes);
	if (list->tmp_subscriptions != NULL)
		mailbox_tree_deinit(&list->tmp_subscriptions);
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
imapc_list_update_tree(struct imapc_mailbox_list *list,
		       struct mailbox_tree_context *tree,
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

	T_BEGIN {
		const char *vname =
			mailbox_list_get_vname(&list->list, name);

		if ((info_flags & MAILBOX_NONEXISTENT) != 0)
			node = mailbox_tree_lookup(tree, vname);
		else
			node = mailbox_tree_get(tree, vname, &created);
	} T_END;
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
		mailbox_tree_set_separator(list->mailboxes, list->sep);
	} else {
		(void)imapc_list_update_tree(list, list->mailboxes, args);
	}
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
	node = imapc_list_update_tree(list, list->tmp_subscriptions != NULL ?
				      list->tmp_subscriptions :
				      list->list.subscriptions, args);
	if (node != NULL) {
		if ((node->flags & MAILBOX_NOSELECT) == 0)
			node->flags |= MAILBOX_SUBSCRIBED;
		else {
			/* LSUB \Noselect means that the mailbox isn't
			   subscribed, but it has children that are */
			node->flags &= ~MAILBOX_NOSELECT;
		}
	}
}

void imapc_list_register_callbacks(struct imapc_mailbox_list *list)
{
	imapc_storage_register_untagged(list->storage, "LIST",
					imapc_untagged_list);
	imapc_storage_register_untagged(list->storage, "LSUB",
					imapc_untagged_lsub);
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

	/* storage should have looked this up when it was created */
	i_assert(list->sep != '\0');

	return list->sep;
}

static const char *
imapc_list_get_storage_name(struct mailbox_list *_list, const char *vname)
{
	struct imapc_mailbox_list *list = (struct imapc_mailbox_list *)_list;
	const char *prefix = list->storage->set->imapc_list_prefix;
	const char *storage_name;

	storage_name = mailbox_list_default_get_storage_name(_list, vname);
	if (*prefix != '\0' && strcasecmp(storage_name, "INBOX") != 0) {
		storage_name = t_strdup_printf("%s%c%s", prefix, list->sep,
					       storage_name);
	}
	return storage_name;
}

static const char *
imapc_list_get_vname(struct mailbox_list *_list, const char *storage_name)
{
	struct imapc_mailbox_list *list = (struct imapc_mailbox_list *)_list;
	const char *prefix = list->storage->set->imapc_list_prefix;
	unsigned int prefix_len;

	if (*prefix != '\0' && strcasecmp(storage_name, "INBOX") != 0) {
		prefix_len = strlen(prefix);
		i_assert(strncmp(prefix, storage_name, prefix_len) == 0 &&
			 storage_name[prefix_len] == list->sep);
		storage_name += prefix_len+1;
	}
	return mailbox_list_default_get_vname(_list, storage_name);
}

static struct mailbox_list *imapc_list_get_fs(struct imapc_mailbox_list *list)
{
	struct mailbox_list_settings list_set;
	const char *error, *dir;

	dir = list->list.set.index_dir;
	if (dir == NULL)
		dir = list->list.set.root_dir;

	if (dir == NULL) {
		/* indexes disabled */
	} else if (list->index_list == NULL && !list->index_list_failed) {
		memset(&list_set, 0, sizeof(list_set));
		list_set.layout = MAILBOX_LIST_NAME_MAILDIRPLUSPLUS;
		list_set.root_dir = dir;
		list_set.escape_char = IMAPC_LIST_ESCAPE_CHAR;
		list_set.mailbox_dir_name = "";
		list_set.maildir_name = "";

		if (mailbox_list_create(list_set.layout, list->list.ns,
					&list_set, MAILBOX_LIST_FLAG_SECONDARY,
					&list->index_list, &error) < 0) {
			i_error("imapc: Couldn't create %s mailbox list: %s",
				list_set.layout, error);
			list->index_list_failed = TRUE;
		}
	}
	return list->index_list;
}

static const char *
imapc_list_get_fs_name(struct imapc_mailbox_list *list, const char *name)
{
	struct mailbox_list *fs_list = imapc_list_get_fs(list);
	const char *vname;

	if (name == NULL)
		return name;

	vname = mailbox_list_get_vname(&list->list, name);
	return mailbox_list_get_storage_name(fs_list, vname);
}

static const char *
imapc_list_get_path(struct mailbox_list *_list, const char *name,
		    enum mailbox_list_path_type type)
{
	struct imapc_mailbox_list *list = (struct imapc_mailbox_list *)_list;
	struct mailbox_list *fs_list = imapc_list_get_fs(list);
	const char *fs_name;

	if (fs_list != NULL) {
		fs_name = imapc_list_get_fs_name(list, name);
		return mailbox_list_get_path(fs_list, fs_name, type);
	} else {
		if (type == MAILBOX_LIST_PATH_TYPE_INDEX)
			return "";
		return NULL;
	}
}

static const char *
imapc_list_get_temp_prefix(struct mailbox_list *_list, bool global)
{
	struct imapc_mailbox_list *list = (struct imapc_mailbox_list *)_list;
	struct mailbox_list *fs_list = imapc_list_get_fs(list);

	if (fs_list != NULL) {
		return global ?
			mailbox_list_get_global_temp_prefix(fs_list) :
			mailbox_list_get_temp_prefix(fs_list);
	} else {
		i_panic("imapc: Can't return a temp prefix for '%s'",
			_list->ns->prefix);
		return NULL;
	}
}

static const char *
imapc_list_join_refpattern(struct mailbox_list *list ATTR_UNUSED,
			   const char *ref, const char *pattern)
{
	return t_strconcat(ref, pattern, NULL);
}

static struct imapc_command *
imapc_list_simple_context_init(struct imapc_simple_context *ctx,
			       struct imapc_mailbox_list *list)
{
	imapc_simple_context_init(ctx, list->storage);
	return imapc_client_cmd(list->storage->client,
				imapc_list_simple_callback, ctx);
}

static void imapc_list_delete_unused_indexes(struct imapc_mailbox_list *list)
{
	struct mailbox_list *fs_list = imapc_list_get_fs(list);
	struct mailbox_list_iterate_context *iter;
	const struct mailbox_info *info;
	const char *fs_name;

	if (fs_list == NULL)
		return;

	iter = mailbox_list_iter_init(fs_list, "*",
				      MAILBOX_LIST_ITER_RAW_LIST |
				      MAILBOX_LIST_ITER_NO_AUTO_BOXES |
				      MAILBOX_LIST_ITER_RETURN_NO_FLAGS);
	while ((info = mailbox_list_iter_next(iter)) != NULL) {
		if (mailbox_tree_lookup(list->mailboxes, info->vname) == NULL) {
			fs_name = mailbox_list_get_storage_name(fs_list,
								info->vname);
			(void)fs_list->v.delete_mailbox(fs_list, fs_name);
		}
	}
	(void)mailbox_list_iter_deinit(&iter);
}

static int imapc_list_refresh(struct imapc_mailbox_list *list)
{
	struct imapc_command *cmd;
	struct imapc_simple_context ctx;
	const char *pattern;

	i_assert(list->sep != '\0');

	if (list->refreshed_mailboxes)
		return 0;

	if (*list->storage->set->imapc_list_prefix == '\0')
		pattern = "*";
	else {
		pattern = t_strdup_printf("%s%c*",
			list->storage->set->imapc_list_prefix, list->sep);
	}

	cmd = imapc_list_simple_context_init(&ctx, list);
	imapc_command_sendf(cmd, "LIST \"\" %s", pattern);
	mailbox_tree_deinit(&list->mailboxes);
	list->mailboxes = mailbox_tree_init(list->sep);
	mailbox_tree_set_parents_nonexistent(list->mailboxes);

	if ((list->list.ns->flags & NAMESPACE_FLAG_INBOX_USER) != 0) {
		/* INBOX always exists in IMAP server. since this namespace is
		   marked with inbox=yes, show the INBOX even if
		   imapc_list_prefix doesn't match it */
		bool created;
		(void)mailbox_tree_get(list->mailboxes, "INBOX", &created);
	}

	imapc_simple_run(&ctx);
	if (ctx.ret == 0) {
		list->refreshed_mailboxes = TRUE;
		imapc_list_delete_unused_indexes(list);
	}
	return ctx.ret;
}

static void
imapc_list_build_match_tree(struct imapc_mailbox_list_iterate_context *ctx)
{
	struct imapc_mailbox_list *list =
		(struct imapc_mailbox_list *)ctx->ctx.list;
	struct mailbox_list_iter_update_context update_ctx;
	struct mailbox_tree_iterate_context *iter;
	struct mailbox_node *node;
	const char *name;

	memset(&update_ctx, 0, sizeof(update_ctx));
	update_ctx.iter_ctx = &ctx->ctx;
	update_ctx.tree_ctx = ctx->tree;
	update_ctx.glob = ctx->ctx.glob;
	update_ctx.match_parents = TRUE;

	iter = mailbox_tree_iterate_init(list->mailboxes, NULL, 0);
	while ((node = mailbox_tree_iterate_next(iter, &name)) != NULL) {
		update_ctx.leaf_flags = node->flags;
		mailbox_list_iter_update(&update_ctx, name);
	}
	mailbox_tree_iterate_deinit(&iter);
}

static struct mailbox_list_iterate_context *
imapc_list_iter_init(struct mailbox_list *_list, const char *const *patterns,
		     enum mailbox_list_iter_flags flags)
{
	struct imapc_mailbox_list *list = (struct imapc_mailbox_list *)_list;
	struct mailbox_list_iterate_context *_ctx;
	struct imapc_mailbox_list_iterate_context *ctx;
	pool_t pool;
	const char *ns_root_name;
	char sep;
	int ret = 0;

	if ((flags & MAILBOX_LIST_ITER_SELECT_SUBSCRIBED) == 0 ||
	    (flags & MAILBOX_LIST_ITER_RETURN_NO_FLAGS) == 0)
		ret = imapc_list_refresh(list);

	list->iter_count++;

	if ((flags & MAILBOX_LIST_ITER_SELECT_SUBSCRIBED) != 0) {
		/* we're listing only subscriptions. just use the cached
		   subscriptions list. */
		_ctx = mailbox_list_subscriptions_iter_init(_list, patterns,
							    flags);
		if (ret < 0)
			_ctx->failed = TRUE;
		return _ctx;
	}

	sep = mailbox_list_get_hierarchy_sep(_list);

	pool = pool_alloconly_create("mailbox list imapc iter", 1024);
	ctx = p_new(pool, struct imapc_mailbox_list_iterate_context, 1);
	ctx->ctx.pool = pool;
	ctx->ctx.list = _list;
	ctx->ctx.flags = flags;
	ctx->ctx.glob = imap_match_init_multiple(pool, patterns, FALSE, sep);
	array_create(&ctx->ctx.module_contexts, pool, sizeof(void *), 5);

	ctx->info.ns = _list->ns;

	ctx->tree = mailbox_tree_init(sep);
	mailbox_tree_set_parents_nonexistent(ctx->tree);
	imapc_list_build_match_tree(ctx);

	if (list->list.ns->prefix_len > 0) {
		ns_root_name = t_strndup(_list->ns->prefix,
					 _list->ns->prefix_len - 1);
		ctx->ns_root = mailbox_tree_lookup(ctx->tree, ns_root_name);
	}

	ctx->iter = mailbox_tree_iterate_init(ctx->tree, NULL, 0);
	if (ret < 0)
		ctx->ctx.failed = TRUE;
	return &ctx->ctx;
}

static const struct mailbox_info *
imapc_list_iter_next(struct mailbox_list_iterate_context *_ctx)
{
	struct imapc_mailbox_list_iterate_context *ctx =
		(struct imapc_mailbox_list_iterate_context *)_ctx;
	struct mailbox_node *node;
	const char *vname;

	if (_ctx->failed)
		return NULL;

	if ((_ctx->flags & MAILBOX_LIST_ITER_SELECT_SUBSCRIBED) != 0)
		return mailbox_list_subscriptions_iter_next(_ctx);

	do {
		node = mailbox_tree_iterate_next(ctx->iter, &vname);
		if (node == NULL)
			return NULL;
	} while ((node->flags & MAILBOX_MATCHED) == 0);

	ctx->info.vname = vname;
	ctx->info.flags = node->flags;
	return &ctx->info;
}

static int imapc_list_iter_deinit(struct mailbox_list_iterate_context *_ctx)
{
	struct imapc_mailbox_list_iterate_context *ctx =
		(struct imapc_mailbox_list_iterate_context *)_ctx;
	struct imapc_mailbox_list *list =
		(struct imapc_mailbox_list *)_ctx->list;
	int ret = _ctx->failed ? -1 : 0;

	i_assert(list->iter_count > 0);

	if (--list->iter_count == 0) {
		list->refreshed_mailboxes = FALSE;
		list->refreshed_subscriptions = FALSE;
	}

	if ((_ctx->flags & MAILBOX_LIST_ITER_SELECT_SUBSCRIBED) != 0)
		return mailbox_list_subscriptions_iter_deinit(_ctx);

	mailbox_tree_iterate_deinit(&ctx->iter);
	mailbox_tree_deinit(&ctx->tree);
	pool_unref(&_ctx->pool);
	return ret;
}

static int
imapc_list_subscriptions_refresh(struct mailbox_list *_src_list,
				 struct mailbox_list *dest_list)
{
	struct imapc_mailbox_list *src_list =
		(struct imapc_mailbox_list *)_src_list;
	struct imapc_simple_context ctx;
	struct imapc_command *cmd;
	const char *pattern;
	char sep;

	i_assert(src_list->tmp_subscriptions == NULL);

	if (src_list->refreshed_subscriptions) {
		if (dest_list->subscriptions == NULL) {
			sep = mailbox_list_get_hierarchy_sep(dest_list);
			dest_list->subscriptions =
				mailbox_tree_init(sep);
		}
		return 0;
	}

	if (src_list->sep == '\0')
		(void)mailbox_list_get_hierarchy_sep(_src_list);

	src_list->tmp_subscriptions = mailbox_tree_init(src_list->sep);

	cmd = imapc_list_simple_context_init(&ctx, src_list);
	if (*src_list->storage->set->imapc_list_prefix == '\0')
		pattern = "*";
	else {
		pattern = t_strdup_printf("%s%c*",
				src_list->storage->set->imapc_list_prefix,
				src_list->sep);
	}
	imapc_command_sendf(cmd, "LSUB \"\" %s", pattern);
	imapc_simple_run(&ctx);

	/* replace subscriptions tree in destination */
	mailbox_tree_set_separator(src_list->tmp_subscriptions,
				   mailbox_list_get_hierarchy_sep(dest_list));
	if (dest_list->subscriptions != NULL)
		mailbox_tree_deinit(&dest_list->subscriptions);
	dest_list->subscriptions = src_list->tmp_subscriptions;
	src_list->tmp_subscriptions = NULL;

	src_list->refreshed_subscriptions = TRUE;
	return 0;
}

static int imapc_list_set_subscribed(struct mailbox_list *_list,
				     const char *name, bool set)
{
	struct imapc_mailbox_list *list = (struct imapc_mailbox_list *)_list;
	struct imapc_command *cmd;
	struct imapc_simple_context ctx;

	cmd = imapc_list_simple_context_init(&ctx, list);
	imapc_command_sendf(cmd, set ? "SUBSCRIBE %s" : "UNSUBSCRIBE %s", name);
	imapc_simple_run(&ctx);
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
	struct mailbox_list *fs_list = imapc_list_get_fs(list);
	struct imapc_command *cmd;
	struct imapc_simple_context ctx;

	cmd = imapc_list_simple_context_init(&ctx, list);
	imapc_command_sendf(cmd, "DELETE %s", name);
	imapc_simple_run(&ctx);

	if (fs_list != NULL && ctx.ret == 0) {
		name = imapc_list_get_fs_name(list, name);
		(void)fs_list->v.delete_mailbox(fs_list, name);
	}
	return ctx.ret;
}

static int
imapc_list_delete_dir(struct mailbox_list *_list, const char *name)
{
	struct imapc_mailbox_list *list = (struct imapc_mailbox_list *)_list;
	struct mailbox_list *fs_list = imapc_list_get_fs(list);

	if (fs_list != NULL) {
		name = imapc_list_get_fs_name(list, name);
		(void)mailbox_list_delete_dir(fs_list, name);
	}
	return 0;
}

static int
imapc_list_delete_symlink(struct mailbox_list *list,
			  const char *name ATTR_UNUSED)
{
	mailbox_list_set_error(list, MAIL_ERROR_NOTPOSSIBLE, "Not supported");
	return -1;
}

static int
imapc_list_rename_mailbox(struct mailbox_list *oldlist, const char *oldname,
			  struct mailbox_list *newlist, const char *newname,
			  bool rename_children)
{
	struct imapc_mailbox_list *list = (struct imapc_mailbox_list *)oldlist;
	struct mailbox_list *fs_list = imapc_list_get_fs(list);
	struct imapc_command *cmd;
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

	cmd = imapc_list_simple_context_init(&ctx, list);
	imapc_command_sendf(cmd, "RENAME %s %s", oldname, newname);
	imapc_simple_run(&ctx);
	if (ctx.ret == 0 && fs_list != NULL && oldlist == newlist) {
		oldname = imapc_list_get_fs_name(list, oldname);
		newname = imapc_list_get_fs_name(list, newname);
		(void)fs_list->v.rename_mailbox(fs_list, oldname,
						fs_list, newname,
						rename_children);
	}
	return ctx.ret;
}

int imapc_list_get_mailbox_flags(struct mailbox_list *_list, const char *name,
				 enum mailbox_info_flags *flags_r)
{
	struct imapc_mailbox_list *list = (struct imapc_mailbox_list *)_list;
	struct imapc_command *cmd;
	struct imapc_simple_context sctx;
	struct mailbox_node *node;
	const char *vname;

	i_assert(list->sep != '\0');

	vname = mailbox_list_get_vname(_list, name);
	if (!list->refreshed_mailboxes) {
		node = mailbox_tree_lookup(list->mailboxes, vname);
		if (node != NULL)
			node->flags |= MAILBOX_NONEXISTENT;

		/* refresh the mailbox flags */
		cmd = imapc_list_simple_context_init(&sctx, list);
		imapc_command_sendf(cmd, "LIST \"\" %s", name);
		imapc_simple_run(&sctx);
		if (sctx.ret < 0)
			return -1;
	}

	node = mailbox_tree_lookup(list->mailboxes, vname);
	if (node == NULL)
		*flags_r = MAILBOX_NONEXISTENT;
	else
		*flags_r = node->flags;
	return 0;
}

struct mailbox_list imapc_mailbox_list = {
	.name = MAILBOX_LIST_NAME_IMAPC,
	.props = MAILBOX_LIST_PROP_NO_ROOT | MAILBOX_LIST_PROP_AUTOCREATE_DIRS,
	.mailbox_name_max_length = MAILBOX_LIST_NAME_MAX_LENGTH,

	{
		imapc_list_alloc,
		imapc_list_deinit,
		NULL,
		imapc_is_valid_pattern,
		imapc_is_valid_existing_name,
		imapc_is_valid_create_name,
		imapc_list_get_hierarchy_sep,
		imapc_list_get_vname,
		imapc_list_get_storage_name,
		imapc_list_get_path,
		imapc_list_get_temp_prefix,
		imapc_list_join_refpattern,
		imapc_list_iter_init,
		imapc_list_iter_next,
		imapc_list_iter_deinit,
		NULL,
		NULL,
		imapc_list_subscriptions_refresh,
		imapc_list_set_subscribed,
		imapc_list_create_mailbox_dir,
		imapc_list_delete_mailbox,
		imapc_list_delete_dir,
		imapc_list_delete_symlink,
		imapc_list_rename_mailbox
	}
};
