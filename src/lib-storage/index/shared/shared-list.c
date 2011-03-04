/* Copyright (c) 2008-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "imap-match.h"
#include "mailbox-list-private.h"
#include "index-storage.h"
#include "shared-storage.h"

struct shared_mailbox_list_iterate_context {
	struct mailbox_list_iterate_context ctx;
	struct mail_namespace *cur_ns;
	struct imap_match_glob *glob;
	struct mailbox_info info;
};

extern struct mailbox_list shared_mailbox_list;

static struct mailbox_list *shared_list_alloc(void)
{
	struct mailbox_list *list;
	pool_t pool;

	pool = pool_alloconly_create("shared list", 1024);
	list = p_new(pool, struct mailbox_list, 1);
	*list = shared_mailbox_list;
	list->pool = pool;
	return list;
}

static void shared_list_deinit(struct mailbox_list *list)
{
	pool_unref(&list->pool);
}

static void shared_list_copy_error(struct mailbox_list *shared_list,
				   struct mail_namespace *backend_ns)
{
	const char *str;
	enum mail_error error;

	str = mailbox_list_get_last_error(backend_ns->list, &error);
	mailbox_list_set_error(shared_list, error, str);
}

static int
shared_get_storage(struct mailbox_list **list, const char **name,
		   struct mail_storage **storage_r)
{
	struct mail_namespace *ns = (*list)->ns;

	if (shared_storage_get_namespace(&ns, name) < 0)
		return -1;
	*list = ns->list;
	*storage_r = ns->storage;
	return 0;
}

static bool
shared_is_valid_pattern(struct mailbox_list *list, const char *pattern)
{
	struct mail_namespace *ns = list->ns;

	if (shared_storage_get_namespace(&ns, &pattern) < 0)
		return FALSE;
	return mailbox_list_is_valid_pattern(ns->list, pattern);
}

static bool
shared_is_valid_existing_name(struct mailbox_list *list, const char *name)
{
	struct mail_namespace *ns = list->ns;

	if (shared_storage_get_namespace(&ns, &name) < 0)
		return FALSE;
	return mailbox_list_is_valid_existing_name(ns->list, name);
}

static bool
shared_is_valid_create_name(struct mailbox_list *list, const char *name)
{
	struct mail_namespace *ns = list->ns;

	if (shared_storage_get_namespace(&ns, &name) < 0)
		return FALSE;
	return mailbox_list_is_valid_create_name(ns->list, name);
}

static const char *
shared_list_get_path(struct mailbox_list *list, const char *name,
		     enum mailbox_list_path_type type)
{
	struct mail_namespace *ns = list->ns;

	if (list->ns->storage == NULL || name == NULL ||
	    shared_storage_get_namespace(&ns, &name) < 0) {
		switch (type) {
		case MAILBOX_LIST_PATH_TYPE_DIR:
		case MAILBOX_LIST_PATH_TYPE_ALT_DIR:
		case MAILBOX_LIST_PATH_TYPE_MAILBOX:
		case MAILBOX_LIST_PATH_TYPE_ALT_MAILBOX:
		case MAILBOX_LIST_PATH_TYPE_CONTROL:
			break;
		case MAILBOX_LIST_PATH_TYPE_INDEX:
			/* we can safely say we don't use indexes */
			return "";
		}
		/* we don't have a directory we can use. */
		return NULL;
	}
	return mailbox_list_get_path(ns->list, name, type);
}

static int
shared_list_get_mailbox_name_status(struct mailbox_list *list, const char *name,
				    enum mailbox_name_status *status_r)
{
	struct mail_namespace *ns = list->ns;
	int ret;

	if (shared_storage_get_namespace(&ns, &name) < 0)
		return -1;
	ret = mailbox_list_get_mailbox_name_status(ns->list, name, status_r);
	if (ret < 0)
		shared_list_copy_error(list, ns);
	return ret;
}

static const char *
shared_list_get_temp_prefix(struct mailbox_list *list, bool global ATTR_UNUSED)
{
	i_panic("shared mailbox list: Can't return a temp prefix for '%s'",
		list->ns->prefix);
	return NULL;
}

static const char *
shared_list_join_refpattern(struct mailbox_list *list,
			    const char *ref, const char *pattern)
{
	struct mail_namespace *ns = list->ns;
	const char *ns_ref, *prefix = list->ns->prefix;
	unsigned int prefix_len = strlen(prefix);

	if (*ref != '\0' && strncmp(ref, prefix, prefix_len) == 0)
		ns_ref = ref + prefix_len;
	else
		ns_ref = NULL;

	if (ns_ref != NULL && shared_storage_get_namespace(&ns, &ns_ref) == 0)
		return mailbox_list_join_refpattern(ns->list, ref, pattern);

	/* fallback to default behavior */
	if (*ref != '\0')
		pattern = t_strconcat(ref, pattern, NULL);
	return pattern;
}

static struct mailbox_list_iterate_context *
shared_list_iter_init(struct mailbox_list *list, const char *const *patterns,
		      enum mailbox_list_iter_flags flags)
{
	struct shared_mailbox_list_iterate_context *ctx;

	ctx = i_new(struct shared_mailbox_list_iterate_context, 1);
	ctx->ctx.list = list;
	ctx->ctx.flags = flags;
	ctx->cur_ns = list->ns->user->namespaces;
	ctx->info.ns = list->ns;
	ctx->info.flags = MAILBOX_NONEXISTENT;
	ctx->glob = imap_match_init_multiple(default_pool, patterns,
					     FALSE, list->ns->sep);
	return &ctx->ctx;
}

static const struct mailbox_info *
shared_list_iter_next(struct mailbox_list_iterate_context *_ctx)
{
	struct shared_mailbox_list_iterate_context *ctx =
		(struct shared_mailbox_list_iterate_context *)_ctx;
	struct mail_namespace *ns = ctx->cur_ns;

	for (; ns != NULL; ns = ns->next) {
		if (ns->type != NAMESPACE_SHARED ||
		    (ns->flags & NAMESPACE_FLAG_AUTOCREATED) == 0)
			continue;
		if ((ns->flags & (NAMESPACE_FLAG_LIST_PREFIX |
				  NAMESPACE_FLAG_LIST_CHILDREN)) == 0)
			continue;

		if (ns->prefix_len < ctx->info.ns->prefix_len ||
		    strncmp(ns->prefix, ctx->info.ns->prefix,
			    ctx->info.ns->prefix_len) != 0)
			continue;

		/* visible and listable namespace under ourself, see if the
		   prefix matches without the trailing separator */
		i_assert(ns->prefix_len > 0);
		ctx->info.name = t_strndup(ns->prefix, ns->prefix_len - 1);
		if (imap_match(ctx->glob, ctx->info.name) == IMAP_MATCH_YES) {
			ctx->cur_ns = ns->next;
			return &ctx->info;
		}
	}

	ctx->cur_ns = NULL;
	return NULL;
}

static int shared_list_iter_deinit(struct mailbox_list_iterate_context *_ctx)
{
	struct shared_mailbox_list_iterate_context *ctx =
		(struct shared_mailbox_list_iterate_context *)_ctx;

	imap_match_deinit(&ctx->glob);
	i_free(ctx);
	return 0;
}

static int shared_list_set_subscribed(struct mailbox_list *list,
				      const char *name, bool set)
{
	struct mail_namespace *ns = list->ns;
	int ret;

	if (shared_storage_get_namespace(&ns, &name) < 0)
		return -1;
	ret = mailbox_list_set_subscribed(ns->list, name, set);
	if (ret < 0)
		shared_list_copy_error(list, ns);
	return ret;
}

static int
shared_list_create_mailbox_dir(struct mailbox_list *list, const char *name,
			       enum mailbox_dir_create_type type)
{
	struct mail_namespace *ns = list->ns;
	int ret;

	if (shared_storage_get_namespace(&ns, &name) < 0)
		return -1;
	ret = ns->list->v.create_mailbox_dir(ns->list, name, type);
	if (ret < 0)
		shared_list_copy_error(list, ns);
	return ret;
}

static int
shared_list_delete_mailbox(struct mailbox_list *list, const char *name)
{
	struct mail_namespace *ns = list->ns;
	int ret;

	if (shared_storage_get_namespace(&ns, &name) < 0)
		return -1;
	ret = ns->list->v.delete_mailbox(ns->list, name);
	if (ret < 0)
		shared_list_copy_error(list, ns);
	return ret;
}

static int
shared_list_delete_dir(struct mailbox_list *list, const char *name)
{
	struct mail_namespace *ns = list->ns;
	int ret;

	if (shared_storage_get_namespace(&ns, &name) < 0)
		return -1;
	ret = mailbox_list_delete_dir(ns->list, name);
	if (ret < 0)
		shared_list_copy_error(list, ns);
	return ret;
}

static int shared_list_rename_get_ns(struct mailbox_list *oldlist,
				     const char **oldname,
				     struct mailbox_list *newlist,
				     const char **newname,
				     struct mail_namespace **ns_r)
{
	struct mail_namespace *old_ns = oldlist->ns, *new_ns = newlist->ns;

	if (shared_storage_get_namespace(&old_ns, oldname) < 0 ||
	    shared_storage_get_namespace(&new_ns, newname) < 0)
		return -1;
	if (old_ns != new_ns) {
		mailbox_list_set_error(oldlist, MAIL_ERROR_NOTPOSSIBLE,
			"Can't rename shared mailboxes across storages.");
		return -1;
	}
	*ns_r = old_ns;
	return 0;
}

static int
shared_list_rename_mailbox(struct mailbox_list *oldlist, const char *oldname,
			   struct mailbox_list *newlist, const char *newname,
			   bool rename_children)
{
	struct mail_namespace *ns;
	int ret;

	if (shared_list_rename_get_ns(oldlist, &oldname,
				      newlist, &newname, &ns) < 0)
		return -1;

	ret = ns->list->v.rename_mailbox(ns->list, oldname, ns->list, newname,
					 rename_children);
	if (ret < 0)
		shared_list_copy_error(oldlist, ns);
	return ret;
}

struct mailbox_list shared_mailbox_list = {
	.name = "shared",
	.hierarchy_sep = '/',
	.props = 0,
	.mailbox_name_max_length = MAILBOX_LIST_NAME_MAX_LENGTH,

	{
		shared_list_alloc,
		shared_list_deinit,
		shared_get_storage,
		shared_is_valid_pattern,
		shared_is_valid_existing_name,
		shared_is_valid_create_name,
		shared_list_get_path,
		shared_list_get_mailbox_name_status,
		shared_list_get_temp_prefix,
		shared_list_join_refpattern,
		shared_list_iter_init,
		shared_list_iter_next,
		shared_list_iter_deinit,
		NULL,
		NULL,
		shared_list_set_subscribed,
		shared_list_create_mailbox_dir,
		shared_list_delete_mailbox,
		shared_list_delete_dir,
		shared_list_rename_mailbox
	}
};
