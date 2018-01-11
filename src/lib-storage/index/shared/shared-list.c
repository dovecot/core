/* Copyright (c) 2008-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "imap-match.h"
#include "mailbox-tree.h"
#include "mailbox-list-private.h"
#include "index-storage.h"
#include "shared-storage.h"

extern struct mailbox_list shared_mailbox_list;

static struct mailbox_list *shared_list_alloc(void)
{
	struct mailbox_list *list;
	pool_t pool;

	pool = pool_alloconly_create("shared list", 2048);
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
shared_get_storage(struct mailbox_list **list, const char *vname,
		   struct mail_storage **storage_r)
{
	struct mail_namespace *ns = (*list)->ns;
	const char *name;

	name = mailbox_list_get_storage_name(*list, vname);
	if (*name == '\0' && (ns->flags & NAMESPACE_FLAG_AUTOCREATED) == 0) {
		/* trying to access the shared/ prefix itself */
		*storage_r = ns->storage;
		return 0;
	}

	if (shared_storage_get_namespace(&ns, &name) < 0)
		return -1;
	*list = ns->list;
	return mailbox_list_get_storage(list, vname, storage_r);
}

static char shared_list_get_hierarchy_sep(struct mailbox_list *list ATTR_UNUSED)
{
	return '/';
}

static int
shared_list_get_path(struct mailbox_list *list, const char *name,
		     enum mailbox_list_path_type type, const char **path_r)
{
	struct mail_namespace *ns = list->ns;

	if (mail_namespace_get_default_storage(list->ns) == NULL ||
	    name == NULL ||
	    shared_storage_get_namespace(&ns, &name) < 0) {
		/* we don't have a directory we can use. */
		*path_r = NULL;
		return 0;
	}
	return mailbox_list_get_path(ns->list, name, type, path_r);
}

static const char *
shared_list_get_temp_prefix(struct mailbox_list *list, bool global ATTR_UNUSED)
{
	i_panic("shared mailbox list: Can't return a temp prefix for '%s'",
		list->ns->prefix);
}

static const char *
shared_list_join_refpattern(struct mailbox_list *list,
			    const char *ref, const char *pattern)
{
	struct mail_namespace *ns = list->ns;
	const char *ns_ref, *prefix = list->ns->prefix;
	size_t prefix_len = strlen(prefix);

	if (*ref != '\0' && str_begins(ref, prefix))
		ns_ref = ref + prefix_len;
	else
		ns_ref = NULL;

	if (ns_ref != NULL && *ns_ref != '\0' &&
	    shared_storage_get_namespace(&ns, &ns_ref) == 0)
		return mailbox_list_join_refpattern(ns->list, ref, pattern);

	/* fallback to default behavior */
	if (*ref != '\0')
		pattern = t_strconcat(ref, pattern, NULL);
	return pattern;
}

static void
shared_list_create_missing_namespaces(struct mailbox_list *list,
				      const char *const *patterns)
{
	struct mail_namespace *ns;
	char sep = mail_namespace_get_sep(list->ns);
	const char *list_pat, *name;
	unsigned int i;

	for (i = 0; patterns[i] != NULL; i++) {
		const char *last = NULL, *p;

		/* we'll require that the pattern begins with the list's
		   namespace prefix. we could also handle other patterns
		   (e.g. %/user/%), but it's more of a theoretical problem. */
		if (strncmp(list->ns->prefix, patterns[i],
			    list->ns->prefix_len) != 0)
			continue;
		list_pat = patterns[i] + list->ns->prefix_len;

		for (p = list_pat; *p != '\0'; p++) {
			if (*p == '%' || *p == '*')
				break;
			if (*p == sep)
				last = p;
		}
		if (last != NULL) {
			ns = list->ns;
			name = t_strdup_until(list_pat, last);
			(void)shared_storage_get_namespace(&ns, &name);
		}
	}
}

static struct mailbox_list_iterate_context *
shared_list_iter_init(struct mailbox_list *list, const char *const *patterns,
		      enum mailbox_list_iter_flags flags)
{
	struct mailbox_list_iterate_context *ctx;
	pool_t pool;
	char sep = mail_namespace_get_sep(list->ns);

	pool = pool_alloconly_create("mailbox list shared iter", 1024);
	ctx = p_new(pool, struct mailbox_list_iterate_context, 1);
	ctx->pool = pool;
	ctx->list = list;
	ctx->flags = flags;
	ctx->glob = imap_match_init_multiple(pool, patterns, FALSE, sep);
	array_create(&ctx->module_contexts, pool, sizeof(void *), 5);

	if ((flags & MAILBOX_LIST_ITER_SELECT_SUBSCRIBED) == 0 &&
	    (list->ns->flags & NAMESPACE_FLAG_AUTOCREATED) == 0) T_BEGIN {
		shared_list_create_missing_namespaces(list, patterns);
	} T_END;
	return ctx;
}

static const struct mailbox_info *
shared_list_iter_next(struct mailbox_list_iterate_context *ctx ATTR_UNUSED)
{
	return NULL;
}

static int shared_list_iter_deinit(struct mailbox_list_iterate_context *ctx)
{
	pool_unref(&ctx->pool);
	return 0;
}

static int
shared_list_subscriptions_refresh(struct mailbox_list *src_list,
				  struct mailbox_list *dest_list)
{
	char sep;

	if (dest_list->subscriptions == NULL) {
		sep = mail_namespace_get_sep(src_list->ns);
		dest_list->subscriptions = mailbox_tree_init(sep);
	}
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

static int
shared_list_delete_symlink(struct mailbox_list *list, const char *name)
{
	struct mail_namespace *ns = list->ns;
	int ret;

	if (shared_storage_get_namespace(&ns, &name) < 0)
		return -1;
	ret = mailbox_list_delete_symlink(ns->list, name);
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
			   struct mailbox_list *newlist, const char *newname)
{
	struct mail_namespace *ns;
	int ret;

	if (shared_list_rename_get_ns(oldlist, &oldname,
				      newlist, &newname, &ns) < 0)
		return -1;

	ret = ns->list->v.rename_mailbox(ns->list, oldname, ns->list, newname);
	if (ret < 0)
		shared_list_copy_error(oldlist, ns);
	return ret;
}

struct mailbox_list shared_mailbox_list = {
	.name = "shared",
	.props = 0,
	.mailbox_name_max_length = MAILBOX_LIST_NAME_MAX_LENGTH,

	.v = {
		.alloc = shared_list_alloc,
		.deinit = shared_list_deinit,
		.get_storage = shared_get_storage,
		.get_hierarchy_sep = shared_list_get_hierarchy_sep,
		.get_vname = mailbox_list_default_get_vname,
		.get_storage_name = mailbox_list_default_get_storage_name,
		.get_path = shared_list_get_path,
		.get_temp_prefix = shared_list_get_temp_prefix,
		.join_refpattern = shared_list_join_refpattern,
		.iter_init = shared_list_iter_init,
		.iter_next = shared_list_iter_next,
		.iter_deinit = shared_list_iter_deinit,
		.subscriptions_refresh = shared_list_subscriptions_refresh,
		.set_subscribed = shared_list_set_subscribed,
		.delete_mailbox = shared_list_delete_mailbox,
		.delete_dir = shared_list_delete_dir,
		.delete_symlink = shared_list_delete_symlink,
		.rename_mailbox = shared_list_rename_mailbox,
	}
};
