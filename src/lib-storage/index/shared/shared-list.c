/* Copyright (c) 2008-2012 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "imap-match.h"
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
	} else {
		if (shared_storage_get_namespace(&ns, &name) < 0)
			return -1;
	}
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

static char shared_list_get_hierarchy_sep(struct mailbox_list *list ATTR_UNUSED)
{
	return '/';
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
		case MAILBOX_LIST_PATH_TYPE_INDEX_PRIVATE:
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
			name = t_strdup_until(list_pat, last);
			(void)mailbox_list_is_valid_existing_name(list, name);
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
shared_list_subscriptions_refresh(struct mailbox_list *src_list ATTR_UNUSED,
				  struct mailbox_list *dest_list ATTR_UNUSED)
{
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
	.props = 0,
	.mailbox_name_max_length = MAILBOX_LIST_NAME_MAX_LENGTH,

	{
		shared_list_alloc,
		shared_list_deinit,
		shared_get_storage,
		shared_is_valid_pattern,
		shared_is_valid_existing_name,
		shared_is_valid_create_name,
		shared_list_get_hierarchy_sep,
		mailbox_list_default_get_vname,
		mailbox_list_default_get_storage_name,
		shared_list_get_path,
		shared_list_get_temp_prefix,
		shared_list_join_refpattern,
		shared_list_iter_init,
		shared_list_iter_next,
		shared_list_iter_deinit,
		NULL,
		NULL,
		shared_list_subscriptions_refresh,
		shared_list_set_subscribed,
		shared_list_create_mailbox_dir,
		shared_list_delete_mailbox,
		shared_list_delete_dir,
		shared_list_delete_symlink,
		shared_list_rename_mailbox
	}
};
