/* Copyright (c) 2008 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "mailbox-list-private.h"
#include "shared-storage.h"

struct shared_mailbox_list_iterate_context {
	struct mailbox_list_iterate_context ctx;
};

extern struct mailbox_list shared_mailbox_list;

static struct mailbox_list *shared_list_alloc(void)
{
	struct mailbox_list *list;
	pool_t pool;

	pool = pool_alloconly_create("shared list", 256);
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

static bool
shared_is_valid_pattern(struct mailbox_list *list, const char *pattern)
{
	struct mail_namespace *ns;

	if (shared_storage_get_namespace(list->ns->storage, &pattern, &ns) < 0)
		return FALSE;
	return mailbox_list_is_valid_pattern(ns->list, pattern);
}

static bool
shared_is_valid_existing_name(struct mailbox_list *list, const char *name)
{
	struct mail_namespace *ns;

	if (shared_storage_get_namespace(list->ns->storage, &name, &ns) < 0)
		return FALSE;
	return mailbox_list_is_valid_existing_name(ns->list, name);
}

static bool
shared_is_valid_create_name(struct mailbox_list *list, const char *name)
{
	struct mail_namespace *ns;

	if (shared_storage_get_namespace(list->ns->storage, &name, &ns) < 0)
		return FALSE;
	return mailbox_list_is_valid_create_name(ns->list, name);
}

static const char *
shared_list_get_path(struct mailbox_list *list, const char *name,
		     enum mailbox_list_path_type type)
{
	struct mail_namespace *ns;

	if (list->ns->storage == NULL ||
	    shared_storage_get_namespace(list->ns->storage, &name, &ns) < 0) {
		switch (type) {
		case MAILBOX_LIST_PATH_TYPE_DIR:
		case MAILBOX_LIST_PATH_TYPE_MAILBOX:
		case MAILBOX_LIST_PATH_TYPE_CONTROL:
			break;
		case MAILBOX_LIST_PATH_TYPE_INDEX:
			/* we can safely say we don't use indexes */
			return "";
		}
		i_panic("shared mailbox list: Can't return path for '%s'",
			list->ns->prefix);
	}
	return mailbox_list_get_path(ns->list, name, type);
}

static int
shared_list_get_mailbox_name_status(struct mailbox_list *list, const char *name,
				    enum mailbox_name_status *status_r)
{
	struct mail_namespace *ns;
	int ret;

	if (shared_storage_get_namespace(list->ns->storage, &name, &ns) < 0)
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
	struct mail_namespace *ns;

	if (*ref != '\0' &&
	    shared_storage_get_namespace(list->ns->storage, &ref, &ns) == 0)
		return mailbox_list_join_refpattern(ns->list, ref, pattern);

	if (*ref == '\0' &&
	    shared_storage_get_namespace(list->ns->storage, &pattern, &ns) == 0)
		return mailbox_list_join_refpattern(ns->list, "", pattern);

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

	/* FIXME */
	return &ctx->ctx;
}

static const struct mailbox_info *
shared_list_iter_next(struct mailbox_list_iterate_context *_ctx)
{
	struct shared_mailbox_list_iterate_context *ctx =
		(struct shared_mailbox_list_iterate_context *)_ctx;

	return NULL;
}

static int shared_list_iter_deinit(struct mailbox_list_iterate_context *_ctx)
{
	struct shared_mailbox_list_iterate_context *ctx =
		(struct shared_mailbox_list_iterate_context *)_ctx;

	i_free(ctx);
	return -1;
}

static int shared_list_set_subscribed(struct mailbox_list *list,
				      const char *name, bool set)
{
	struct mail_namespace *ns;
	int ret;

	if (shared_storage_get_namespace(list->ns->storage, &name, &ns) < 0)
		return -1;
	ret = mailbox_list_set_subscribed(ns->list, name, set);
	if (ret < 0)
		shared_list_copy_error(list, ns);
	return ret;
}

static int
shared_list_delete_mailbox(struct mailbox_list *list, const char *name)
{
	struct mail_namespace *ns;
	int ret;

	if (shared_storage_get_namespace(list->ns->storage, &name, &ns) < 0)
		return -1;
	ret = mailbox_list_delete_mailbox(ns->list, name);
	if (ret < 0)
		shared_list_copy_error(list, ns);
	return ret;
}

static int shared_list_rename_get_ns(struct mailbox_list *list,
				     const char **oldname, const char **newname,
				     struct mail_namespace **ns_r)
{
	struct mail_namespace *old_ns, *new_ns;

	if (shared_storage_get_namespace(list->ns->storage,
					 oldname, &old_ns) < 0 ||
	    shared_storage_get_namespace(list->ns->storage,
					 newname, &new_ns) < 0)
		return -1;
	if (old_ns != new_ns) {
		mailbox_list_set_error(list, MAIL_ERROR_NOTPOSSIBLE,
			"Can't rename mailboxes across storages");
		return -1;
	}
	*ns_r = old_ns;
	return 0;
}

static int shared_list_rename_mailbox(struct mailbox_list *list,
				      const char *oldname, const char *newname)
{
	struct mail_namespace *ns;
	int ret;

	if (shared_list_rename_get_ns(list, &oldname, &newname, &ns) < 0)
		return -1;
	ret = mailbox_list_rename_mailbox(ns->list, oldname, newname);
	if (ret < 0)
		shared_list_copy_error(list, ns);
	return ret;
}

static int
shared_list_rename_mailbox_pre(struct mailbox_list *list,
			       const char *oldname, const char *newname)
{
	struct mail_namespace *ns;
	int ret;

	if (shared_list_rename_get_ns(list, &oldname, &newname, &ns) < 0)
		return -1;
	ret = ns->list->v.rename_mailbox_pre(ns->list, oldname, newname);
	if (ret < 0)
		shared_list_copy_error(list, ns);
	return ret;
}

struct mailbox_list shared_mailbox_list = {
	MEMBER(name) "shared",
	MEMBER(hierarchy_sep) '/',
	MEMBER(mailbox_name_max_length) PATH_MAX,

	{
		shared_list_alloc,
		shared_list_deinit,
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
		shared_list_set_subscribed,
		shared_list_delete_mailbox,
		shared_list_rename_mailbox,
		shared_list_rename_mailbox_pre
	}
};
