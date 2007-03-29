/* Copyright (C) 2006 Timo Sirainen */

#include "lib.h"
#include "array.h"
#include "mailbox-list-private.h"
#include "acl-api-private.h"
#include "acl-plugin.h"

#define ACL_LIST_CONTEXT(obj) \
	MODULE_CONTEXT(obj, acl_mailbox_list_module)

struct acl_mailbox_list {
	union mailbox_list_module_context module_ctx;

	/* FIXME: this is wrong. multiple storages can use the same
	   mailbox_list, so the whole ACL plugin probably needs redesigning.
	   for now this is just kludged to work this way. */
	struct mail_storage *storage;
};

static MODULE_CONTEXT_DEFINE_INIT(acl_mailbox_list_module,
				  &mailbox_list_module_register);


static struct mailbox_info *
acl_mailbox_list_iter_next(struct mailbox_list_iterate_context *ctx)
{
	struct acl_mailbox_list *alist = ACL_LIST_CONTEXT(ctx->list);
	struct mailbox_info *info;
	int ret;

	for (;;) {
		info = alist->module_ctx.super.iter_next(ctx);
		if (info == NULL)
			return NULL;

		ret = acl_storage_have_right(alist->storage, info->name,
					     ACL_STORAGE_RIGHT_LOOKUP, NULL);
		if (ret > 0)
			return info;
		if (ret < 0) {
			ctx->failed = TRUE;
			return NULL;
		}

		/* no permission to see this mailbox */
		if ((ctx->flags & MAILBOX_LIST_ITER_SUBSCRIBED) != 0) {
			/* it's subscribed, show it as non-existent */
			if ((ctx->flags & MAILBOX_LIST_ITER_FAST_FLAGS) == 0)
				info->flags = MAILBOX_NONEXISTENT;
			return info;
		}

		/* skip to next one */
	}
}

static int acl_get_mailbox_name_status(struct mailbox_list *list,
				       const char *name,
				       enum mailbox_name_status *status)
{
	struct acl_mailbox_list *alist = ACL_LIST_CONTEXT(list);
	const char *parent;
	int ret;

	ret = acl_storage_have_right(alist->storage, name,
				     ACL_STORAGE_RIGHT_LOOKUP, NULL);
	if (ret < 0)
		return -1;

	if (alist->module_ctx.super.get_mailbox_name_status(list, name,
							    status) < 0)
		return -1;
	if (ret > 0)
		return 0;

	/* we shouldn't reveal this mailbox's existance */
	switch (*status) {
	case MAILBOX_NAME_EXISTS:
		*status = MAILBOX_NAME_VALID;
		break;
	case MAILBOX_NAME_VALID:
	case MAILBOX_NAME_INVALID:
		break;
	case MAILBOX_NAME_NOINFERIORS:
		/* have to check if we are allowed to see the parent */
		t_push();
		parent = acl_storage_get_parent_mailbox_name(alist->storage,
							     name);
		ret = acl_storage_have_right(alist->storage, parent,
					     ACL_STORAGE_RIGHT_LOOKUP, NULL);
		t_pop();

		if (ret < 0)
			return -1;
		if (ret == 0) {
			/* no permission to see the parent */
			*status = MAILBOX_NAME_VALID;
		}
		break;
	}
	return 0;
}

static int
acl_mailbox_list_delete(struct mailbox_list *list, const char *name)
{
	struct acl_mailbox_list *alist = ACL_LIST_CONTEXT(list);
	bool can_see;
	int ret;

	ret = acl_storage_have_right(alist->storage, name,
				     ACL_STORAGE_RIGHT_DELETE, &can_see);
	if (ret <= 0) {
		if (ret < 0)
			return -1;
		if (can_see) {
			mail_storage_set_error(alist->storage,
					       MAILBOX_LIST_ERR_NO_PERMISSION);
		} else {
			mail_storage_set_error(alist->storage,
				MAILBOX_LIST_ERR_MAILBOX_NOT_FOUND, name);
		}
		return -1;
	}

	return alist->module_ctx.super.delete_mailbox(list, name);
}

static int
acl_mailbox_list_rename(struct mailbox_list *list,
			const char *oldname, const char *newname)
{
	struct acl_mailbox_list *alist = ACL_LIST_CONTEXT(list);
	bool can_see;
	int ret;

	/* renaming requires rights to delete the old mailbox */
	ret = acl_storage_have_right(alist->storage, oldname,
				     ACL_STORAGE_RIGHT_DELETE, &can_see);
	if (ret <= 0) {
		if (ret < 0)
			return -1;
		if (can_see) {
			mail_storage_set_error(alist->storage,
					       MAILBOX_LIST_ERR_NO_PERMISSION);
		} else {
			mail_storage_set_error(alist->storage,
				MAILBOX_LIST_ERR_MAILBOX_NOT_FOUND, oldname);
		}
		return 0;
	}

	/* and create the new one under the parent mailbox */
	t_push();
	ret = acl_storage_have_right(alist->storage,
		acl_storage_get_parent_mailbox_name(alist->storage, newname),
		ACL_STORAGE_RIGHT_CREATE, NULL);
	t_pop();

	if (ret <= 0) {
		if (ret == 0) {
			/* Note that if the mailbox didn't have LOOKUP
			   permission, this not reveals to user the mailbox's
			   existence. Can't help it. */
			mail_storage_set_error(alist->storage,
					       MAILBOX_LIST_ERR_NO_PERMISSION);
		}
		return -1;
	}

	return alist->module_ctx.super.rename_mailbox(list, oldname, newname);
}

void acl_mailbox_list_created(struct mailbox_list *list)
{
	struct acl_mailbox_list *alist;

	if (acl_next_hook_mailbox_list_created != NULL)
		acl_next_hook_mailbox_list_created(list);

	alist = p_new(list->pool, struct acl_mailbox_list, 1);
	alist->module_ctx.super = list->v;
	list->v.iter_next = acl_mailbox_list_iter_next;
	list->v.get_mailbox_name_status = acl_get_mailbox_name_status;
	list->v.delete_mailbox = acl_mailbox_list_delete;
	list->v.rename_mailbox = acl_mailbox_list_rename;

	MODULE_CONTEXT_SET(list, acl_mailbox_list_module, alist);
}

void acl_mailbox_list_set_storage(struct mail_storage *storage)
{
	struct acl_mailbox_list *alist = ACL_LIST_CONTEXT(storage->list);

	i_assert(alist->storage == NULL);

	alist->storage = storage;
}
