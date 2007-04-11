/* Copyright (C) 2006 Timo Sirainen */

#include "lib.h"
#include "array.h"
#include "mail-namespace.h"
#include "mailbox-list-private.h"
#include "acl-api-private.h"
#include "acl-plugin.h"

#include <stdlib.h>

#define ACL_LIST_CONTEXT(obj) \
	MODULE_CONTEXT(obj, acl_mailbox_list_module)

struct acl_mailbox_list {
	union mailbox_list_module_context module_ctx;

	struct acl_storage_rights_context rights;
};

static MODULE_CONTEXT_DEFINE_INIT(acl_mailbox_list_module,
				  &mailbox_list_module_register);

struct acl_backend *acl_mailbox_list_get_backend(struct mailbox_list *list)
{
	struct acl_mailbox_list *alist = ACL_LIST_CONTEXT(list);

	return alist->rights.backend;
}

const char *acl_mailbox_list_get_parent_mailbox_name(struct mailbox_list *list,
						     const char *name)
{
	const char *p;
	char sep;

	sep = mailbox_list_get_hierarchy_sep(list);
	p = strrchr(name, sep);
	return p == NULL ? "" : t_strdup_until(name, p);
}

static int
acl_mailbox_list_have_right(struct acl_mailbox_list *alist, const char *name,
			    unsigned int acl_storage_right_idx, bool *can_see_r)
{
	return acl_storage_rights_ctx_have_right(&alist->rights, name,
						 acl_storage_right_idx,
						 can_see_r);
}

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

		ret = acl_mailbox_list_have_right(alist, info->name,
						  ACL_STORAGE_RIGHT_LOOKUP,
						  NULL);
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

	ret = acl_mailbox_list_have_right(alist, name, ACL_STORAGE_RIGHT_LOOKUP,
					  NULL);
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
		parent = acl_mailbox_list_get_parent_mailbox_name(list, name);
		ret = acl_mailbox_list_have_right(alist, parent,
						  ACL_STORAGE_RIGHT_LOOKUP,
						  NULL);
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

	ret = acl_mailbox_list_have_right(alist, name, ACL_STORAGE_RIGHT_DELETE,
					  &can_see);
	if (ret <= 0) {
		if (ret < 0)
			return -1;
		if (can_see) {
			mailbox_list_set_error(list,
					       MAILBOX_LIST_ERR_NO_PERMISSION);
		} else {
			mailbox_list_set_error(list, t_strdup_printf(
				MAILBOX_LIST_ERR_MAILBOX_NOT_FOUND, name));
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
	ret = acl_mailbox_list_have_right(alist, oldname,
					  ACL_STORAGE_RIGHT_DELETE, &can_see);
	if (ret <= 0) {
		if (ret < 0)
			return -1;
		if (can_see) {
			mailbox_list_set_error(list,
					       MAILBOX_LIST_ERR_NO_PERMISSION);
		} else {
			mailbox_list_set_error(list, t_strdup_printf(
				MAILBOX_LIST_ERR_MAILBOX_NOT_FOUND, oldname));
		}
		return 0;
	}

	/* and create the new one under the parent mailbox */
	t_push();
	ret = acl_mailbox_list_have_right(alist,
		acl_mailbox_list_get_parent_mailbox_name(list, newname),
		ACL_STORAGE_RIGHT_CREATE, NULL);
	t_pop();

	if (ret <= 0) {
		if (ret == 0) {
			/* Note that if the mailbox didn't have LOOKUP
			   permission, this not reveals to user the mailbox's
			   existence. Can't help it. */
			mailbox_list_set_error(list,
					       MAILBOX_LIST_ERR_NO_PERMISSION);
		}
		return -1;
	}

	return alist->module_ctx.super.rename_mailbox(list, oldname, newname);
}

void acl_mailbox_list_created(struct mailbox_list *list)
{
	struct acl_mailbox_list *alist;
	struct acl_backend *backend;
	struct mail_namespace *ns;
	enum mailbox_list_flags flags;
	const char *acl_env, *current_username, *owner_username;

	if (acl_next_hook_mailbox_list_created != NULL)
		acl_next_hook_mailbox_list_created(list);

	acl_env = getenv("ACL");
	i_assert(acl_env != NULL);

	owner_username = getenv("USER");
	if (owner_username == NULL)
		i_fatal("ACL: USER environment not set");

	current_username = getenv("MASTER_USER");
	if (current_username == NULL)
		current_username = owner_username;

	/* We don't care about the username for non-private mailboxes.
	   It's used only when checking if we're the mailbox owner. We never
	   are for shared/public mailboxes. */
	ns = mailbox_list_get_namespace(list);
	if (ns->type != NAMESPACE_PRIVATE)
		owner_username = NULL;

	/* FIXME: set groups */
	backend = acl_backend_init(acl_env, list, current_username, NULL,
				   owner_username);
	if (backend == NULL)
		i_fatal("ACL backend initialization failed");

	flags = mailbox_list_get_flags(list);
	if ((flags & MAILBOX_LIST_FLAG_FULL_FS_ACCESS) != 0) {
		/* not necessarily, but safer to do this for now.. */
		i_fatal("mail_full_filesystem_access=yes is "
			"incompatible with ACLs");
	}

	alist = p_new(list->pool, struct acl_mailbox_list, 1);
	alist->module_ctx.super = list->v;
	list->v.iter_next = acl_mailbox_list_iter_next;
	list->v.get_mailbox_name_status = acl_get_mailbox_name_status;
	list->v.delete_mailbox = acl_mailbox_list_delete;
	list->v.rename_mailbox = acl_mailbox_list_rename;

	acl_storage_rights_ctx_init(&alist->rights, backend);

	MODULE_CONTEXT_SET(list, acl_mailbox_list_module, alist);
}
