/* Copyright (c) 2006-2008 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "imap-match.h"
#include "mailbox-tree.h"
#include "mail-namespace.h"
#include "mailbox-list-private.h"
#include "acl-api-private.h"
#include "acl-cache.h"
#include "acl-shared-storage.h"
#include "acl-plugin.h"

#define ACL_LIST_CONTEXT(obj) \
	MODULE_CONTEXT(obj, acl_mailbox_list_module)

#define MAILBOX_FLAG_MATCHED 0x40000000

struct acl_mailbox_list {
	union mailbox_list_module_context module_ctx;

	struct acl_storage_rights_context rights;
};

struct acl_mailbox_list_iterate_context {
	struct mailbox_list_iterate_context ctx;
	struct mailbox_list_iterate_context *super_ctx;

	struct mailbox_tree_context *tree;
	struct mailbox_info info;
};

static MODULE_CONTEXT_DEFINE_INIT(acl_mailbox_list_module,
				  &mailbox_list_module_register);

struct acl_backend *acl_mailbox_list_get_backend(struct mailbox_list *list)
{
	struct acl_mailbox_list *alist = ACL_LIST_CONTEXT(list);

	return alist->rights.backend;
}

static int
acl_mailbox_list_have_right(struct mailbox_list *list, const char *name,
			    unsigned int acl_storage_right_idx, bool *can_see_r)
{
	struct acl_mailbox_list *alist = ACL_LIST_CONTEXT(list);
	int ret;

	ret = acl_storage_rights_ctx_have_right(&alist->rights, name, FALSE,
						acl_storage_right_idx,
						can_see_r);
	if (ret < 0)
		mailbox_list_set_internal_error(list);
	return ret;
}

static void
acl_mailbox_try_list_fast(struct acl_mailbox_list_iterate_context *ctx,
			  const char *const *patterns)
{
	struct acl_mailbox_list *alist = ACL_LIST_CONTEXT(ctx->ctx.list);
	struct acl_backend *backend = alist->rights.backend;
	const unsigned int *idxp =
		alist->rights.acl_storage_right_idx + ACL_STORAGE_RIGHT_LOOKUP;
	const struct acl_mask *acl_mask;
	struct acl_mailbox_list_context *nonowner_list_ctx;
	struct mail_namespace *ns = ctx->ctx.list->ns;
	struct mailbox_list_iter_update_context update_ctx;
	const char *name;
	string_t *vname;
	char sep;
	int try, ret;

	if ((ctx->ctx.flags & (MAILBOX_LIST_ITER_RAW_LIST |
			       MAILBOX_LIST_ITER_SELECT_SUBSCRIBED)) != 0)
		return;

	if (acl_backend_get_default_rights(backend, &acl_mask) < 0 ||
	    acl_cache_mask_isset(acl_mask, *idxp))
		return;

	/* default is to not list mailboxes. we can optimize this. */
	if ((ctx->ctx.flags & MAILBOX_LIST_ITER_VIRTUAL_NAMES) != 0) {
		sep = ns->sep;
		vname = t_str_new(256);
	} else {
		sep = ns->real_sep;
		vname = NULL;
	}

	memset(&update_ctx, 0, sizeof(update_ctx));
	update_ctx.iter_ctx = &ctx->ctx;
	update_ctx.glob =
		imap_match_init_multiple(pool_datastack_create(), patterns,
					 TRUE, sep);;
	update_ctx.match_parents = TRUE;

	for (try = 0; try < 2; try++) {
		nonowner_list_ctx =
			acl_backend_nonowner_lookups_iter_init(backend);
		ctx->tree = mailbox_tree_init(sep);
		update_ctx.tree_ctx = ctx->tree;

		while ((ret = acl_backend_nonowner_lookups_iter_next(
					nonowner_list_ctx, &name)) > 0) {
			if (vname != NULL) {
				name = mail_namespace_get_vname(ns, vname,
								name);
			}
			mailbox_list_iter_update(&update_ctx, name);
		}
		acl_backend_nonowner_lookups_iter_deinit(&nonowner_list_ctx);

		if (ret == 0)
			break;

		/* try again */
		mailbox_tree_deinit(&ctx->tree);
	}
}

static struct mailbox_list_iterate_context *
acl_mailbox_list_iter_init(struct mailbox_list *list,
			   const char *const *patterns,
			   enum mailbox_list_iter_flags flags)
{
	struct acl_mailbox_list *alist = ACL_LIST_CONTEXT(list);
	struct acl_mailbox_list_iterate_context *ctx;

	ctx = i_new(struct acl_mailbox_list_iterate_context, 1);
	ctx->ctx.list = list;
	ctx->ctx.flags = flags;

	if (list->ns->type == NAMESPACE_SHARED &&
	    (list->ns->flags & NAMESPACE_FLAG_AUTOCREATED) == 0) {
		/* before listing anything add namespaces for all users
		   who may have visible mailboxes */
		if (acl_shared_namespaces_add(list->ns) < 0)
			ctx->ctx.failed = TRUE;
	}

	T_BEGIN {
		acl_mailbox_try_list_fast(ctx, patterns);
	} T_END;
	ctx->super_ctx = alist->module_ctx.super.
		iter_init(list, patterns, flags);
	return &ctx->ctx;
}

static const struct mailbox_info *
acl_mailbox_list_iter_next_info(struct acl_mailbox_list_iterate_context *ctx)
{
	struct acl_mailbox_list *alist = ACL_LIST_CONTEXT(ctx->ctx.list);
	const struct mailbox_info *info;

	do {
		info = alist->module_ctx.super.iter_next(ctx->super_ctx);
		if (info == NULL)
			return NULL;
		/* if the mailbox isn't in shared mailboxes list, it's not
		   visible to us. */
	} while (ctx->tree != NULL &&
		 mailbox_tree_lookup(ctx->tree, info->name) == NULL);

	return info;
}

static const char *
acl_mailbox_list_iter_get_name(struct mailbox_list_iterate_context *ctx,
			       const char *name)
{
	struct mail_namespace *ns = ctx->list->ns;

	if ((ctx->flags & MAILBOX_LIST_ITER_VIRTUAL_NAMES) == 0)
		return name;

	/* Mailbox names contain namespace prefix,
	   except when listing INBOX. */
	if (strncmp(name, ns->prefix, ns->prefix_len) == 0)
		name += ns->prefix_len;
	return mail_namespace_fix_sep(ns, name);
}

static int
acl_mailbox_list_info_is_visible(struct acl_mailbox_list_iterate_context *ctx)
{
	struct mailbox_info *info = &ctx->info;
	const char *acl_name;
	int ret;

	if ((ctx->ctx.flags & MAILBOX_LIST_ITER_RAW_LIST) != 0) {
		/* skip ACL checks. */
		return 1;
	}

	acl_name = acl_mailbox_list_iter_get_name(&ctx->ctx, info->name);
	ret = acl_mailbox_list_have_right(ctx->ctx.list, acl_name,
					  ACL_STORAGE_RIGHT_LOOKUP,
					  NULL);
	if (ret != 0)
		return ret;

	/* no permission to see this mailbox */
	if ((info->flags & MAILBOX_SUBSCRIBED) != 0) {
		/* it's subscribed, show it as non-existent */
		info->flags = MAILBOX_NONEXISTENT | MAILBOX_SUBSCRIBED;
		return 1;
	}
	return 0;
}

static const struct mailbox_info *
acl_mailbox_list_iter_next(struct mailbox_list_iterate_context *_ctx)
{
	struct acl_mailbox_list_iterate_context *ctx =
		(struct acl_mailbox_list_iterate_context *)_ctx;
	const struct mailbox_info *info;
	int ret;

	while ((info = acl_mailbox_list_iter_next_info(ctx)) != NULL) {
		ctx->info = *info;
		T_BEGIN {
			ret = acl_mailbox_list_info_is_visible(ctx);
		} T_END;
		if (ret > 0)
			break;
		if (ret < 0) {
			ctx->ctx.failed = TRUE;
			return NULL;
		}
		/* skip to next one */
	}
	return info == NULL ? NULL : &ctx->info;
}

static int
acl_mailbox_list_iter_is_mailbox(struct mailbox_list_iterate_context *ctx,
				 const char *dir, const char *fname,
				 const char *mailbox_name,
				 enum mailbox_list_file_type type,
				 enum mailbox_info_flags *flags_r)
{
	struct acl_mailbox_list *alist = ACL_LIST_CONTEXT(ctx->list);
	int ret;

	ret = alist->module_ctx.super.iter_is_mailbox(ctx, dir, fname,
						      mailbox_name,
						      type, flags_r);
	if (ret <= 0 || (ctx->flags & MAILBOX_LIST_ITER_RAW_LIST) != 0)
		return ret;

	mailbox_name = acl_mailbox_list_iter_get_name(ctx, mailbox_name);
	return acl_mailbox_list_have_right(ctx->list, mailbox_name,
					   ACL_STORAGE_RIGHT_LOOKUP, NULL);
}

static int
acl_mailbox_list_iter_deinit(struct mailbox_list_iterate_context *_ctx)
{
	struct acl_mailbox_list_iterate_context *ctx =
		(struct acl_mailbox_list_iterate_context *)_ctx;
	struct acl_mailbox_list *alist = ACL_LIST_CONTEXT(_ctx->list);
	int ret = ctx->ctx.failed ? -1 : 0;

	if (alist->module_ctx.super.iter_deinit(ctx->super_ctx) < 0)
		ret = -1;
	if (ctx->tree != NULL)
		mailbox_tree_deinit(&ctx->tree);

	i_free(ctx);
	return ret;
}

static int acl_get_mailbox_name_status(struct mailbox_list *list,
				       const char *name,
				       enum mailbox_name_status *status)
{
	struct acl_mailbox_list *alist = ACL_LIST_CONTEXT(list);
	int ret;

	ret = acl_mailbox_list_have_right(list, name, ACL_STORAGE_RIGHT_LOOKUP,
					  NULL);
	if (ret < 0)
		return -1;
	if (ret == 0) {
		/* If we have INSERT right for the mailbox, we'll need to
		   reveal its existence so that APPEND and COPY works. */
		ret = acl_mailbox_list_have_right(list, name,
						  ACL_STORAGE_RIGHT_INSERT,
						  NULL);
		if (ret < 0)
			return -1;
	}

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
		T_BEGIN {
			ret = acl_storage_rights_ctx_have_right(&alist->rights, name,
					TRUE, ACL_STORAGE_RIGHT_LOOKUP, NULL);
		} T_END;

		if (ret < 0) {
			mailbox_list_set_internal_error(list);
			return -1;
		}
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

	ret = acl_mailbox_list_have_right(list, name, ACL_STORAGE_RIGHT_DELETE,
					  &can_see);
	if (ret <= 0) {
		if (ret < 0)
			return -1;
		if (can_see) {
			mailbox_list_set_error(list, MAIL_ERROR_PERM,
					       MAIL_ERRSTR_NO_PERMISSION);
		} else {
			mailbox_list_set_error(list, MAIL_ERROR_NOTFOUND,
				T_MAIL_ERR_MAILBOX_NOT_FOUND(name));
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
	ret = acl_mailbox_list_have_right(list, oldname,
					  ACL_STORAGE_RIGHT_DELETE, &can_see);
	if (ret <= 0) {
		if (ret < 0)
			return -1;
		if (can_see) {
			mailbox_list_set_error(list, MAIL_ERROR_PERM,
					       MAIL_ERRSTR_NO_PERMISSION);
		} else {
			mailbox_list_set_error(list, MAIL_ERROR_NOTFOUND,
				T_MAIL_ERR_MAILBOX_NOT_FOUND(oldname));
		}
		return 0;
	}

	/* and create the new one under the parent mailbox */
	T_BEGIN {
		ret = acl_storage_rights_ctx_have_right(&alist->rights, newname,
				TRUE, ACL_STORAGE_RIGHT_CREATE, NULL);
	} T_END;

	if (ret <= 0) {
		if (ret == 0) {
			/* Note that if the mailbox didn't have LOOKUP
			   permission, this not reveals to user the mailbox's
			   existence. Can't help it. */
			mailbox_list_set_error(list, MAIL_ERROR_PERM,
					       MAIL_ERRSTR_NO_PERMISSION);
		} else {
			mailbox_list_set_internal_error(list);
		}
		return -1;
	}

	return alist->module_ctx.super.rename_mailbox(list, oldname, newname);
}

void acl_mailbox_list_created(struct mailbox_list *list)
{
	struct acl_user *auser = ACL_USER_CONTEXT(list->ns->user);
	struct acl_mailbox_list *alist;
	struct acl_backend *backend;
	struct mail_namespace *ns;
	enum mailbox_list_flags flags;
	const char *current_username, *owner_username;
	bool owner = TRUE;

	if ((list->ns->flags & NAMESPACE_FLAG_INTERNAL) != 0) {
		/* no ACL checks for internal namespaces (deliver) */
		return;
	}

	owner_username = list->ns->user->username;
	current_username = auser->master_user;
	if (current_username == NULL)
		current_username = owner_username;
	else
		owner = strcmp(current_username, owner_username) == 0;

	/* We don't care about the username for non-private mailboxes.
	   It's used only when checking if we're the mailbox owner. We never
	   are for shared/public mailboxes. */
	ns = mailbox_list_get_namespace(list);
	if (ns->type != NAMESPACE_PRIVATE)
		owner = FALSE;

	backend = acl_backend_init(auser->acl_env, list, current_username,
				   auser->groups, owner);
	if (backend == NULL)
		i_fatal("ACL backend initialization failed");

	flags = mailbox_list_get_flags(list);
	if ((flags & MAILBOX_LIST_FLAG_FULL_FS_ACCESS) != 0) {
		/* not necessarily, but safer to do this for now. */
		i_fatal("mail_full_filesystem_access=yes is "
			"incompatible with ACLs");
	}

	alist = p_new(list->pool, struct acl_mailbox_list, 1);
	alist->module_ctx.super = list->v;
	list->v.iter_init = acl_mailbox_list_iter_init;
	list->v.iter_next = acl_mailbox_list_iter_next;
	list->v.iter_deinit = acl_mailbox_list_iter_deinit;
	list->v.iter_is_mailbox = acl_mailbox_list_iter_is_mailbox;
	list->v.get_mailbox_name_status = acl_get_mailbox_name_status;
	list->v.delete_mailbox = acl_mailbox_list_delete;
	list->v.rename_mailbox = acl_mailbox_list_rename;

	acl_storage_rights_ctx_init(&alist->rights, backend);

	MODULE_CONTEXT_SET(list, acl_mailbox_list_module, alist);

	if (acl_next_hook_mailbox_list_created != NULL)
		acl_next_hook_mailbox_list_created(list);
}
