/* Copyright (c) 2006-2013 Dovecot authors, see the included COPYING file */

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

#define MAILBOX_FLAG_MATCHED 0x40000000

struct acl_mailbox_list_iterate_context {
	struct mailbox_list_iterate_context ctx;
	struct mailbox_list_iterate_context *super_ctx;

	struct mailbox_tree_context *lookup_boxes;
	struct mailbox_info info;

	char sep;
	unsigned int simple_star_glob:1;
};

static const char *acl_storage_right_names[ACL_STORAGE_RIGHT_COUNT] = {
	MAIL_ACL_LOOKUP,
	MAIL_ACL_READ,
	MAIL_ACL_WRITE,
	MAIL_ACL_WRITE_SEEN,
	MAIL_ACL_WRITE_DELETED,
	MAIL_ACL_INSERT,
	MAIL_ACL_POST,
	MAIL_ACL_EXPUNGE,
	MAIL_ACL_CREATE,
	MAIL_ACL_DELETE,
	MAIL_ACL_ADMIN
};

struct acl_mailbox_list_module acl_mailbox_list_module =
	MODULE_CONTEXT_INIT(&mailbox_list_module_register);

struct acl_backend *acl_mailbox_list_get_backend(struct mailbox_list *list)
{
	struct acl_mailbox_list *alist = ACL_LIST_CONTEXT(list);

	return alist->rights.backend;
}

int acl_mailbox_list_have_right(struct mailbox_list *list, const char *name,
				bool parent, unsigned int acl_storage_right_idx,
				bool *can_see_r)
{
	struct acl_mailbox_list *alist = ACL_LIST_CONTEXT(list);
	struct acl_backend *backend = alist->rights.backend;
	const unsigned int *idx_arr = alist->rights.acl_storage_right_idx;
	struct acl_object *aclobj;
	int ret, ret2;

	aclobj = !parent ?
		acl_object_init_from_name(backend, name) :
		acl_object_init_from_parent(backend, name);
	ret = acl_object_have_right(aclobj, idx_arr[acl_storage_right_idx]);

	if (can_see_r != NULL) {
		ret2 = acl_object_have_right(aclobj,
					     idx_arr[ACL_STORAGE_RIGHT_LOOKUP]);
		if (ret2 < 0)
			ret = -1;
		*can_see_r = ret2 > 0;
	}
	acl_object_deinit(&aclobj);

	if (ret < 0)
		mailbox_list_set_internal_error(list);
	return ret;
}

static void
acl_mailbox_try_list_fast(struct acl_mailbox_list_iterate_context *ctx)
{
	struct acl_mailbox_list *alist = ACL_LIST_CONTEXT(ctx->ctx.list);
	struct acl_backend *backend = alist->rights.backend;
	const unsigned int *idxp;
	const struct acl_mask *acl_mask;
	struct acl_mailbox_list_context *nonowner_list_ctx;
	struct mail_namespace *ns = ctx->ctx.list->ns;
	struct mailbox_list_iter_update_context update_ctx;
	const char *name;
	int ret;

	if ((ctx->ctx.flags & (MAILBOX_LIST_ITER_RAW_LIST |
			       MAILBOX_LIST_ITER_SELECT_SUBSCRIBED)) != 0)
		return;

	if (ns->type == MAIL_NAMESPACE_TYPE_PUBLIC) {
		/* mailboxes in public namespace should all be listable to
		   someone. we don't benefit from fast listing. */
		return;
	}

	/* if this namespace's default rights contain LOOKUP, we'll need to
	   go through all mailboxes in any case. */
	idxp = alist->rights.acl_storage_right_idx + ACL_STORAGE_RIGHT_LOOKUP;
	if (acl_backend_get_default_rights(backend, &acl_mask) < 0 ||
	    acl_cache_mask_isset(acl_mask, *idxp))
		return;

	/* no LOOKUP right by default, we can optimize this */
	memset(&update_ctx, 0, sizeof(update_ctx));
	update_ctx.iter_ctx = &ctx->ctx;
	update_ctx.glob =
		imap_match_init(pool_datastack_create(), "*",
				(ns->flags & NAMESPACE_FLAG_INBOX_USER) != 0,
				ctx->sep);
	update_ctx.match_parents = TRUE;
	update_ctx.tree_ctx = mailbox_tree_init(ctx->sep);

	nonowner_list_ctx = acl_backend_nonowner_lookups_iter_init(backend);
	while ((ret = acl_backend_nonowner_lookups_iter_next(nonowner_list_ctx,
							     &name)) > 0) {
		T_BEGIN {
			const char *vname =
				mailbox_list_get_vname(ns->list, name);
			mailbox_list_iter_update(&update_ctx, vname);
		} T_END;
	}
	acl_backend_nonowner_lookups_iter_deinit(&nonowner_list_ctx);

	if (ret == 0)
		ctx->lookup_boxes = update_ctx.tree_ctx;
	else
		mailbox_tree_deinit(&update_ctx.tree_ctx);
}

static struct mailbox_list_iterate_context *
acl_mailbox_list_iter_init_shared(struct mailbox_list *list,
				  const char *const *patterns,
				  enum mailbox_list_iter_flags flags)
{
	struct acl_mailbox_list *alist = ACL_LIST_CONTEXT(list);
	struct mailbox_list_iterate_context *ctx;
	int ret;

	/* before listing anything add namespaces for all users
	   who may have visible mailboxes */
	ret = acl_shared_namespaces_add(list->ns);

	ctx = alist->module_ctx.super.iter_init(list, patterns, flags);
	if (ret < 0)
		ctx->failed = TRUE;
	return ctx;
}

static struct mailbox_list_iterate_context *
acl_mailbox_list_iter_init(struct mailbox_list *list,
			   const char *const *patterns,
			   enum mailbox_list_iter_flags flags)
{
	struct acl_mailbox_list *alist = ACL_LIST_CONTEXT(list);
	struct acl_mailbox_list_iterate_context *ctx;
	pool_t pool;
	const char *p;
	unsigned int i;
	bool inboxcase;

	pool = pool_alloconly_create("mailbox list acl iter", 1024);
	ctx = p_new(pool, struct acl_mailbox_list_iterate_context, 1);
	ctx->ctx.pool = pool;
	ctx->ctx.list = list;
	ctx->ctx.flags = flags;

	inboxcase = (list->ns->flags & NAMESPACE_FLAG_INBOX_USER) != 0;
	ctx->sep = mail_namespace_get_sep(list->ns);
	ctx->ctx.glob = imap_match_init_multiple(pool, patterns,
						 inboxcase, ctx->sep);
	/* see if all patterns have only a single '*' and it's at the end.
	   we can use it to do some optimizations. */
	ctx->simple_star_glob = TRUE;
	for (i = 0; patterns[i] != NULL; i++) {
		p = strchr(patterns[i], '*');
		if (p == NULL || p[1] != '\0') {
			ctx->simple_star_glob = FALSE;
			break;
		}
	}

	/* Try to avoid reading ACLs from all mailboxes by getting a smaller
	   list of mailboxes that have even potential to be visible. If we
	   couldn't get such a list, we'll go through all mailboxes. */
	T_BEGIN {
		acl_mailbox_try_list_fast(ctx);
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

	while ((info = alist->module_ctx.super.iter_next(ctx->super_ctx)) != NULL) {
		/* if we've a list of mailboxes with LOOKUP rights, skip the
		   mailboxes not in the list (since we know they can't be
		   visible to us). */
		if (ctx->lookup_boxes == NULL ||
		    mailbox_tree_lookup(ctx->lookup_boxes, info->vname) != NULL)
			break;
		if (ctx->ctx.list->ns->user->mail_debug) {
			i_debug("acl: Mailbox not in dovecot-acl-list: %s",
				info->vname);
		}
	}

	return info;
}

static const char *
acl_mailbox_list_iter_get_name(struct mailbox_list_iterate_context *ctx,
			       const char *vname)
{
	struct mail_namespace *ns = ctx->list->ns;
	const char *name;
	unsigned int len;

	name = mailbox_list_get_storage_name(ns->list, vname);
	len = strlen(name);
	if (len > 0 && name[len-1] == mailbox_list_get_hierarchy_sep(ns->list)) {
		/* name ends with separator. this can happen if doing e.g.
		   LIST "" foo/% and it lists "foo/". */
		name = t_strndup(name, len-1);
	}
	return name;
}

static bool
iter_is_listing_all_children(struct acl_mailbox_list_iterate_context *ctx)
{
	const char *child;

	/* If all patterns (with '.' separator) are in "name*", "name.*" or
	   "%.*" style format, simple_star_glob=TRUE and we can easily test
	   this by simply checking if name/child mailbox matches. */
	child = t_strdup_printf("%s%cx", ctx->info.vname, ctx->sep);
	return ctx->simple_star_glob &&
		imap_match(ctx->ctx.glob, child) == IMAP_MATCH_YES;
}

static bool
iter_mailbox_has_visible_children(struct acl_mailbox_list_iterate_context *ctx,
				  bool only_nonpatterns)
{
	struct mailbox_list_iterate_context *iter;
	const struct mailbox_info *info;
	string_t *pattern;
	const char *prefix;
	unsigned int i, prefix_len;
	bool stars = FALSE, ret = FALSE;

	/* do we have child mailboxes with LOOKUP right that don't match
	   the list pattern? */
	if (ctx->lookup_boxes != NULL) {
		/* we have a list of mailboxes with LOOKUP rights. before
		   starting the slow list iteration, check check first
		   if there even are any children with LOOKUP rights. */
		struct mailbox_node *node;

		node = mailbox_tree_lookup(ctx->lookup_boxes, ctx->info.vname);
		i_assert(node != NULL);
		if (node->children == NULL)
			return FALSE;
	}

	/* if mailbox name has '*' characters in it, they'll conflict with the
	   LIST wildcard. replace then with '%' and verify later that all
	   results have the correct prefix. */
	pattern = t_str_new(128);
	for (i = 0; ctx->info.vname[i] != '\0'; i++) {
		if (ctx->info.vname[i] != '*')
			str_append_c(pattern, ctx->info.vname[i]);
		else {
			stars = TRUE;
			str_append_c(pattern, '%');
		}
	}
	if (i > 0 && ctx->info.vname[i-1] != ctx->sep)
		str_append_c(pattern, ctx->sep);
	str_append_c(pattern, '*');
	prefix = str_c(pattern);
	prefix_len = str_len(pattern) - 1;

	iter = mailbox_list_iter_init(ctx->ctx.list, str_c(pattern),
				      MAILBOX_LIST_ITER_RETURN_NO_FLAGS);
	while ((info = mailbox_list_iter_next(iter)) != NULL) {
		if (only_nonpatterns &&
		    imap_match(ctx->ctx.glob, info->vname) == IMAP_MATCH_YES) {
			/* at least one child matches also the original list
			   patterns. we don't need to show this mailbox. */
			ret = FALSE;
			break;
		}
		if (!stars || strncmp(info->vname, prefix, prefix_len) == 0)
			ret = TRUE;
	}
	(void)mailbox_list_iter_deinit(&iter);
	return ret;
}

static int
acl_mailbox_list_info_is_visible(struct acl_mailbox_list_iterate_context *ctx)
{
#define PRESERVE_MAILBOX_FLAGS (MAILBOX_SUBSCRIBED | MAILBOX_CHILD_SUBSCRIBED)
	struct mailbox_info *info = &ctx->info;
	const char *acl_name;
	int ret;

	if ((ctx->ctx.flags & MAILBOX_LIST_ITER_RAW_LIST) != 0) {
		/* skip ACL checks. */
		return 1;
	}

	if ((ctx->ctx.flags & MAILBOX_LIST_ITER_SELECT_SUBSCRIBED) != 0 &&
	    (ctx->ctx.flags & MAILBOX_LIST_ITER_RETURN_NO_FLAGS) != 0) {
		/* don't waste time doing an ACL check. we're going to list
		   all subscriptions anyway. */
		info->flags &= MAILBOX_SUBSCRIBED | MAILBOX_CHILD_SUBSCRIBED;
		return 1;
	}

	acl_name = acl_mailbox_list_iter_get_name(&ctx->ctx, info->vname);
	ret = acl_mailbox_list_have_right(ctx->ctx.list, acl_name, FALSE,
					  ACL_STORAGE_RIGHT_LOOKUP,
					  NULL);
	if (ret != 0) {
		if ((ctx->ctx.flags & MAILBOX_LIST_ITER_RETURN_NO_FLAGS) != 0) {
			/* don't waste time checking if there are visible
			   children, but also don't return incorrect flags */
			info->flags &= ~MAILBOX_CHILDREN;
		} else if ((info->flags & MAILBOX_CHILDREN) != 0 &&
			   !iter_mailbox_has_visible_children(ctx, FALSE)) {
			info->flags &= ~MAILBOX_CHILDREN;
			info->flags |= MAILBOX_NOCHILDREN;
		}
		return ret;
	}

	/* no permission to see this mailbox */
	if ((ctx->ctx.flags & MAILBOX_LIST_ITER_SELECT_SUBSCRIBED) != 0) {
		/* we're listing subscribed mailboxes. this one or its child
		   is subscribed, so we'll need to list it. but since we don't
		   have LOOKUP right, we'll need to show it as nonexistent. */
		i_assert((info->flags & PRESERVE_MAILBOX_FLAGS) != 0);
		info->flags = MAILBOX_NONEXISTENT |
			(info->flags & PRESERVE_MAILBOX_FLAGS);
		return 1;
	}

	if (!iter_is_listing_all_children(ctx) &&
	    iter_mailbox_has_visible_children(ctx, TRUE)) {
		/* no child mailboxes match the list pattern(s), but mailbox
		   has visible children. we'll need to show this as
		   non-existent. */
		info->flags = MAILBOX_NONEXISTENT | MAILBOX_CHILDREN |
			(info->flags & PRESERVE_MAILBOX_FLAGS);
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
		if (ctx->ctx.list->ns->user->mail_debug) {
			i_debug("acl: No lookup right to mailbox: %s",
				info->vname);
		}
	}
	return info == NULL ? NULL : &ctx->info;
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
	if (ctx->lookup_boxes != NULL)
		mailbox_tree_deinit(&ctx->lookup_boxes);
	pool_unref(&_ctx->pool);
	return ret;
}

static void acl_mailbox_list_deinit(struct mailbox_list *list)
{
	struct acl_mailbox_list *alist = ACL_LIST_CONTEXT(list);

	if (alist->rights.backend != NULL)
		acl_backend_deinit(&alist->rights.backend);
	alist->module_ctx.super.deinit(list);
}

static void acl_mailbox_list_init_shared(struct mailbox_list *list)
{
	struct acl_mailbox_list *alist;
	struct mailbox_list_vfuncs *v = list->vlast;

	alist = p_new(list->pool, struct acl_mailbox_list, 1);
	alist->module_ctx.super = *v;
	list->vlast = &alist->module_ctx.super;
	v->deinit = acl_mailbox_list_deinit;
	v->iter_init = acl_mailbox_list_iter_init_shared;

	MODULE_CONTEXT_SET(list, acl_mailbox_list_module, alist);
}

static void acl_storage_rights_ctx_init(struct acl_storage_rights_context *ctx,
					struct acl_backend *backend)
{
	unsigned int i;

	ctx->backend = backend;
	for (i = 0; i < ACL_STORAGE_RIGHT_COUNT; i++) {
		ctx->acl_storage_right_idx[i] =
			acl_backend_lookup_right(backend,
						 acl_storage_right_names[i]);
	}
}

static void acl_mailbox_list_init_default(struct mailbox_list *list)
{
	struct mailbox_list_vfuncs *v = list->vlast;
	struct acl_mailbox_list *alist;

	if (list->mail_set->mail_full_filesystem_access) {
		/* not necessarily, but safer to do this for now. */
		i_fatal("mail_full_filesystem_access=yes is "
			"incompatible with ACLs");
	}

	alist = p_new(list->pool, struct acl_mailbox_list, 1);
	alist->module_ctx.super = *v;
	list->vlast = &alist->module_ctx.super;
	v->deinit = acl_mailbox_list_deinit;
	v->iter_init = acl_mailbox_list_iter_init;
	v->iter_next = acl_mailbox_list_iter_next;
	v->iter_deinit = acl_mailbox_list_iter_deinit;

	MODULE_CONTEXT_SET(list, acl_mailbox_list_module, alist);
}

void acl_mail_namespace_storage_added(struct mail_namespace *ns)
{
	struct acl_user *auser = ACL_USER_CONTEXT(ns->user);
	struct acl_mailbox_list *alist = ACL_LIST_CONTEXT(ns->list);
	struct acl_backend *backend;
	const char *current_username, *owner_username;
	bool owner = TRUE;

	if (alist == NULL)
		return;

	owner_username = ns->user->username;
	current_username = auser->master_user;
	if (current_username == NULL)
		current_username = owner_username;
	else
		owner = strcmp(current_username, owner_username) == 0;

	/* We don't care about the username for non-private mailboxes.
	   It's used only when checking if we're the mailbox owner. We never
	   are for shared/public mailboxes. */
	if (ns->type != MAIL_NAMESPACE_TYPE_PRIVATE)
		owner = FALSE;

	/* we need to know the storage when initializing backend */
	backend = acl_backend_init(auser->acl_env, ns->list, current_username,
				   auser->groups, owner);
	if (backend == NULL)
		i_fatal("ACL backend initialization failed");
	acl_storage_rights_ctx_init(&alist->rights, backend);
}

void acl_mailbox_list_created(struct mailbox_list *list)
{
	struct acl_user *auser = ACL_USER_CONTEXT(list->ns->user);

	if (auser == NULL) {
		/* ACLs disabled for this user */
	} else if ((list->ns->flags & NAMESPACE_FLAG_NOACL) != 0) {
		/* no ACL checks for internal namespaces (lda, shared) */
		if (list->ns->type == MAIL_NAMESPACE_TYPE_SHARED)
			acl_mailbox_list_init_shared(list);
	} else if ((list->ns->flags & NAMESPACE_FLAG_UNUSABLE) != 0) {
		/* this namespace is empty. don't attempt to lookup ACLs,
		   because they're not going to work anyway and we could
		   crash doing it. */
	} else {
		acl_mailbox_list_init_default(list);
	}
}
