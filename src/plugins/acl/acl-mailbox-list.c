/* Copyright (c) 2006-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "imap-match.h"
#include "mailbox-tree.h"
#include "mail-namespace.h"
#include "mailbox-list-iter-private.h"
#include "acl-api-private.h"
#include "acl-cache.h"
#include "acl-shared-storage.h"
#include "acl-plugin.h"

#define MAILBOX_FLAG_MATCHED 0x40000000

struct acl_mailbox_list_iterate_context {
	union mailbox_list_iterate_module_context module_ctx;

	struct mailbox_tree_context *lookup_boxes;
	struct mailbox_info info;

	char sep;
	bool hide_nonlistable_subscriptions:1;
	bool simple_star_glob:1;
	bool autocreate_acls_checked:1;
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

#define ACL_LIST_ITERATE_CONTEXT(obj) \
	MODULE_CONTEXT_REQUIRE(obj, acl_mailbox_list_module)

struct acl_mailbox_list_module acl_mailbox_list_module =
	MODULE_CONTEXT_INIT(&mailbox_list_module_register);

struct acl_backend *acl_mailbox_list_get_backend(struct mailbox_list *list)
{
	struct acl_mailbox_list *alist = ACL_LIST_CONTEXT_REQUIRE(list);

	return alist->rights.backend;
}

int acl_mailbox_list_have_right(struct mailbox_list *list, const char *name,
				bool parent, unsigned int acl_storage_right_idx,
				bool *can_see_r)
{
	struct acl_mailbox_list *alist = ACL_LIST_CONTEXT_REQUIRE(list);
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
acl_mailbox_try_list_fast(struct mailbox_list_iterate_context *_ctx)
{
	struct acl_mailbox_list_iterate_context *ctx =
		ACL_LIST_ITERATE_CONTEXT(_ctx);
	struct acl_mailbox_list *alist = ACL_LIST_CONTEXT_REQUIRE(_ctx->list);
	struct acl_backend *backend = alist->rights.backend;
	const unsigned int *idxp;
	const struct acl_mask *acl_mask;
	struct acl_mailbox_list_context *nonowner_list_ctx;
	struct mail_namespace *ns = _ctx->list->ns;
	struct mailbox_list_iter_update_context update_ctx;
	const char *name;

	if ((_ctx->flags & (MAILBOX_LIST_ITER_RAW_LIST |
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
	i_zero(&update_ctx);
	update_ctx.iter_ctx = _ctx;
	update_ctx.glob =
		imap_match_init(pool_datastack_create(), "*",
				(ns->flags & NAMESPACE_FLAG_INBOX_USER) != 0,
				ctx->sep);
	update_ctx.match_parents = TRUE;
	update_ctx.tree_ctx = mailbox_tree_init(ctx->sep);

	nonowner_list_ctx = acl_backend_nonowner_lookups_iter_init(backend);
	while (acl_backend_nonowner_lookups_iter_next(nonowner_list_ctx,
							     &name)) {
		T_BEGIN {
			const char *vname =
				mailbox_list_get_vname(ns->list, name);
			mailbox_list_iter_update(&update_ctx, vname);
		} T_END;
	}

	if (acl_backend_nonowner_lookups_iter_deinit(&nonowner_list_ctx) >= 0)
		ctx->lookup_boxes = update_ctx.tree_ctx;
	else
		mailbox_tree_deinit(&update_ctx.tree_ctx);
}

static struct mailbox_list_iterate_context *
acl_mailbox_list_iter_init_shared(struct mailbox_list *list,
				  const char *const *patterns,
				  enum mailbox_list_iter_flags flags)
{
	struct acl_mailbox_list *alist = ACL_LIST_CONTEXT_REQUIRE(list);
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
	struct acl_mailbox_list *alist = ACL_LIST_CONTEXT_REQUIRE(list);
	struct mailbox_list_iterate_context *_ctx;
	struct acl_mailbox_list_iterate_context *ctx;
	const char *p;
	unsigned int i;

	_ctx = alist->module_ctx.super.iter_init(list, patterns, flags);

	ctx = p_new(_ctx->pool, struct acl_mailbox_list_iterate_context, 1);

	if (list->ns->type != MAIL_NAMESPACE_TYPE_PRIVATE &&
	    (list->ns->flags & NAMESPACE_FLAG_SUBSCRIPTIONS) != 0) {
		/* non-private namespace with subscriptions=yes. this could be
		   a site-global subscriptions file, so hide subscriptions for
		   mailboxes the user doesn't see. */
		ctx->hide_nonlistable_subscriptions = TRUE;
	}

	ctx->sep = mail_namespace_get_sep(list->ns);
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

	MODULE_CONTEXT_SET(_ctx, acl_mailbox_list_module, ctx);

	/* Try to avoid reading ACLs from all mailboxes by getting a smaller
	   list of mailboxes that have even potential to be visible. If we
	   couldn't get such a list, we'll go through all mailboxes. */
	T_BEGIN {
		acl_mailbox_try_list_fast(_ctx);
	} T_END;

	return _ctx;
}

static const struct mailbox_info *
acl_mailbox_list_iter_next_info(struct mailbox_list_iterate_context *_ctx)
{
	struct acl_mailbox_list_iterate_context *ctx =
		ACL_LIST_ITERATE_CONTEXT(_ctx);
	struct acl_mailbox_list *alist = ACL_LIST_CONTEXT_REQUIRE(_ctx->list);
	const struct mailbox_info *info;

	while ((info = alist->module_ctx.super.iter_next(_ctx)) != NULL) {
		/* if we've a list of mailboxes with LOOKUP rights, skip the
		   mailboxes not in the list (since we know they can't be
		   visible to us). */
		if (ctx->lookup_boxes == NULL ||
		    mailbox_tree_lookup(ctx->lookup_boxes, info->vname) != NULL)
			break;
		e_debug(_ctx->list->ns->user->event,
			"acl: Mailbox not in dovecot-acl-list: %s", info->vname);
	}

	return info;
}

static const char *
acl_mailbox_list_iter_get_name(struct mailbox_list_iterate_context *ctx,
			       const char *vname)
{
	struct mail_namespace *ns = ctx->list->ns;
	const char *name;
	size_t len;

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
iter_is_listing_all_children(struct mailbox_list_iterate_context *_ctx)
{
	struct acl_mailbox_list_iterate_context *ctx =
		ACL_LIST_ITERATE_CONTEXT(_ctx);
	const char *child;

	/* If all patterns (with '.' separator) are in "name*", "name.*" or
	   "%.*" style format, simple_star_glob=TRUE and we can easily test
	   this by simply checking if name/child mailbox matches. */
	child = t_strdup_printf("%s%cx", ctx->info.vname, ctx->sep);
	return ctx->simple_star_glob &&
		imap_match(_ctx->glob, child) == IMAP_MATCH_YES;
}

static bool
iter_mailbox_has_visible_children(struct mailbox_list_iterate_context *_ctx,
				  bool only_nonpatterns, bool subscribed)
{
	struct acl_mailbox_list_iterate_context *ctx =
		ACL_LIST_ITERATE_CONTEXT(_ctx);
	struct mailbox_list_iterate_context *iter;
	const struct mailbox_info *info;
	string_t *pattern;
	const char *prefix;
	size_t i, prefix_len;
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

	iter = mailbox_list_iter_init(_ctx->list, str_c(pattern),
				      (!subscribed ? 0 :
				       MAILBOX_LIST_ITER_SELECT_SUBSCRIBED) |
				      MAILBOX_LIST_ITER_RETURN_NO_FLAGS);
	while ((info = mailbox_list_iter_next(iter)) != NULL) {
		if (only_nonpatterns &&
		    imap_match(_ctx->glob, info->vname) == IMAP_MATCH_YES) {
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
acl_mailbox_list_info_is_visible(struct mailbox_list_iterate_context *_ctx)
{
	struct acl_mailbox_list_iterate_context *ctx =
		ACL_LIST_ITERATE_CONTEXT(_ctx);
#define PRESERVE_MAILBOX_FLAGS (MAILBOX_SUBSCRIBED | MAILBOX_CHILD_SUBSCRIBED)
	struct mailbox_info *info = &ctx->info;
	const char *acl_name;
	int ret;

	if ((_ctx->flags & MAILBOX_LIST_ITER_RAW_LIST) != 0) {
		/* skip ACL checks. */
		return 1;
	}

	if ((_ctx->flags & MAILBOX_LIST_ITER_SELECT_SUBSCRIBED) != 0 &&
	    (_ctx->flags & MAILBOX_LIST_ITER_RETURN_NO_FLAGS) != 0 &&
	    !ctx->hide_nonlistable_subscriptions) {
		/* don't waste time doing an ACL check. we're going to list
		   all subscriptions anyway. */
		info->flags &= MAILBOX_SUBSCRIBED | MAILBOX_CHILD_SUBSCRIBED;
		return 1;
	}

	acl_name = acl_mailbox_list_iter_get_name(_ctx, info->vname);
	ret = acl_mailbox_list_have_right(_ctx->list, acl_name, FALSE,
					  ACL_STORAGE_RIGHT_LOOKUP,
					  NULL);
	if (ret != 0) {
		if ((_ctx->flags & MAILBOX_LIST_ITER_RETURN_NO_FLAGS) != 0) {
			/* don't waste time checking if there are visible
			   children, but also don't return incorrect flags */
			info->flags &= ~MAILBOX_CHILDREN;
		} else if ((info->flags & MAILBOX_CHILDREN) != 0 &&
			   !iter_mailbox_has_visible_children(_ctx, FALSE, FALSE)) {
			info->flags &= ~MAILBOX_CHILDREN;
			info->flags |= MAILBOX_NOCHILDREN;
		}
		return ret;
	}

	/* no permission to see this mailbox */
	if ((_ctx->flags & MAILBOX_LIST_ITER_SELECT_SUBSCRIBED) != 0) {
		/* we're listing subscribed mailboxes. this one or its child
		   is subscribed, so we'll need to list it. but since we don't
		   have LOOKUP right, we'll need to show it as nonexistent. */
		i_assert((info->flags & PRESERVE_MAILBOX_FLAGS) != 0);
		info->flags = MAILBOX_NONEXISTENT |
			(info->flags & PRESERVE_MAILBOX_FLAGS);
		if (ctx->hide_nonlistable_subscriptions) {
			/* global subscriptions file. hide this entry if there
			   are no visible subscribed children or if we're going
			   to list the subscribed children anyway. */
			if ((info->flags & MAILBOX_CHILD_SUBSCRIBED) == 0)
				return 0;
			if (iter_is_listing_all_children(_ctx) ||
			    !iter_mailbox_has_visible_children(_ctx, TRUE, TRUE))
				return 0;
			/* e.g. LSUB "" % with visible subscribed children */
		}
		return 1;
	}

	if (!iter_is_listing_all_children(_ctx) &&
	    iter_mailbox_has_visible_children(_ctx, TRUE, FALSE)) {
		/* no child mailboxes match the list pattern(s), but mailbox
		   has visible children. we'll need to show this as
		   non-existent. */
		info->flags = MAILBOX_NONEXISTENT | MAILBOX_CHILDREN |
			(info->flags & PRESERVE_MAILBOX_FLAGS);
		return 1;
	}
	return 0;
}

static int
acl_mailbox_list_iter_check_autocreate_acls(struct mailbox_list_iterate_context *_ctx)
{
	struct acl_mailbox_list_iterate_context *ctx =
		ACL_LIST_ITERATE_CONTEXT(_ctx);
	struct mailbox_settings *const *box_sets;
	unsigned int i, count;
	int ret;

	ctx->autocreate_acls_checked = TRUE;
	if (_ctx->autocreate_ctx == NULL)
		return 0;
	if ((_ctx->flags & MAILBOX_LIST_ITER_RAW_LIST) != 0) {
		/* skip ACL checks. */
		return 0;
	}

	box_sets = array_get(&_ctx->autocreate_ctx->box_sets, &count);
	i_assert(array_count(&_ctx->autocreate_ctx->boxes) == count);

	for (i = 0; i < count; ) {
		const char *acl_name =
			acl_mailbox_list_iter_get_name(_ctx, box_sets[i]->name);
		ret = acl_mailbox_list_have_right(_ctx->list, acl_name, FALSE,
						  ACL_STORAGE_RIGHT_LOOKUP,
						  NULL);
		if (ret < 0)
			return -1;
		if (ret > 0)
			i++;
		else {
			/* no list right - remove the whole autobox */
			array_delete(&_ctx->autocreate_ctx->box_sets, i, 1);
			array_delete(&_ctx->autocreate_ctx->boxes, i, 1);
			box_sets = array_get(&_ctx->autocreate_ctx->box_sets, &count);
		}
	}
	return 0;
}

static const struct mailbox_info *
acl_mailbox_list_iter_next(struct mailbox_list_iterate_context *_ctx)
{
	struct acl_mailbox_list_iterate_context *ctx =
		ACL_LIST_ITERATE_CONTEXT(_ctx);
	const struct mailbox_info *info;
	int ret;

	if (!ctx->autocreate_acls_checked) {
		if (acl_mailbox_list_iter_check_autocreate_acls(_ctx) < 0) {
			_ctx->failed = TRUE;
			return NULL;
		}
	}

	while ((info = acl_mailbox_list_iter_next_info(_ctx)) != NULL) {
		ctx->info = *info;
		T_BEGIN {
			ret = acl_mailbox_list_info_is_visible(_ctx);
		} T_END;
		if (ret > 0)
			break;
		if (ret < 0) {
			_ctx->failed = TRUE;
			return NULL;
		}
		/* skip to next one */
		e_debug(_ctx->list->ns->user->event,
			"acl: No lookup right to mailbox: %s", info->vname);
	}
	return info == NULL ? NULL : &ctx->info;
}

static int
acl_mailbox_list_iter_deinit(struct mailbox_list_iterate_context *_ctx)
{
	struct acl_mailbox_list_iterate_context *ctx =
		ACL_LIST_ITERATE_CONTEXT(_ctx);
	struct acl_mailbox_list *alist = ACL_LIST_CONTEXT_REQUIRE(_ctx->list);
	int ret = _ctx->failed ? -1 : 0;

        if (ctx->lookup_boxes != NULL)
                mailbox_tree_deinit(&ctx->lookup_boxes);
	if (alist->module_ctx.super.iter_deinit(_ctx) < 0)
		ret = -1;
	return ret;
}

static void acl_mailbox_list_deinit(struct mailbox_list *list)
{
	struct acl_mailbox_list *alist = ACL_LIST_CONTEXT_REQUIRE(list);

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
	struct acl_mailbox_list *alist = ACL_LIST_CONTEXT(ns->list);
	struct acl_backend *backend;
	const char *current_username, *owner_username;
	bool owner = TRUE;

	if (alist == NULL)
		return;
	struct acl_user *auser = ACL_USER_CONTEXT_REQUIRE(ns->user);

	owner_username = ns->user->username;
	current_username = auser->acl_user;
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
