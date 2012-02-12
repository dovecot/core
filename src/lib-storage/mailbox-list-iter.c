/* Copyright (c) 2006-2012 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "imap-match.h"
#include "mail-storage.h"
#include "mailbox-tree.h"
#include "mailbox-list-private.h"

enum autocreate_match_result {
	/* list contains the mailbox */
	AUTOCREATE_MATCH_RESULT_YES		= 0x01,
	/* list contains children of the mailbox */
	AUTOCREATE_MATCH_RESULT_CHILDREN	= 0x02,
	/* list contains parents of the mailbox */
	AUTOCREATE_MATCH_RESULT_PARENT		= 0x04
};

struct autocreate_box {
	const char *name;
	const struct mailbox_settings *set;
	enum mailbox_info_flags flags;
	bool child_listed;
};

ARRAY_DEFINE_TYPE(mailbox_settings, struct mailbox_settings *);
struct mailbox_list_autocreate_iterate_context {
	unsigned int idx;
	struct mailbox_info new_info;
	ARRAY_DEFINE(boxes, struct autocreate_box);
	ARRAY_TYPE(mailbox_settings) box_sets;
	ARRAY_TYPE(mailbox_settings) all_ns_box_sets;
};

struct ns_list_iterate_context {
	struct mailbox_list_iterate_context ctx;
	struct mailbox_list_iterate_context *backend_ctx;
	struct mail_namespace *namespaces;
	pool_t pool;
	const char **patterns, **patterns_ns_match;
	enum namespace_type type_mask;

	struct mail_namespace *iter_namespaces;
	struct mailbox_info ns_info;
};

static bool ns_match_next(struct ns_list_iterate_context *ctx, 
			  struct mail_namespace *ns, const char *pattern);

struct mailbox_list_iterate_context *
mailbox_list_iter_init(struct mailbox_list *list, const char *pattern,
		       enum mailbox_list_iter_flags flags)
{
	const char *patterns[2];

	patterns[0] = pattern;
	patterns[1] = NULL;
	return mailbox_list_iter_init_multiple(list, patterns, flags);
}

static int mailbox_list_subscriptions_refresh(struct mailbox_list *list)
{
	struct mail_namespace *ns = list->ns;

	if ((ns->flags & NAMESPACE_FLAG_SUBSCRIPTIONS) == 0) {
		/* no subscriptions in this namespace. find where they are. */
		ns = mail_namespace_find_subscribable(ns->user->namespaces,
						      ns->prefix);
		if (ns == NULL) {
			/* no subscriptions. avoid crashes by initializing
			   a subscriptions tree. */
			if (list->subscriptions == NULL) {
				char sep = mail_namespace_get_sep(list->ns);
				list->subscriptions = mailbox_tree_init(sep);
			}
			return 0;
		}
	}
	return ns->list->v.subscriptions_refresh(ns->list, list);
}

static struct mailbox_settings *
mailbox_settings_add_ns_prefix(pool_t pool, struct mail_namespace *ns,
			       struct mailbox_settings *in_set)
{
	struct mailbox_settings *out_set;

	if (ns->prefix_len == 0 || strcasecmp(in_set->name, "INBOX") == 0)
		return in_set;

	out_set = p_new(pool, struct mailbox_settings, 1);
	*out_set = *in_set;
	if (*in_set->name == '\0') {
		/* namespace prefix itself */
		out_set->name = p_strndup(pool, ns->prefix, ns->prefix_len-1);
	} else {
		out_set->name =
			p_strconcat(pool, ns->prefix, in_set->name, NULL);
	}
	return out_set;
}

static void
mailbox_list_iter_init_autocreate(struct mailbox_list_iterate_context *ctx)
{
	struct mail_namespace *ns = ctx->list->ns;
	struct mailbox_list_autocreate_iterate_context *actx;
	struct mailbox_settings *const *box_sets, *set;
	struct autocreate_box *autobox;
	unsigned int i, count;

	if (!array_is_created(&ns->set->mailboxes))
		return;
	box_sets = array_get(&ns->set->mailboxes, &count);
	if (count == 0)
		return;

	actx = p_new(ctx->pool, struct mailbox_list_autocreate_iterate_context, 1);
	ctx->autocreate_ctx = actx;

	/* build the list of mailboxes we need to consider as existing */
	p_array_init(&actx->boxes, ctx->pool, 16);
	p_array_init(&actx->box_sets, ctx->pool, 16);
	p_array_init(&actx->all_ns_box_sets, ctx->pool, 16);
	for (i = 0; i < count; i++) {
		if (strcmp(box_sets[i]->autocreate, MAILBOX_SET_AUTO_NO) == 0)
			continue;

		set = mailbox_settings_add_ns_prefix(ctx->pool,
						     ns, box_sets[i]);

		/* autocreate mailbox belongs to listed namespace */
		array_append(&actx->all_ns_box_sets, &set, 1);
		if ((ctx->flags & MAILBOX_LIST_ITER_SELECT_SUBSCRIBED) == 0 ||
		    strcmp(set->autocreate, MAILBOX_SET_AUTO_SUBSCRIBE) == 0) {
			array_append(&actx->box_sets, &set, 1);
			autobox = array_append_space(&actx->boxes);
			autobox->name = set->name;
			autobox->set = set;
		}
	}
}

struct mailbox_list_iterate_context *
mailbox_list_iter_init_multiple(struct mailbox_list *list,
				const char *const *patterns,
				enum mailbox_list_iter_flags flags)
{
	struct mailbox_list_iterate_context *ctx;
	int ret = 0;

	i_assert(*patterns != NULL);

	if ((flags & (MAILBOX_LIST_ITER_SELECT_SUBSCRIBED |
		      MAILBOX_LIST_ITER_RETURN_SUBSCRIBED)) != 0)
		ret = mailbox_list_subscriptions_refresh(list);

	ctx = list->v.iter_init(list, patterns, flags);
	if (ret < 0)
		ctx->failed = TRUE;
	else if ((flags & MAILBOX_LIST_ITER_NO_AUTO_BOXES) == 0)
		mailbox_list_iter_init_autocreate(ctx);
	return ctx;
}

static bool
ns_match_simple(struct ns_list_iterate_context *ctx, struct mail_namespace *ns)
{
	if ((ctx->type_mask & ns->type) == 0)
		return FALSE;

	if ((ctx->ctx.flags & MAILBOX_LIST_ITER_SKIP_ALIASES) != 0) {
		if (ns->alias_for != NULL)
			return FALSE;
	}
	return TRUE;
}

static bool
ns_match_inbox(struct mail_namespace *ns, const char *pattern)
{
	struct imap_match_glob *glob;

	if ((ns->flags & NAMESPACE_FLAG_INBOX_USER) == 0)
		return FALSE;

	glob = imap_match_init(pool_datastack_create(), pattern,
			       TRUE, mail_namespace_get_sep(ns));
	return imap_match(glob, "INBOX") == IMAP_MATCH_YES;
}

static bool
ns_is_match_within_ns(struct ns_list_iterate_context *ctx, 
		      struct mail_namespace *ns, const char *prefix_without_sep,
		      const char *pattern, enum imap_match_result result)
{
	switch (result) {
	case IMAP_MATCH_YES:
		/* allow matching prefix only when it's done without
		   wildcards */
		if (strcmp(prefix_without_sep, pattern) == 0)
			return TRUE;
		break;
	case IMAP_MATCH_CHILDREN: {
		/* allow this only if there isn't another namespace
		   with longer prefix that matches this pattern
		   (namespaces are sorted by prefix length) */
		struct mail_namespace *tmp;

		T_BEGIN {
			for (tmp = ns->next; tmp != NULL; tmp = tmp->next) {
				if (ns_match_simple(ctx, tmp) &&
				    ns_match_next(ctx, tmp, pattern))
					break;
			}
		} T_END;
		if (tmp == NULL)
			return TRUE;
		break;
	}
	case IMAP_MATCH_NO:
	case IMAP_MATCH_PARENT:
		break;
	}
	return FALSE;
}

static bool ns_match_next(struct ns_list_iterate_context *ctx, 
			  struct mail_namespace *ns, const char *pattern)
{
	struct imap_match_glob *glob;
	enum imap_match_result result;
	const char *prefix_without_sep;
	unsigned int len;

	len = ns->prefix_len;
	if (len > 0 && ns->prefix[len-1] == mail_namespace_get_sep(ns))
		len--;

	if ((ns->flags & (NAMESPACE_FLAG_LIST_PREFIX |
			  NAMESPACE_FLAG_LIST_CHILDREN)) == 0) {
		/* non-listable namespace matches only with exact prefix */
		if (strncmp(ns->prefix, pattern, ns->prefix_len) != 0)
			return FALSE;
	}

	prefix_without_sep = t_strndup(ns->prefix, len);
	if (*prefix_without_sep == '\0')
		result = IMAP_MATCH_CHILDREN;
	else {
		glob = imap_match_init(pool_datastack_create(), pattern,
				       TRUE, mail_namespace_get_sep(ns));
		result = imap_match(glob, prefix_without_sep);
	}

	if ((ctx->ctx.flags & MAILBOX_LIST_ITER_STAR_WITHIN_NS) != 0) {
		return ns_is_match_within_ns(ctx, ns, prefix_without_sep,
					     pattern, result);
	} else {
		switch (result) {
		case IMAP_MATCH_YES:
		case IMAP_MATCH_CHILDREN:
			return TRUE;
		case IMAP_MATCH_NO:
		case IMAP_MATCH_PARENT:
			break;
		}
		return FALSE;
	}
}

static bool
ns_match(struct ns_list_iterate_context *ctx, struct mail_namespace *ns)
{
	unsigned int i;

	if (!ns_match_simple(ctx, ns))
		return FALSE;

	/* filter out namespaces whose prefix doesn't match. this same code
	   handles both with and without STAR_WITHIN_NS, so the "without" case
	   is slower than necessary, but this shouldn't matter much */
	T_BEGIN {
		for (i = 0; ctx->patterns_ns_match[i] != NULL; i++) {
			if (ns_match_inbox(ns, ctx->patterns_ns_match[i]))
				break;
			if (ns_match_next(ctx, ns, ctx->patterns_ns_match[i]))
				break;
		}
	} T_END;

	return ctx->patterns_ns_match[i] != NULL;
}

static struct mail_namespace *
ns_next(struct ns_list_iterate_context *ctx, struct mail_namespace *ns)
{
	for (; ns != NULL; ns = ns->next) {
		if (ns_match(ctx, ns))
			break;
	}
	return ns;
}

static bool
iter_next_try_prefix_pattern(struct ns_list_iterate_context *ctx,
			     struct mail_namespace *ns, const char *pattern)
{
	struct imap_match_glob *glob;
	enum imap_match_result result;
	const char *prefix_without_sep;

	i_assert(ns->prefix_len > 0);

	if ((ns->flags & (NAMESPACE_FLAG_LIST_PREFIX |
			  NAMESPACE_FLAG_LIST_CHILDREN)) == 0) {
		/* non-listable namespace matches only with exact prefix */
		if (strncmp(ns->prefix, pattern, ns->prefix_len) != 0)
			return FALSE;
	}

	prefix_without_sep = t_strndup(ns->prefix, ns->prefix_len-1);
	glob = imap_match_init(pool_datastack_create(), pattern,
			       TRUE, mail_namespace_get_sep(ns));
	result = imap_match(glob, prefix_without_sep);
	return result == IMAP_MATCH_YES &&
		ns_is_match_within_ns(ctx, ns, prefix_without_sep,
				      pattern, result);
}

static bool iter_next_try_prefix(struct ns_list_iterate_context *ctx,
				 struct mail_namespace *ns)
{
	unsigned int i;
	bool ret = FALSE;

	for (i = 0; ctx->patterns_ns_match[i] != NULL; i++) {
		T_BEGIN {
			ret = iter_next_try_prefix_pattern(ctx, ns,
						ctx->patterns_ns_match[i]);
		} T_END;
		if (ret)
			break;
	}
	return ret;
}

static const struct mailbox_info *
mailbox_list_ns_iter_next(struct mailbox_list_iterate_context *_ctx)
{
	struct ns_list_iterate_context *ctx =
		(struct ns_list_iterate_context *)_ctx;
	const struct mailbox_info *info;

	while (ctx->iter_namespaces != NULL) {
		struct mail_namespace *ns = ctx->iter_namespaces;

		ctx->iter_namespaces = ns->next;
		if (ns->prefix_len > 0 && iter_next_try_prefix(ctx, ns)) {
			ctx->ns_info.ns = ns;
			ctx->ns_info.name = p_strndup(ctx->pool, ns->prefix,
						      ns->prefix_len-1);
			return &ctx->ns_info;
		}
	}

	info = ctx->backend_ctx == NULL ? NULL :
		mailbox_list_iter_next(ctx->backend_ctx);
	if (info == NULL && ctx->namespaces != NULL) {
		/* go to the next namespace */
		if (mailbox_list_iter_deinit(&ctx->backend_ctx) < 0)
			_ctx->failed = TRUE;
		ctx->ctx.list->ns = ctx->namespaces;
		ctx->backend_ctx =
			mailbox_list_iter_init_multiple(ctx->namespaces->list,
							ctx->patterns,
							_ctx->flags);
		ctx->namespaces = ns_next(ctx, ctx->namespaces->next);
		return mailbox_list_ns_iter_next(_ctx);
	}
	return info;
}

static int
mailbox_list_ns_iter_deinit(struct mailbox_list_iterate_context *_ctx)
{
	struct ns_list_iterate_context *ctx =
		(struct ns_list_iterate_context *)_ctx;
	int ret;

	if (ctx->backend_ctx != NULL) {
		if (mailbox_list_iter_deinit(&ctx->backend_ctx) < 0)
			_ctx->failed = TRUE;
	}
	ret = _ctx->failed ? -1 : 0;
	pool_unref(&ctx->pool);
	return ret;
}

static const char **
dup_patterns_without_stars(pool_t pool, const char *const *patterns,
			   unsigned int count)
{
	const char **dup;
	unsigned int i;

	dup = p_new(pool, const char *, count + 1);
	for (i = 0; i < count; i++) {
		char *p = p_strdup(pool, patterns[i]);
		dup[i] = p;

		for (; *p != '\0'; p++) {
			if (*p == '*')
				*p = '%';
		}
	}
	return dup;
}

struct mailbox_list_iterate_context *
mailbox_list_iter_init_namespaces(struct mail_namespace *namespaces,
				  const char *const *patterns,
				  enum namespace_type type_mask,
				  enum mailbox_list_iter_flags flags)
{
	struct ns_list_iterate_context *ctx;
	unsigned int i, count;
	pool_t pool;

	i_assert(namespaces != NULL);

	pool = pool_alloconly_create("mailbox list namespaces", 1024);
	ctx = p_new(pool, struct ns_list_iterate_context, 1);
	ctx->pool = pool;
	ctx->type_mask = type_mask;
	ctx->ctx.flags = flags;
	ctx->ctx.list = p_new(pool, struct mailbox_list, 1);
	ctx->ctx.list->v.iter_next = mailbox_list_ns_iter_next;
	ctx->ctx.list->v.iter_deinit = mailbox_list_ns_iter_deinit;
	ctx->iter_namespaces = namespaces;

	count = str_array_length(patterns);
	ctx->patterns = p_new(pool, const char *, count + 1);
	for (i = 0; i < count; i++)
		ctx->patterns[i] = p_strdup(pool, patterns[i]);

	if ((flags & MAILBOX_LIST_ITER_STAR_WITHIN_NS) != 0) {
		/* create copies of patterns with '*' wildcard changed to '%' */
		ctx->patterns_ns_match =
			dup_patterns_without_stars(pool, ctx->patterns, count);
	} else {
		ctx->patterns_ns_match = ctx->patterns;
	}

	namespaces = ns_next(ctx, namespaces);
	ctx->ctx.list->ns = namespaces;
	if (namespaces != NULL) {
		ctx->backend_ctx =
			mailbox_list_iter_init_multiple(namespaces->list,
							patterns, flags);
		ctx->namespaces = ns_next(ctx, namespaces->next);
	}
	return &ctx->ctx;
}

static enum autocreate_match_result
autocreate_box_match(const ARRAY_TYPE(mailbox_settings) *boxes,
		     struct mail_namespace *ns, const char *name,
		     bool only_subscribed, unsigned int *idx_r)
{
	struct mailbox_settings *const *sets;
	unsigned int i, count, len, name_len = strlen(name);
	enum autocreate_match_result result = 0;
	char sep = mail_namespace_get_sep(ns);

	*idx_r = -1U;

	sets = array_get(boxes, &count);
	for (i = 0; i < count; i++) {
		if (only_subscribed &&
		    strcmp(sets[i]->autocreate, MAILBOX_SET_AUTO_SUBSCRIBE) != 0)
			continue;
		len = I_MIN(name_len, strlen(sets[i]->name));
		if (strncmp(name, sets[i]->name, len) != 0)
			continue;

		if (name[len] == '\0' && sets[i]->name[len] == '\0') {
			result |= AUTOCREATE_MATCH_RESULT_YES;
			*idx_r = i;
		} else if (name[len] == '\0' && sets[i]->name[len] == sep)
			result |= AUTOCREATE_MATCH_RESULT_CHILDREN;
		else if (name[len] == sep && sets[i]->name[len] == '\0')
			result |= AUTOCREATE_MATCH_RESULT_PARENT;
	}
	return result;
}

static const struct mailbox_info *
autocreate_iter_existing(struct mailbox_list_iterate_context *ctx)
{
	struct mailbox_list_autocreate_iterate_context *actx =
		ctx->autocreate_ctx;
	struct mailbox_info *info = &actx->new_info;
	enum autocreate_match_result match, match2;
	unsigned int idx;

	match = autocreate_box_match(&actx->box_sets, ctx->list->ns,
				     info->name, FALSE, &idx);

	if ((match & AUTOCREATE_MATCH_RESULT_YES) != 0) {
		/* we have an exact match in the list.
		   don't list it at the end. */
		array_delete(&actx->boxes, idx, 1);
		array_delete(&actx->box_sets, idx, 1);
	}

	if ((match & AUTOCREATE_MATCH_RESULT_CHILDREN) != 0) {
		if ((ctx->flags & MAILBOX_LIST_ITER_SELECT_SUBSCRIBED) != 0)
			info->flags |= MAILBOX_CHILD_SUBSCRIBED;
		else {
			info->flags &= ~MAILBOX_NOCHILDREN;
			info->flags |= MAILBOX_CHILDREN;
		}
	}

	/* make sure the mailbox existence flags are correct. */
	if ((ctx->flags & MAILBOX_LIST_ITER_SELECT_SUBSCRIBED) == 0)
		match2 = match;
	else {
		info->flags |= MAILBOX_SUBSCRIBED;
		match2 = autocreate_box_match(&actx->all_ns_box_sets,
					      ctx->list->ns, info->name,
					      FALSE, &idx);
	}
	if ((match2 & AUTOCREATE_MATCH_RESULT_YES) != 0)
		info->flags &= ~MAILBOX_NONEXISTENT;
	if ((match2 & AUTOCREATE_MATCH_RESULT_CHILDREN) != 0) {
		info->flags &= ~MAILBOX_NOCHILDREN;
		info->flags |= MAILBOX_CHILDREN;
	}

	if ((ctx->flags & MAILBOX_LIST_ITER_SELECT_SUBSCRIBED) == 0 &&
	    (ctx->flags & MAILBOX_LIST_ITER_RETURN_SUBSCRIBED) != 0) {
		/* we're listing all mailboxes and want \Subscribed flag */
		match2 = autocreate_box_match(&actx->all_ns_box_sets,
					      ctx->list->ns, info->name,
					      TRUE, &idx);
		if ((match2 & AUTOCREATE_MATCH_RESULT_YES) != 0) {
			/* mailbox is also marked as autosubscribe */
			info->flags |= MAILBOX_SUBSCRIBED;
		}
		if ((match2 & AUTOCREATE_MATCH_RESULT_CHILDREN) != 0) {
			/* mailbox also has a children marked as
			   autosubscribe */
			info->flags |= MAILBOX_CHILD_SUBSCRIBED;
		}
	}

	if ((match & AUTOCREATE_MATCH_RESULT_PARENT) != 0) {
		/* there are autocreate parent boxes.
		   set their children flag states. */
		struct autocreate_box *autobox;
		unsigned int name_len;
		char sep = mail_namespace_get_sep(ctx->list->ns);

		array_foreach_modifiable(&actx->boxes, autobox) {
			name_len = strlen(autobox->name);
			if (strncmp(info->name, autobox->name, name_len) != 0 ||
			    info->name[name_len] != sep)
				continue;

			if ((info->flags & MAILBOX_NONEXISTENT) == 0)
				autobox->flags |= MAILBOX_CHILDREN;
			if ((info->flags & MAILBOX_SUBSCRIBED) != 0)
				autobox->flags |= MAILBOX_CHILD_SUBSCRIBED;
			autobox->child_listed = TRUE;
		}
	}
	return info;
}

static bool autocreate_iter_autobox(struct mailbox_list_iterate_context *ctx,
				    const struct autocreate_box *autobox)
{
	struct mailbox_list_autocreate_iterate_context *actx =
		ctx->autocreate_ctx;
	enum imap_match_result match;

	memset(&actx->new_info, 0, sizeof(actx->new_info));
	actx->new_info.ns = ctx->list->ns;
	actx->new_info.name = autobox->name;
	actx->new_info.flags = autobox->flags;

	if ((ctx->flags & MAILBOX_LIST_ITER_SELECT_SUBSCRIBED) != 0)
		actx->new_info.flags |= MAILBOX_SUBSCRIBED;

	if ((actx->new_info.flags & MAILBOX_CHILDREN) == 0)
		actx->new_info.flags |= MAILBOX_NOCHILDREN;

	match = imap_match(ctx->glob, actx->new_info.name);
	if (match == IMAP_MATCH_YES) {
		actx->new_info.special_use =
			*autobox->set->special_use == '\0' ? NULL :
			autobox->set->special_use;
		return TRUE;
	}
	if ((match & IMAP_MATCH_PARENT) != 0 && !autobox->child_listed) {
		enum mailbox_info_flags old_flags = actx->new_info.flags;
		char sep = mail_namespace_get_sep(ctx->list->ns);
		const char *p;

		/* e.g. autocreate=foo/bar and we're listing % */
		actx->new_info.flags = MAILBOX_NONEXISTENT |
			(old_flags & (MAILBOX_CHILDREN |
				      MAILBOX_CHILD_SUBSCRIBED));
		if ((old_flags & MAILBOX_NONEXISTENT) == 0) {
			actx->new_info.flags |= MAILBOX_CHILDREN;
			actx->new_info.flags &= ~MAILBOX_NOCHILDREN;
		}
		if ((old_flags & MAILBOX_SUBSCRIBED) != 0)
			actx->new_info.flags |= MAILBOX_CHILD_SUBSCRIBED;
		do {
			p = strrchr(actx->new_info.name, sep);
			i_assert(p != NULL);
			actx->new_info.name =
				t_strdup_until(actx->new_info.name, p);
			match = imap_match(ctx->glob, actx->new_info.name);
		} while (match != IMAP_MATCH_YES);
		return TRUE;
	}
	return FALSE;
}

static const struct mailbox_info *
mailbox_list_iter_next_call(struct mailbox_list_iterate_context *ctx)
{
	const struct mailbox_info *info;
	const struct mailbox_settings *set;

	info = ctx->list->v.iter_next(ctx);
	if (info == NULL)
		return NULL;

	ctx->list->ns->flags |= NAMESPACE_FLAG_USABLE;
	if ((ctx->flags & MAILBOX_LIST_ITER_RETURN_SPECIALUSE) != 0) {
		set = mailbox_settings_find(ctx->list->ns->user, info->name);
		if (set != NULL && *set->special_use != '\0') {
			ctx->specialuse_info = *info;
			ctx->specialuse_info.special_use =
				*set->special_use == '\0' ? NULL :
				set->special_use;
			info = &ctx->specialuse_info;
		}
	}
	return info;
}

static const struct mailbox_info *
autocreate_iter_next(struct mailbox_list_iterate_context *ctx)
{
	struct mailbox_list_autocreate_iterate_context *actx =
		ctx->autocreate_ctx;
	const struct mailbox_info *info;
	const struct autocreate_box *autoboxes, *autobox;
	unsigned int count;

	if (actx->idx == 0) {
		info = mailbox_list_iter_next_call(ctx);
		if (info != NULL) {
			actx->new_info = *info;
			return autocreate_iter_existing(ctx);
		}
	}

	/* list missing mailboxes */
	autoboxes = array_get(&actx->boxes, &count);
	while (actx->idx < count) {
		autobox = &autoboxes[actx->idx++];
		if (autocreate_iter_autobox(ctx, autobox))
			return &actx->new_info;
	}
	i_assert(array_count(&actx->boxes) == array_count(&actx->box_sets));
	return NULL;
}

static bool
special_use_selection(struct mailbox_list_iterate_context *ctx,
		      const struct mailbox_info *info)
{
	return (ctx->flags & MAILBOX_LIST_ITER_SELECT_SPECIALUSE) == 0 ||
		info->special_use != NULL;
}

const struct mailbox_info *
mailbox_list_iter_next(struct mailbox_list_iterate_context *ctx)
{
	const struct mailbox_info *info;

	do {
		if (ctx->autocreate_ctx != NULL)
			info = autocreate_iter_next(ctx);
		else
			info = mailbox_list_iter_next_call(ctx);
	} while (info != NULL && !special_use_selection(ctx, info));
	return info;
}

int mailbox_list_iter_deinit(struct mailbox_list_iterate_context **_ctx)
{
	struct mailbox_list_iterate_context *ctx = *_ctx;

	*_ctx = NULL;

	return ctx->list->v.iter_deinit(ctx);
}

static void node_fix_parents(struct mailbox_node *node)
{
	/* If we happened to create any of the parents, we need to mark them
	   nonexistent. */
	node = node->parent;
	for (; node != NULL; node = node->parent) {
		if ((node->flags & MAILBOX_MATCHED) == 0)
			node->flags |= MAILBOX_NONEXISTENT;
	}
}

static void
mailbox_list_iter_update_real(struct mailbox_list_iter_update_context *ctx,
			      const char *name)
{
	struct mail_namespace *ns = ctx->iter_ctx->list->ns;
	struct mailbox_node *node;
	enum mailbox_info_flags create_flags, always_flags;
	enum imap_match_result match;
	const char *p;
	bool created, add_matched;

	create_flags = MAILBOX_NOCHILDREN;
	always_flags = ctx->leaf_flags;
	add_matched = TRUE;

	for (;;) {
		created = FALSE;
		match = imap_match(ctx->glob, name);
		if (match == IMAP_MATCH_YES) {
			node = ctx->update_only ?
				mailbox_tree_lookup(ctx->tree_ctx, name) :
				mailbox_tree_get(ctx->tree_ctx, name, &created);
			if (created) {
				node->flags = create_flags;
				if (create_flags != 0)
					node_fix_parents(node);
			}
			if (node != NULL) {
				if (!ctx->update_only && add_matched)
					node->flags |= MAILBOX_MATCHED;
				node->flags |= always_flags;
			}
			/* We don't want to show the parent mailboxes unless
			   something else matches them, but if they are matched
			   we want to show them having child subscriptions */
			add_matched = FALSE;
		} else {
			if ((match & IMAP_MATCH_PARENT) == 0)
				break;
			/* We've a (possibly) non-subscribed parent mailbox
			   which has a subscribed child mailbox. Make sure we
			   return the parent mailbox. */
		}

		if (!ctx->match_parents)
			break;

		/* see if parent matches */
		p = strrchr(name, mail_namespace_get_sep(ns));
		if (p == NULL)
			break;

		name = t_strdup_until(name, p);
		create_flags |= MAILBOX_NONEXISTENT;
		create_flags &= ~MAILBOX_NOCHILDREN;
		always_flags = MAILBOX_CHILDREN | ctx->parent_flags;
	}
}

void mailbox_list_iter_update(struct mailbox_list_iter_update_context *ctx,
			      const char *name)
{
	T_BEGIN {
		mailbox_list_iter_update_real(ctx, name);
	} T_END;
}
