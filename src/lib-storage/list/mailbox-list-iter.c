/* Copyright (c) 2006-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "hash.h"
#include "imap-match.h"
#include "mail-storage.h"
#include "mailbox-tree.h"
#include "mailbox-list-subscriptions.h"
#include "mailbox-list-private.h"
#include "mailbox-list-iter-private.h"

enum autocreate_match_result {
	/* list contains the mailbox */
	AUTOCREATE_MATCH_RESULT_YES		= 0x01,
	/* list contains children of the mailbox */
	AUTOCREATE_MATCH_RESULT_CHILDREN	= 0x02,
	/* list contains parents of the mailbox */
	AUTOCREATE_MATCH_RESULT_PARENT		= 0x04
};

struct ns_list_iterate_context {
	struct mailbox_list_iterate_context ctx;
	struct mailbox_list_iterate_context *backend_ctx;
	struct mail_namespace *namespaces, *cur_ns;
	struct mailbox_list *error_list;
	pool_t pool;
	const char **patterns, **patterns_ns_match;
	enum mail_namespace_type type_mask;

	struct mailbox_info ns_info;
	struct mailbox_info inbox_info;
	const struct mailbox_info *pending_backend_info;

	bool cur_ns_prefix_sent:1;
	bool inbox_list:1;
	bool inbox_listed:1;
};

static void mailbox_list_ns_iter_failed(struct ns_list_iterate_context *ctx);
static bool ns_match_next(struct ns_list_iterate_context *ctx, 
			  struct mail_namespace *ns, const char *pattern);
static int mailbox_list_match_anything(struct ns_list_iterate_context *ctx,
				       struct mail_namespace *ns,
				       const char *prefix);

static struct mailbox_list_iterate_context mailbox_list_iter_failed;

struct mailbox_list_iterate_context *
mailbox_list_iter_init(struct mailbox_list *list, const char *pattern,
		       enum mailbox_list_iter_flags flags)
{
	const char *patterns[2];

	patterns[0] = pattern;
	patterns[1] = NULL;
	return mailbox_list_iter_init_multiple(list, patterns, flags);
}

int mailbox_list_iter_subscriptions_refresh(struct mailbox_list *list)
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
	hash_table_create(&actx->duplicate_vnames, ctx->pool, 0,
			  str_hash, strcmp);

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
		array_push_back(&actx->all_ns_box_sets, &set);
		if ((ctx->flags & MAILBOX_LIST_ITER_SELECT_SUBSCRIBED) == 0 ||
		    strcmp(set->autocreate, MAILBOX_SET_AUTO_SUBSCRIBE) == 0) {
			array_push_back(&actx->box_sets, &set);
			autobox = array_append_space(&actx->boxes);
			autobox->name = set->name;
			autobox->set = set;
			if (strcasecmp(autobox->name, "INBOX") == 0) {
				/* make sure duplicate INBOX/Inbox/etc.
				   won't get created */
				autobox->name = "INBOX";
			}
		}
	}
}

struct mailbox_list_iterate_context *
mailbox_list_iter_init_multiple(struct mailbox_list *list,
				const char *const *patterns,
				enum mailbox_list_iter_flags flags)
{
	struct mailbox_list_iterate_context *ctx;

	i_assert(*patterns != NULL);

	if ((flags & (MAILBOX_LIST_ITER_SELECT_SUBSCRIBED |
		      MAILBOX_LIST_ITER_RETURN_SUBSCRIBED)) != 0) {
		if (mailbox_list_iter_subscriptions_refresh(list) < 0)
			return &mailbox_list_iter_failed;
	}

	ctx = list->v.iter_init(list, patterns, flags);
	if ((flags & MAILBOX_LIST_ITER_NO_AUTO_BOXES) == 0)
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
ns_is_match_within_ns(struct ns_list_iterate_context *ctx, 
		      struct mail_namespace *ns, const char *prefix_without_sep,
		      const char *pattern, enum imap_match_result result)
{
	if ((ctx->ctx.flags & MAILBOX_LIST_ITER_STAR_WITHIN_NS) == 0) {
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

static bool list_pattern_has_wildcards(const char *pattern)
{
	for (; *pattern != '\0'; pattern++) {
		if (*pattern == '%' || *pattern == '*')
			return TRUE;
	}
	return FALSE;
}

static bool ns_match_next(struct ns_list_iterate_context *ctx, 
			  struct mail_namespace *ns, const char *pattern)
{
	struct imap_match_glob *glob;
	enum imap_match_result result;
	const char *prefix_without_sep;
	size_t len;

	len = ns->prefix_len;
	if (len > 0 && ns->prefix[len-1] == mail_namespace_get_sep(ns))
		len--;

	if ((ns->flags & (NAMESPACE_FLAG_LIST_PREFIX |
			  NAMESPACE_FLAG_LIST_CHILDREN)) == 0) {
		/* non-listable namespace matches only with exact prefix */
		if (strncmp(ns->prefix, pattern, ns->prefix_len) != 0)
			return FALSE;
		/* with prefix="", list=no we don't want to show anything,
		   except when the client explicitly lists a mailbox without
		   wildcards (e.g. LIST "" mailbox). this is mainly useful
		   for working around client bugs (and supporting a specific
		   IMAP client behavior that's not exactly buggy but not very
		   good IMAP behavior either). */
		if (ns->prefix_len == 0 && list_pattern_has_wildcards(pattern))
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

	return ns_is_match_within_ns(ctx, ns, prefix_without_sep,
				     pattern, result);
}

static bool
mailbox_list_ns_match_patterns(struct ns_list_iterate_context *ctx)
{
	struct mail_namespace *ns = ctx->cur_ns;
	unsigned int i;

	if (!ns_match_simple(ctx, ns))
		return FALSE;

	/* filter out namespaces whose prefix doesn't match. this same code
	   handles both with and without STAR_WITHIN_NS, so the "without" case
	   is slower than necessary, but this shouldn't matter much */
	T_BEGIN {
		for (i = 0; ctx->patterns_ns_match[i] != NULL; i++) {
			if (ns_match_next(ctx, ns, ctx->patterns_ns_match[i]))
				break;
		}
	} T_END;

	return ctx->patterns_ns_match[i] != NULL;
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

static bool
mailbox_list_ns_prefix_match(struct ns_list_iterate_context *ctx,
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

static int
ns_prefix_is_visible(struct ns_list_iterate_context *ctx,
		     struct mail_namespace *ns)
{
	int ret;

	if ((ns->flags & NAMESPACE_FLAG_LIST_PREFIX) != 0)
		return 1;
	if ((ns->flags & NAMESPACE_FLAG_LIST_CHILDREN) != 0) {
		if ((ret = mailbox_list_match_anything(ctx, ns, ns->prefix)) != 0)
			return ret;
	}
	return 0;
}

static int
ns_prefix_has_visible_child_namespace(struct ns_list_iterate_context *ctx,
				      const char *prefix)
{
	struct mail_namespace *ns;
	size_t prefix_len = strlen(prefix);
	int ret;

	for (ns = ctx->namespaces; ns != NULL; ns = ns->next) {
		if (ns->prefix_len > prefix_len &&
		    strncmp(ns->prefix, prefix, prefix_len) == 0) {
			ret = ns_prefix_is_visible(ctx, ns);
			if (ret != 0)
				return ret;
		}
	}
	return 0;
}

static bool
mailbox_ns_prefix_is_shared_inbox(struct mail_namespace *ns)
{
	return ns->type == MAIL_NAMESPACE_TYPE_SHARED &&
		(ns->flags & NAMESPACE_FLAG_INBOX_ANY) != 0 &&
		!ns->list->mail_set->mail_shared_explicit_inbox;
}

static bool
mailbox_is_shared_inbox(struct mail_namespace *ns, const char *vname)
{
	return mailbox_ns_prefix_is_shared_inbox(ns) &&
		strncmp(ns->prefix, vname, ns->prefix_len-1) == 0 &&
		vname[ns->prefix_len-1] == '\0';
}

static int
mailbox_list_match_anything(struct ns_list_iterate_context *ctx,
			    struct mail_namespace *ns, const char *prefix)
{
	enum mailbox_list_iter_flags list_flags =
		MAILBOX_LIST_ITER_RETURN_NO_FLAGS;
	struct mailbox_list_iterate_context *list_iter;
	const struct mailbox_info *info;
	const char *pattern;
	int ret;

	if ((ret = ns_prefix_has_visible_child_namespace(ctx, prefix)) != 0)
		return ret;

	pattern = t_strconcat(prefix, "%", NULL);
	list_iter = mailbox_list_iter_init(ns->list, pattern, list_flags);
	info = mailbox_list_iter_next(list_iter);
	if (info != NULL && mailbox_ns_prefix_is_shared_inbox(ns) &&
	    mailbox_is_shared_inbox(ns, info->vname)) {
		/* we don't want to see this, try the next one */
		info = mailbox_list_iter_next(list_iter);
	}
	ret = info != NULL ? 1 : 0;
	if (mailbox_list_iter_deinit(&list_iter) < 0) {
		if (ret == 0)
			ret = -1;
	}
	return ret;
}

static bool
mailbox_ns_prefix_check_selection_criteria(struct ns_list_iterate_context *ctx)
{
	if ((ctx->ctx.flags & MAILBOX_LIST_ITER_SELECT_SUBSCRIBED) != 0) {
		if ((ctx->ns_info.flags & MAILBOX_SUBSCRIBED) != 0)
			return TRUE;
		if ((ctx->ctx.flags & MAILBOX_LIST_ITER_SELECT_RECURSIVEMATCH) != 0 &&
		    (ctx->ns_info.flags & MAILBOX_CHILD_SUBSCRIBED) != 0)
			return TRUE;
		return FALSE;
	}
	return TRUE;
}

static bool
mailbox_list_ns_prefix_return(struct ns_list_iterate_context *ctx,
			      struct mail_namespace *ns, bool has_children)
{
	struct mailbox *box;
	enum mailbox_existence existence;
	int ret;

	if (strncasecmp(ns->prefix, "INBOX", 5) == 0 &&
	    ns->prefix[5] == mail_namespace_get_sep(ns)) {
		/* prefix=INBOX/ (or prefix=INBOX/something/) namespace exists.
		   so we can create children to INBOX. */
		ctx->inbox_info.flags &= ~MAILBOX_NOINFERIORS;
	}

	if (ns->prefix_len == 0 || !mailbox_list_ns_prefix_match(ctx, ns))
		return FALSE;

	i_zero(&ctx->ns_info);
	ctx->ns_info.ns = ns;
	ctx->ns_info.vname = p_strndup(ctx->pool, ns->prefix,
				       ns->prefix_len-1);
	if (ns->special_use_mailboxes)
		ctx->ns_info.flags |= MAILBOX_CHILD_SPECIALUSE;

	if (strcasecmp(ctx->ns_info.vname, "INBOX") == 0) {
		i_assert(!ctx->inbox_listed);
		ctx->inbox_listed = TRUE;
		ctx->ns_info.flags |= ctx->inbox_info.flags | MAILBOX_SELECT;
	}

	if ((ctx->ctx.flags & (MAILBOX_LIST_ITER_RETURN_SUBSCRIBED |
			       MAILBOX_LIST_ITER_SELECT_SUBSCRIBED)) != 0) {
		/* Refresh subscriptions first, this won't cause a duplicate
		   call later on as this is only called when the namespace's
		   children definitely don't match */
		if (mailbox_list_iter_subscriptions_refresh(ns->list) < 0) {
			mailbox_list_ns_iter_failed(ctx);
			return FALSE;
		}
		mailbox_list_set_subscription_flags(ns->list,
						    ctx->ns_info.vname,
						    &ctx->ns_info.flags);
	}
	if (!mailbox_ns_prefix_check_selection_criteria(ctx))
		return FALSE;

	/* see if the namespace has children */
	if (has_children)
		ctx->ns_info.flags |= MAILBOX_CHILDREN;
	else if ((ctx->ctx.flags & MAILBOX_LIST_ITER_RETURN_CHILDREN) != 0 ||
		 (ns->flags & NAMESPACE_FLAG_LIST_CHILDREN) != 0) {
		/* need to check this explicitly */
		if ((ret = mailbox_list_match_anything(ctx, ns, ns->prefix)) > 0)
			ctx->ns_info.flags |= MAILBOX_CHILDREN;
		else if (ret == 0) {
			if ((ns->flags & NAMESPACE_FLAG_LIST_CHILDREN) != 0 &&
			    !mailbox_ns_prefix_is_shared_inbox(ns)) {
				/* no children -> not visible */
				return FALSE;
			}
			ctx->ns_info.flags |= MAILBOX_NOCHILDREN;
		}
	}

	if ((ctx->ns_info.flags & MAILBOX_SELECT) == 0) {
		/* see if namespace prefix is selectable */
		box = mailbox_alloc(ns->list, ctx->ns_info.vname, 0);
		if (mailbox_exists(box, TRUE, &existence) == 0 &&
		    existence == MAILBOX_EXISTENCE_SELECT)
			ctx->ns_info.flags |= MAILBOX_SELECT;
		else
			ctx->ns_info.flags |= MAILBOX_NONEXISTENT;
		mailbox_free(&box);
	}
	return TRUE;
}

static void inbox_set_children_flags(struct ns_list_iterate_context *ctx)
{
	const char *prefix;
	int ret;

	if ((ctx->ctx.flags & MAILBOX_LIST_ITER_RETURN_NO_FLAGS) != 0)
		return;
	if ((ctx->inbox_info.flags & (MAILBOX_CHILDREN | MAILBOX_NOINFERIORS |
				      MAILBOX_NOCHILDREN)) != 0)
		return;

	if (mail_namespace_find_prefix(ctx->namespaces, "") == NULL) {
		/* prefix="" namespace doesn't exist, and neither does
		   anything beginning with prefix=INBOX/ (we checked this
		   earlier). there's no way to create children for INBOX. */
		ctx->inbox_info.flags |= MAILBOX_NOINFERIORS;
		return;
	}

 	/* INBOX namespace doesn't exist and we didn't see any children listed
	   for INBOX. this could be because there truly aren't any children,
	   or that the list patterns just didn't match them. */
	prefix = t_strdup_printf("INBOX%c",
				 mail_namespace_get_sep(ctx->inbox_info.ns));
	ret = mailbox_list_match_anything(ctx, ctx->inbox_info.ns, prefix);
	if (ret > 0)
		ctx->inbox_info.flags |= MAILBOX_CHILDREN;
	else if (ret == 0)
		ctx->inbox_info.flags |= MAILBOX_NOCHILDREN;
}

static void mailbox_list_ns_iter_failed(struct ns_list_iterate_context *ctx)
{
	enum mail_error error;
	const char *errstr;

	if (ctx->cur_ns->list != ctx->error_list) {
		errstr = mailbox_list_get_last_error(ctx->cur_ns->list, &error);
		mailbox_list_set_error(ctx->error_list, error, errstr);
	}
	ctx->ctx.failed = TRUE;
}

static bool
mailbox_list_ns_iter_try_next(struct mailbox_list_iterate_context *_ctx,
			      const struct mailbox_info **info_r)
{
	struct ns_list_iterate_context *ctx =
		(struct ns_list_iterate_context *)_ctx;
	struct mail_namespace *ns;
	const struct mailbox_info *info;
	bool has_children;

	if (ctx->cur_ns == NULL) {
		if (!ctx->inbox_listed && ctx->inbox_list && !_ctx->failed) {
			/* send delayed INBOX reply */
			ctx->inbox_listed = TRUE;
			inbox_set_children_flags(ctx);
			*info_r = &ctx->inbox_info;
			return TRUE;
		}
		*info_r = NULL;
		return TRUE;
	}

	if (ctx->backend_ctx == NULL) {
		i_assert(ctx->pending_backend_info == NULL);
		if (!mailbox_list_ns_match_patterns(ctx)) {
			/* namespace's children don't match the patterns,
			   but the namespace prefix itself might */
			ns = ctx->cur_ns;
			ctx->cur_ns = ctx->cur_ns->next;
			if (mailbox_list_ns_prefix_return(ctx, ns, FALSE)) {
				*info_r = &ctx->ns_info;
				return TRUE;
			}
			return FALSE;
		}
		/* start listing this namespace's mailboxes */
		ctx->backend_ctx =
			mailbox_list_iter_init_multiple(ctx->cur_ns->list,
							ctx->patterns,
							_ctx->flags);
		ctx->cur_ns_prefix_sent = FALSE;
	}
	if (ctx->pending_backend_info == NULL)
		info = mailbox_list_iter_next(ctx->backend_ctx);
	else {
		info = ctx->pending_backend_info;
		ctx->pending_backend_info = NULL;
	}
	if (!ctx->cur_ns_prefix_sent) {
		/* delayed sending of namespace prefix */
		ctx->cur_ns_prefix_sent = TRUE;
		has_children = info != NULL &&
			!mailbox_is_shared_inbox(info->ns, info->vname);
		if (mailbox_list_ns_prefix_return(ctx, ctx->cur_ns,
						  has_children)) {
			ctx->pending_backend_info = info;
			*info_r = &ctx->ns_info;
			return TRUE;
		}
	}
	if (info != NULL) {
		if (strcasecmp(info->vname, "INBOX") == 0 && ctx->inbox_list) {
			/* delay sending INBOX reply. we already saved its
			   flags at init stage, except for \Noinferiors
			   and subscription states */
			ctx->inbox_info.flags |=
				(info->flags & (MAILBOX_NOINFERIORS |
						MAILBOX_SUBSCRIBED |
						MAILBOX_CHILD_SUBSCRIBED));
			return FALSE;
		}
		if (strncasecmp(info->vname, "INBOX", 5) == 0 &&
		    info->vname[5] == mail_namespace_get_sep(info->ns)) {
			/* we know now that INBOX has children */
			ctx->inbox_info.flags |= MAILBOX_CHILDREN;
			ctx->inbox_info.flags &= ~MAILBOX_NOINFERIORS;
		}
		if (info->ns->prefix_len > 0 &&
		    strncmp(info->vname, info->ns->prefix,
			    info->ns->prefix_len-1) == 0 &&
		    info->vname[info->ns->prefix_len-1] == '\0') {
			/* this is an entry for namespace prefix, which we
			   already returned. (e.g. shared/$user/INBOX entry
			   returned as shared/$user, or when listing
			   subscribed namespace prefix). */
			return FALSE;
		}

		*info_r = info;
		return TRUE;
	}

	/* finished with this namespace */
	if (mailbox_list_iter_deinit(&ctx->backend_ctx) < 0)
		mailbox_list_ns_iter_failed(ctx);
	ctx->cur_ns = ctx->cur_ns->next;
	return FALSE;
}

static const struct mailbox_info *
mailbox_list_ns_iter_next(struct mailbox_list_iterate_context *_ctx)
{
	const struct mailbox_info *info = NULL;

	while (!mailbox_list_ns_iter_try_next(_ctx, &info)) ;
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
			mailbox_list_ns_iter_failed(ctx);
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

static bool
patterns_match_inbox(struct mail_namespace *namespaces,
		     const char *const *patterns)
{
	struct mail_namespace *ns = mail_namespace_find_inbox(namespaces);
	struct imap_match_glob *glob;

	glob = imap_match_init_multiple(pool_datastack_create(), patterns,
					TRUE, mail_namespace_get_sep(ns));
	return imap_match(glob, "INBOX") == IMAP_MATCH_YES;
}

static int inbox_info_init(struct ns_list_iterate_context *ctx,
			   struct mail_namespace *namespaces)
{
	enum mailbox_info_flags flags;
	int ret;

	ctx->inbox_info.vname = "INBOX";
	ctx->inbox_info.ns = mail_namespace_find_inbox(namespaces);
	i_assert(ctx->inbox_info.ns != NULL);

	if ((ret = mailbox_list_mailbox(ctx->inbox_info.ns->list, "INBOX", &flags)) > 0)
		ctx->inbox_info.flags = flags;
	return ret;
}

struct mailbox_list_iterate_context *
mailbox_list_iter_init_namespaces(struct mail_namespace *namespaces,
				  const char *const *patterns,
				  enum mail_namespace_type type_mask,
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
	ctx->namespaces = namespaces;
	ctx->error_list = namespaces->list;

	count = str_array_length(patterns);
	ctx->patterns = p_new(pool, const char *, count + 1);
	for (i = 0; i < count; i++)
		ctx->patterns[i] = p_strdup(pool, patterns[i]);
	if (patterns_match_inbox(namespaces, ctx->patterns) &&
	    (flags & MAILBOX_LIST_ITER_SELECT_SUBSCRIBED) == 0) {
		/* we're going to list the INBOX. get its own flags (i.e. not
		   [no]children) immediately, so if we end up seeing something
		   else called INBOX (e.g. namespace prefix) we can show it
		   immediately with the proper flags. */
		ctx->inbox_list = TRUE;
		if (inbox_info_init(ctx, namespaces) < 0) {
			pool_unref(&pool);
			return &mailbox_list_iter_failed;
		}
	}

	if ((flags & MAILBOX_LIST_ITER_STAR_WITHIN_NS) != 0) {
		/* create copies of patterns with '*' wildcard changed to '%'.
		   this is used only when checking which namespaces to list */
		ctx->patterns_ns_match =
			dup_patterns_without_stars(pool, ctx->patterns, count);
	} else {
		ctx->patterns_ns_match = ctx->patterns;
	}

	ctx->cur_ns = namespaces;
	ctx->ctx.list->ns = namespaces;
	return &ctx->ctx;
}

static enum autocreate_match_result
autocreate_box_match(const ARRAY_TYPE(mailbox_settings) *boxes,
		     struct mail_namespace *ns, const char *name,
		     bool only_subscribed, unsigned int *idx_r)
{
	struct mailbox_settings *const *sets;
	unsigned int i, count;
	size_t len, name_len = strlen(name);
	enum autocreate_match_result result = 0;
	char sep = mail_namespace_get_sep(ns);

	*idx_r = UINT_MAX;

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

const struct mailbox_info *
mailbox_list_iter_autocreate_filter(struct mailbox_list_iterate_context *ctx,
				    const struct mailbox_info *_info)
{
	struct mailbox_list_autocreate_iterate_context *actx =
		ctx->autocreate_ctx;
	if (actx == NULL || _info == NULL)
		return _info;
	actx->new_info = *_info;
	struct mailbox_info *info = &actx->new_info;
	enum autocreate_match_result match, match2;
	unsigned int idx;

	match = autocreate_box_match(&actx->box_sets, ctx->list->ns,
				     info->vname, FALSE, &idx);

	if (!actx->listing_autoboxes) {
		if ((match & AUTOCREATE_MATCH_RESULT_YES) != 0) {
			/* we have an exact match in the list.
			   don't list it at the end. */
			array_delete(&actx->boxes, idx, 1);
			array_delete(&actx->box_sets, idx, 1);
		}
		if ((match & AUTOCREATE_MATCH_RESULT_CHILDREN) != 0 &&
		    hash_table_lookup(actx->duplicate_vnames, info->vname) == NULL) {
			/* Prevent autocreate-iteration from adding this
			   mailbox as a duplicate. For example we're listing %
			   and we're here because "foo" was found. However,
			   there's also "foo/bar" with auto=create. We're
			   telling here to the autocreate iteration code that
			   "foo" was already found and it doesn't need to add
			   it again. */
			char *vname = p_strdup(ctx->pool, info->vname);
			hash_table_insert(actx->duplicate_vnames, vname, vname);
		}
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
		match2 = autocreate_box_match(&actx->all_ns_box_sets,
					      ctx->list->ns, info->vname,
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
					      ctx->list->ns, info->vname,
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
		size_t name_len;
		char sep = mail_namespace_get_sep(ctx->list->ns);

		array_foreach_modifiable(&actx->boxes, autobox) {
			name_len = strlen(autobox->name);
			if (!str_begins(info->vname, autobox->name) ||
			    info->vname[name_len] != sep)
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

	i_zero(&actx->new_info);
	actx->new_info.ns = ctx->list->ns;
	actx->new_info.vname = autobox->name;
	actx->new_info.flags = autobox->flags;

	if ((ctx->flags & MAILBOX_LIST_ITER_SELECT_SUBSCRIBED) != 0)
		actx->new_info.flags |= MAILBOX_SUBSCRIBED;

	if ((actx->new_info.flags & MAILBOX_CHILDREN) == 0) {
		if ((ctx->list->flags & MAILBOX_LIST_FLAG_MAILBOX_FILES) != 0 &&
		    ctx->list->set.maildir_name[0] == '\0') {
			/* mailbox format using files (e.g. mbox)
			   without DIRNAME specified */
			actx->new_info.flags |= MAILBOX_NOINFERIORS;
		} else {
			actx->new_info.flags |= MAILBOX_NOCHILDREN;
		}
	}

	match = imap_match(ctx->glob, actx->new_info.vname);
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
		char *vname;

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
			p = strrchr(actx->new_info.vname, sep);
			i_assert(p != NULL);
			actx->new_info.vname = vname =
				p_strdup_until(ctx->pool,
					       actx->new_info.vname, p);
			match = imap_match(ctx->glob, actx->new_info.vname);
		} while (match != IMAP_MATCH_YES);

		if (hash_table_lookup(actx->duplicate_vnames, vname) == NULL) {
			hash_table_insert(actx->duplicate_vnames, vname, vname);
			return TRUE;
		}
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
		set = mailbox_settings_find(ctx->list->ns, info->vname);
		if (set != NULL && *set->special_use != '\0') {
			ctx->specialuse_info = *info;
			ctx->specialuse_info.special_use =
				*set->special_use == '\0' ? NULL :
				set->special_use;
			info = &ctx->specialuse_info;
		}
	}

	return mailbox_list_iter_autocreate_filter(ctx, info);
}

const struct mailbox_info *
mailbox_list_iter_default_next(struct mailbox_list_iterate_context *ctx)
{
	struct mailbox_list_autocreate_iterate_context *actx =
        	ctx->autocreate_ctx;
	const struct autocreate_box *autoboxes, *autobox;
	unsigned int count;

	if (actx == NULL)
		return NULL;

	/* do not drop boxes anymore */
	actx->listing_autoboxes = TRUE;

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
	if ((ctx->flags & MAILBOX_LIST_ITER_SELECT_RECURSIVEMATCH) != 0 &&
	    (ctx->flags & MAILBOX_LIST_ITER_SELECT_SPECIALUSE) != 0) {
		/* LIST (SPECIAL-USE RECURSIVEMATCH) used. for now we support
		   this only for namespace prefixes */
		if ((info->flags & MAILBOX_CHILD_SPECIALUSE) != 0)
			return TRUE;
	}
	return (ctx->flags & MAILBOX_LIST_ITER_SELECT_SPECIALUSE) == 0 ||
		info->special_use != NULL;
}

const struct mailbox_info *
mailbox_list_iter_next(struct mailbox_list_iterate_context *ctx)
{
	const struct mailbox_info *info;

	if (ctx == &mailbox_list_iter_failed)
		return NULL;
	do {
		T_BEGIN {
			info = mailbox_list_iter_next_call(ctx);
		} T_END;
	} while (info != NULL && !special_use_selection(ctx, info));
	return info;
}

int mailbox_list_iter_deinit(struct mailbox_list_iterate_context **_ctx)
{
	struct mailbox_list_iterate_context *ctx = *_ctx;

	*_ctx = NULL;

	if (ctx == &mailbox_list_iter_failed)
		return -1;
	if (ctx->autocreate_ctx != NULL)
		hash_table_destroy(&ctx->autocreate_ctx->duplicate_vnames);
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
				if ((always_flags & MAILBOX_CHILDREN) != 0)
					node->flags &= ~MAILBOX_NOCHILDREN;
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
