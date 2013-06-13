/* Copyright (c) 2006-2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "imap-match.h"
#include "mail-storage.h"
#include "mailbox-list-subscriptions.h"
#include "mailbox-list-index.h"

static bool iter_use_index(struct mailbox_list_index_iterate_context *ctx)
{
	struct mailbox_list_index *ilist = INDEX_LIST_CONTEXT(ctx->ctx.list);

	if ((ctx->ctx.flags & MAILBOX_LIST_ITER_SELECT_SUBSCRIBED) != 0) {
		/* for now we don't use indexes when listing subscriptions,
		   because it needs to list also the nonexistent subscribed
		   mailboxes, which don't exist in the index. */
		return FALSE;
	}
	if ((ctx->ctx.flags & MAILBOX_LIST_ITER_RAW_LIST) != 0 &&
	    ilist->has_backing_store) {
		/* no indexing wanted with raw lists */
		return FALSE;
	}
	if (mailbox_list_index_refresh(ctx->ctx.list) < 0 &&
	    ilist->has_backing_store) {
		/* refresh failed */
		return FALSE;
	}
	return TRUE;
}

struct mailbox_list_iterate_context *
mailbox_list_index_iter_init(struct mailbox_list *list,
			     const char *const *patterns,
			     enum mailbox_list_iter_flags flags)
{
	struct mailbox_list_index *ilist = INDEX_LIST_CONTEXT(list);
	struct mailbox_list_index_iterate_context *ctx;
	pool_t pool;
	char ns_sep = mail_namespace_get_sep(list->ns);

	pool = pool_alloconly_create("mailbox list index iter", 2048);
	ctx = p_new(pool, struct mailbox_list_index_iterate_context, 1);
	ctx->ctx.pool = pool;
	ctx->ctx.list = list;
	ctx->ctx.flags = flags;
	ctx->ctx.glob = imap_match_init_multiple(pool, patterns, TRUE, ns_sep);
	array_create(&ctx->ctx.module_contexts, pool, sizeof(void *), 5);
	ctx->info_pool = pool_alloconly_create("mailbox list index iter info", 128);

	if (!iter_use_index(ctx)) {
		/* no indexing */
		ctx->backend_ctx = ilist->module_ctx.super.
			iter_init(list, patterns, flags);
	} else {
		/* listing mailboxes from index */
		ctx->info.ns = list->ns;
		ctx->path = str_new(pool, 128);
		ctx->next_node = ilist->mailbox_tree;
		ctx->mailbox_pool = ilist->mailbox_pool;
		pool_ref(ctx->mailbox_pool);
	}
	return &ctx->ctx;
}

static void
mailbox_list_index_update_info(struct mailbox_list_index_iterate_context *ctx)
{
	struct mailbox_list_index_node *node = ctx->next_node;
	struct mailbox *box;

	p_clear(ctx->info_pool);

	str_truncate(ctx->path, ctx->parent_len);
	if (str_len(ctx->path) > 0) {
		str_append_c(ctx->path,
			     mailbox_list_get_hierarchy_sep(ctx->ctx.list));
	}
	str_append(ctx->path, node->name);

	ctx->info.vname = mailbox_list_get_vname(ctx->ctx.list, str_c(ctx->path));
	ctx->info.vname = p_strdup(ctx->info_pool, ctx->info.vname);
	ctx->info.flags = 0;
	if ((node->flags & MAILBOX_LIST_INDEX_FLAG_NONEXISTENT) != 0)
		ctx->info.flags |= MAILBOX_NONEXISTENT;
	else if ((node->flags & MAILBOX_LIST_INDEX_FLAG_NOSELECT) != 0)
		ctx->info.flags |= MAILBOX_NOSELECT;
	if ((node->flags & MAILBOX_LIST_INDEX_FLAG_NOINFERIORS) != 0)
		ctx->info.flags |= MAILBOX_NOINFERIORS;
	ctx->info.flags |= node->children != NULL ?
		MAILBOX_CHILDREN : MAILBOX_NOCHILDREN;

	if ((ctx->ctx.flags & (MAILBOX_LIST_ITER_SELECT_SUBSCRIBED |
			       MAILBOX_LIST_ITER_RETURN_SUBSCRIBED)) != 0) {
		mailbox_list_set_subscription_flags(ctx->ctx.list,
						    ctx->info.vname,
						    &ctx->info.flags);
	}

	box = mailbox_alloc(ctx->ctx.list, ctx->info.vname, 0);
	mailbox_list_index_status_set_info_flags(box, node->uid,
						 &ctx->info.flags);
	mailbox_free(&box);
}

static void
mailbox_list_index_update_next(struct mailbox_list_index_iterate_context *ctx,
			       bool follow_children)
{
	struct mailbox_list_index_node *node = ctx->next_node;

	if (node->children != NULL && follow_children) {
		ctx->parent_len = str_len(ctx->path);
		ctx->next_node = node->children;
	} else {
		while (node->next == NULL) {
			node = node->parent;
			if (node != NULL) {
				ctx->parent_len -= strlen(node->name);
				if (node->parent != NULL)
					ctx->parent_len--;
			}
			if (node == NULL) {
				/* last one */
				ctx->next_node = NULL;
				return;
			}
		}
		ctx->next_node = node->next;
	}
}

static bool
iter_subscriptions_ok(struct mailbox_list_index_iterate_context *ctx)
{
	if ((ctx->ctx.flags & MAILBOX_LIST_ITER_SELECT_SUBSCRIBED) == 0)
		return TRUE;

	if ((ctx->info.flags & MAILBOX_SUBSCRIBED) != 0)
		return TRUE;

	if ((ctx->ctx.flags & MAILBOX_LIST_ITER_SELECT_RECURSIVEMATCH) != 0 &&
	    (ctx->info.flags & MAILBOX_CHILD_SUBSCRIBED) != 0)
		return TRUE;
	return FALSE;
}

const struct mailbox_info *
mailbox_list_index_iter_next(struct mailbox_list_iterate_context *_ctx)
{
	struct mailbox_list_index_iterate_context *ctx =
		(struct mailbox_list_index_iterate_context *)_ctx;
	struct mailbox_list_index *ilist = INDEX_LIST_CONTEXT(_ctx->list);
	bool follow_children;
	enum imap_match_result match;

	if (ctx->backend_ctx != NULL) {
		/* index isn't being used */
		return ilist->module_ctx.super.iter_next(ctx->backend_ctx);
	}

	/* listing mailboxes from index */
	while (ctx->next_node != NULL) {
		mailbox_list_index_update_info(ctx);
		match = imap_match(_ctx->glob, ctx->info.vname);

		follow_children = (match & (IMAP_MATCH_YES |
					    IMAP_MATCH_CHILDREN)) != 0;
		if (match == IMAP_MATCH_YES && iter_subscriptions_ok(ctx)) {
			mailbox_list_index_update_next(ctx, TRUE);
			return &ctx->info;
		} else if ((_ctx->flags & MAILBOX_LIST_ITER_SELECT_SUBSCRIBED) != 0 &&
			   (ctx->info.flags & MAILBOX_CHILD_SUBSCRIBED) == 0) {
			/* listing only subscriptions, but there are no
			   subscribed children. */
			follow_children = FALSE;
		}
		mailbox_list_index_update_next(ctx, follow_children);
	}
	return NULL;
}

int mailbox_list_index_iter_deinit(struct mailbox_list_iterate_context *_ctx)
{
	struct mailbox_list_index_iterate_context *ctx =
		(struct mailbox_list_index_iterate_context *)_ctx;
	struct mailbox_list_index *ilist = INDEX_LIST_CONTEXT(_ctx->list);
	int ret = ctx->failed ? -1 : 0;

	if (ctx->backend_ctx != NULL)
		ret = ilist->module_ctx.super.iter_deinit(ctx->backend_ctx);
	else
		pool_unref(&ctx->mailbox_pool);

	pool_unref(&ctx->info_pool);
	pool_unref(&_ctx->pool);
	return ret;
}
