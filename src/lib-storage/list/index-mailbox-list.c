/* Copyright (c) 2006-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "array.h"
#include "file-lock.h"
#include "imap-match.h"
#include "mail-index.h"
#include "mail-storage.h"
#include "mail-storage-hooks.h"
#include "mailbox-tree.h"
#include "mailbox-list-subscriptions.h"
#include "mailbox-list-index.h"
#include "index-mailbox-list.h"

#include <stdlib.h>
#include <time.h>
#include <sys/stat.h>

/* min 2 seconds */
#define MAILBOX_LIST_SYNC_SECS 2

struct index_mailbox_list_module index_mailbox_list_module =
	MODULE_CONTEXT_INIT(&mailbox_list_module_register);

static enum mailbox_info_flags
index_mailbox_list_index_flags_translate(enum mailbox_list_index_flags flags)
{
	enum mailbox_info_flags info_flags = 0;

	if ((flags & MAILBOX_LIST_INDEX_FLAG_CHILDREN) != 0)
		info_flags |= MAILBOX_CHILDREN;
	if ((flags & MAILBOX_LIST_INDEX_FLAG_NOCHILDREN) != 0)
		info_flags |= MAILBOX_NOCHILDREN;

	if ((flags & MAILBOX_LIST_INDEX_FLAG_NONEXISTENT) != 0)
		info_flags |= MAILBOX_NONEXISTENT;
	if ((flags & MAILBOX_LIST_INDEX_FLAG_NOSELECT) != 0)
		info_flags |= MAILBOX_NOSELECT;
	return info_flags;
}

static enum mailbox_list_index_flags
index_mailbox_list_info_flags_translate(enum mailbox_info_flags info_flags)
{
	enum mailbox_list_index_flags flags = 0;

	if ((info_flags & MAILBOX_CHILDREN) != 0)
		flags |= MAILBOX_LIST_INDEX_FLAG_CHILDREN;
	else if ((info_flags & MAILBOX_NOCHILDREN) != 0)
		flags |= MAILBOX_LIST_INDEX_FLAG_NOCHILDREN;

	if ((info_flags & MAILBOX_NONEXISTENT) != 0)
		flags |= MAILBOX_LIST_INDEX_FLAG_NONEXISTENT;
	if ((info_flags & MAILBOX_NOSELECT) != 0)
		flags |= MAILBOX_LIST_INDEX_FLAG_NOSELECT;
	return flags;
}

static int
index_mailbox_list_is_synced(struct index_mailbox_list_iterate_context *ctx)
{
	const struct mail_index_header *hdr;
	struct stat st;
	const char *path = ctx->ctx.list->set.root_dir;

	if (ctx->view == NULL) {
		/* uid_validity changed */
		return 0;
	}

	/* FIXME: single sync_stamp works only with maildir++ */
	if (stat(path, &st) < 0) {
		mailbox_list_set_critical(ctx->ctx.list,
					  "stat(%s) failed: %m", path);
		return -1;
	}
	/*
	   if mtime is older than 2 secs, we set the first bit on
	   if mtime is 0-2 secs old, we set the first bit off.

	   this way we'll always do a resync later when syncing a recently
	   changed directory. if the directory changes while we're syncing it
	   we'll resync it again later.

	   this would work with 1 second difference if we didn't store the
	   dirtyness flag in the stamp's first bit.
	*/
	if (st.st_mtime < ioloop_time - MAILBOX_LIST_SYNC_SECS)
		st.st_mtime |= 1;
	else
		st.st_mtime &= ~1;

	ctx->sync_stamp = st.st_mtime;

	hdr = mail_index_get_header(ctx->mail_view);
	return hdr->sync_stamp == ctx->sync_stamp;
}

static void pattern_parse(struct mailbox_list *list, const char *pattern,
			  const char **prefix_r, int *recurse_level_r)
{
	char sep = list->hierarchy_sep;
	const char *prefix_start, *prefix_end;
	bool seen_wildcards = FALSE;
	int recurse_level = 0;

	prefix_start = prefix_end = pattern;
	for (; *pattern != '\0'; pattern++) {
		if (*pattern == '%')
			seen_wildcards = TRUE;
		else if (*pattern == '*') {
			recurse_level = -1;
			break;
		}

		if (*pattern == sep) {
			if (!seen_wildcards)
				prefix_end = pattern;
			recurse_level++;
		}
	}

	*prefix_r = prefix_start == prefix_end ? "" :
		t_strdup_until(prefix_start, prefix_end);
	*recurse_level_r = recurse_level;
}

static int
index_mailbox_list_sync(struct index_mailbox_list_iterate_context *ctx)
{
	struct mailbox_list *list = ctx->ctx.list;
	struct index_mailbox_list *ilist = INDEX_LIST_CONTEXT(list);
	struct mailbox_list_iterate_context *iter;
	struct mailbox_list_index_sync_ctx *sync_ctx;
	const struct mailbox_info *info;
	enum mailbox_list_sync_flags sync_flags;
	enum mailbox_list_index_flags flags;
	const char *patterns[2];
	uint32_t seq;
	int ret = 0;

	/* FIXME: this works nicely with maildir++, but not others */
	sync_flags = MAILBOX_LIST_SYNC_FLAG_RECURSIVE;
	patterns[0] = "*"; patterns[1] = NULL;

	if (mailbox_list_index_sync_init(ilist->list_index, "",
					 sync_flags, &sync_ctx) < 0)
		return -1;

	ctx->trans = mailbox_list_index_sync_get_transaction(sync_ctx);

	iter = ilist->module_ctx.super.
		iter_init(list, patterns, MAILBOX_LIST_ITER_RETURN_CHILDREN);
	while ((info = ilist->module_ctx.super.iter_next(iter)) != NULL) {
		if (mailbox_list_index_sync_more(sync_ctx, info->name,
						 &seq) < 0) {
			ret = -1;
			break;
		}

		flags = index_mailbox_list_info_flags_translate(info->flags);
		mail_index_update_flags(ctx->trans, seq, MODIFY_REPLACE,
					(enum mail_flags)flags);
	}
	if (ilist->module_ctx.super.iter_deinit(iter) < 0)
		ret = -1;

	if (ret < 0) {
		mailbox_list_index_sync_rollback(&sync_ctx);
		return -1;
	}

	/* FIXME: single sync_stamp works only with maildir++ */
	mail_index_update_header(ctx->trans,
		offsetof(struct mail_index_header, sync_stamp),
		&ctx->sync_stamp, sizeof(ctx->sync_stamp), TRUE);
	return mailbox_list_index_sync_commit(&sync_ctx);
}

static bool
index_mailbox_list_iter_init_try(struct index_mailbox_list_iterate_context *ctx,
				 const char *const *patterns)
{
	struct mailbox_list *list = ctx->ctx.list;
	enum mailbox_list_iter_flags flags = ctx->ctx.flags;
	struct index_mailbox_list *ilist = INDEX_LIST_CONTEXT(list);
	const char *prefix, *cur_prefix, *const *tmp;
	enum mailbox_list_iter_flags subs_flags;
	int cur_recurse_level;

	subs_flags = MAILBOX_LIST_ITER_SELECT_SUBSCRIBED |
		MAILBOX_LIST_ITER_RETURN_NO_FLAGS;
	if ((flags & MAILBOX_LIST_ITER_RAW_LIST) != 0 ||
	    (flags & (subs_flags |
		      MAILBOX_LIST_ITER_RETURN_CHILDREN)) == subs_flags) {
		/* Ignore indexes completely */
		return FALSE;
	}

	ctx->glob = imap_match_init_multiple(default_pool, patterns, TRUE,
					     list->hierarchy_sep);
	if ((flags & (MAILBOX_LIST_ITER_SELECT_SUBSCRIBED |
		      MAILBOX_LIST_ITER_RETURN_SUBSCRIBED)) != 0) {
		/* we'll need to know the subscriptions */
		ctx->subs_tree = mailbox_tree_init(list->hierarchy_sep);
		if (mailbox_list_subscriptions_fill(&ctx->ctx, ctx->subs_tree,
						    ctx->glob, FALSE) < 0) {
			/* let the backend handle this failure */
			return FALSE;
		}
	}

	/* Refresh index before opening our view */
	if (mail_index_refresh(ilist->mail_index) < 0)
		return FALSE;

	ctx->mail_view = mail_index_view_open(ilist->mail_index);
	if (mailbox_list_index_view_init(ilist->list_index,
					 ctx->mail_view, &ctx->view) < 0)
		ctx->view = NULL;

	/* FIXME: we could just do multiple lookups for different patterns */
	prefix = NULL;
	for (tmp = patterns; *tmp != NULL; tmp++) {
		pattern_parse(list, *tmp, &cur_prefix, &cur_recurse_level);
		if (prefix != NULL && strcmp(prefix, cur_prefix) != 0)
			prefix = "";
		if (cur_recurse_level > ctx->recurse_level ||
		    cur_recurse_level == -1)
			ctx->recurse_level = cur_recurse_level;
	}
	if (prefix == NULL)
		prefix = "";

	if (index_mailbox_list_is_synced(ctx) <= 0) {
		if (index_mailbox_list_sync(ctx) < 0)
			return FALSE;

		/* updated, we'll have to reopen views */
		mail_index_view_close(&ctx->mail_view);
		if (ctx->view != NULL)
			mailbox_list_index_view_deinit(&ctx->view);

		ctx->mail_view = mail_index_view_open(ilist->mail_index);
		if (mailbox_list_index_view_init(ilist->list_index,
						 ctx->mail_view,
						 &ctx->view) < 0)
			return FALSE;
	}

	if ((flags & MAILBOX_LIST_ITER_SELECT_SUBSCRIBED) != 0) {
		ctx->subs_iter =
			mailbox_tree_iterate_init(ctx->subs_tree,
						  NULL, MAILBOX_MATCHED);
	} else {
		/* list from index */
		ctx->info_pool =
			pool_alloconly_create("mailbox name pool", 256);
		ctx->iter_ctx =
			mailbox_list_index_iterate_init(ctx->view, prefix,
							ctx->recurse_level);
		ctx->prefix = *prefix == '\0' ? i_strdup(ctx->ns_prefix) :
			i_strdup_printf("%s%s%c", ctx->ns_prefix, prefix,
					list->hierarchy_sep);
	}
	return TRUE;
}

static struct mailbox_list_iterate_context *
index_mailbox_list_iter_init(struct mailbox_list *list,
			     const char *const *patterns,
			     enum mailbox_list_iter_flags flags)
{
	struct index_mailbox_list *ilist = INDEX_LIST_CONTEXT(list);
	struct index_mailbox_list_iterate_context *ctx;

	ctx = i_new(struct index_mailbox_list_iterate_context, 1);
	ctx->ctx.list = list;
	ctx->ctx.flags = flags;
	ctx->ns_prefix = list->ns->prefix;
	ctx->ns_prefix_len = strlen(ctx->ns_prefix);

	if (!index_mailbox_list_iter_init_try(ctx, patterns)) {
		/* no indexing */
		ctx->backend_ctx = ilist->module_ctx.super.
			iter_init(list, patterns, flags);
	}
	return &ctx->ctx;
}

static int
list_index_get_info_flags(struct index_mailbox_list_iterate_context *ctx,
			  uint32_t uid, enum mailbox_info_flags *flags_r)
{
	struct index_mailbox_list *ilist = INDEX_LIST_CONTEXT(ctx->ctx.list);
	const struct mail_index_record *rec;
	uint32_t seq;

	if (!mail_index_lookup_seq(ctx->mail_view, uid, &seq)) {
		i_error("Mailbox list index desynced: "
			"Record uid=%u expunged from mail index", uid);
		mail_index_mark_corrupted(ilist->mail_index);
		return -1;
	}

	rec = mail_index_lookup(ctx->mail_view, seq);
	*flags_r = index_mailbox_list_index_flags_translate(rec->flags);
	return 0;
}

static int list_index_iter_next(struct index_mailbox_list_iterate_context *ctx,
				const struct mailbox_info **info_r)
{
	struct index_mailbox_list *ilist = INDEX_LIST_CONTEXT(ctx->ctx.list);
	struct mailbox_list_index_info iinfo;
	struct mailbox_node *subs_node;
	int ret;

	/* find the next matching mailbox */
	for (;;) {
		p_clear(ctx->info_pool);
		ret = mailbox_list_index_iterate_next(ctx->iter_ctx, &iinfo);
		if (ret <= 0) {
			*info_r = NULL;
			return ret;
		}

		ctx->info.name = *ctx->prefix == '\0' ? iinfo.name :
			p_strconcat(ctx->info_pool, ctx->prefix,
				    iinfo.name, NULL);
		if (imap_match(ctx->glob, ctx->info.name) != IMAP_MATCH_YES)
			continue;

		if (list_index_get_info_flags(ctx, iinfo.uid,
					      &ctx->info.flags) < 0)
			return -1;

		if ((ctx->info.flags & MAILBOX_NOCHILDREN) != 0 &&
		    iinfo.has_children) {
			i_error("Mailbox list index desynced: "
				"Children flags for uid=%u wrong in mail index",
				iinfo.uid);
			mail_index_mark_corrupted(ilist->mail_index);
			return -1;
		}

		/* skip nonexistent mailboxes when finding with "*" */
		if ((ctx->info.flags & MAILBOX_NONEXISTENT) != 0 &&
		    ctx->recurse_level < 0)
			continue;

		if (ctx->subs_tree != NULL) {
			/* get subscription states */
			subs_node = mailbox_tree_lookup(ctx->subs_tree,
							ctx->info.name);
			if (subs_node != NULL) {
				ctx->info.flags |= subs_node->flags &
					(MAILBOX_SUBSCRIBED |
					 MAILBOX_CHILD_SUBSCRIBED);
			}
		}

		*info_r = &ctx->info;
		return 0;
	}
}

static const struct mailbox_info *
index_mailbox_list_iter_next(struct mailbox_list_iterate_context *_ctx)
{
	struct index_mailbox_list_iterate_context *ctx =
		(struct index_mailbox_list_iterate_context *)_ctx;
	struct index_mailbox_list *ilist = INDEX_LIST_CONTEXT(_ctx->list);
	const struct mailbox_info *info;
	struct mailbox_node *subs_node;
	const char *index_name;
	uint32_t uid;

	if (ctx->iter_ctx != NULL) {
		/* listing mailboxes from index */
		if (list_index_iter_next(ctx, &info) < 0) {
			ctx->failed = TRUE;
			return NULL;
		}
		return info;
	} else if (ctx->backend_ctx != NULL) {
		/* index isn't being used */
		return ilist->module_ctx.super.iter_next(ctx->backend_ctx);
	}

	/* listing subscriptions, but we also want flags */
	subs_node = mailbox_tree_iterate_next(ctx->subs_iter, &ctx->info.name);
	if (subs_node == NULL)
		return NULL;

	index_name = ctx->info.name;
	if (ctx->ns_prefix_len > 0 &&
	    strncmp(ctx->info.name, ctx->ns_prefix, ctx->ns_prefix_len) == 0)
		index_name += ctx->ns_prefix_len;

	if (mailbox_list_index_lookup(ctx->view, index_name, &uid) < 0 ||
	    list_index_get_info_flags(ctx, uid, &ctx->info.flags) < 0) {
		ctx->failed = TRUE;
		return NULL;
	}

	ctx->info.flags |= subs_node->flags &
		(MAILBOX_SUBSCRIBED | MAILBOX_CHILD_SUBSCRIBED);
	return &ctx->info;
}

static int
index_mailbox_list_iter_deinit(struct mailbox_list_iterate_context *_ctx)
{
	struct index_mailbox_list_iterate_context *ctx =
		(struct index_mailbox_list_iterate_context *)_ctx;
	struct index_mailbox_list *ilist = INDEX_LIST_CONTEXT(_ctx->list);
	int ret = ctx->failed ? -1 : 0;

	if (ctx->subs_iter != NULL)
		mailbox_tree_iterate_deinit(&ctx->subs_iter);
	if (ctx->iter_ctx != NULL)
		mailbox_list_index_iterate_deinit(&ctx->iter_ctx);
	if (ctx->info_pool != NULL)
		pool_unref(&ctx->info_pool);

	if (ctx->mail_view != NULL)
		mail_index_view_close(&ctx->mail_view);
	if (ctx->view != NULL)
		mailbox_list_index_view_deinit(&ctx->view);

	if (ctx->backend_ctx != NULL)
		ret = ilist->module_ctx.super.iter_deinit(ctx->backend_ctx);

	if (ctx->glob != NULL)
		imap_match_deinit(&ctx->glob);
	i_free(ctx->prefix);
	i_free(ctx);
	return ret;
}

static void index_mailbox_list_deinit(struct mailbox_list *list)
{
	struct index_mailbox_list *ilist = INDEX_LIST_CONTEXT(list);

	mailbox_list_index_free(&ilist->list_index);
	mailbox_list_index_view_deinit(&ilist->list_sync_view);
	mail_index_free(&ilist->mail_index);

	ilist->module_ctx.super.deinit(list);
}

static int index_mailbox_list_open_indexes(struct mailbox_list *list,
					   const char *dir)
{
	struct index_mailbox_list *ilist = INDEX_LIST_CONTEXT(list);
	const char *path;
	enum mail_index_open_flags index_flags = 0;
	int ret;

	index_flags = mail_storage_settings_to_index_flags(list->mail_set);

	mail_index_set_lock_method(ilist->mail_index,
				   list->mail_set->parsed_lock_method, -1U);
	if (mail_index_open_or_create(ilist->mail_index, index_flags) < 0) {
		if (mail_index_move_to_memory(ilist->mail_index) < 0) {
			/* try opening once more. it should be created
			   directly into memory now. */
			ret = mail_index_open_or_create(ilist->mail_index,
							index_flags);
			if (ret < 0) {
				/* everything failed. there's a bug in the
				   code, but just work around it by disabling
				   the index completely */
				return -1;
			}
		}
	}

	path = t_strconcat(dir, "/"MAILBOX_LIST_INDEX_NAME, NULL);
	ilist->list_index = mailbox_list_index_alloc(path, list->hierarchy_sep,
						     ilist->mail_index);
	if (mailbox_list_index_open_or_create(ilist->list_index) < 0) {
		/* skip indexing */
		mailbox_list_index_free(&ilist->list_index);
		return -1;
	}
	if (mailbox_list_index_view_init(ilist->list_index, NULL,
					 &ilist->list_sync_view) < 0) {
		mailbox_list_index_free(&ilist->list_index);
		return -1;
	}
	return 0;
}

static void index_mailbox_list_created(struct mailbox_list *list)
{
	struct index_mailbox_list *ilist = NULL;
	const char *dir;

	/* FIXME: always disabled for now */
	dir = mailbox_list_get_path(list, NULL, MAILBOX_LIST_PATH_TYPE_INDEX);
	if (*dir == '\0' || list->mail_set->mailbox_list_index_disable ||
	    strcmp(list->name, "maildir++") != 0 || 1) {
		/* reserve the module context anyway, so syncing code knows
		   that the index is disabled */
		MODULE_CONTEXT_SET(list, index_mailbox_list_module, ilist);
		return;
	}

	ilist = p_new(list->pool, struct index_mailbox_list, 1);
	ilist->module_ctx.super = list->v;

	list->v.deinit = index_mailbox_list_deinit;
	list->v.iter_init = index_mailbox_list_iter_init;
	list->v.iter_deinit = index_mailbox_list_iter_deinit;
	list->v.iter_next = index_mailbox_list_iter_next;
	MODULE_CONTEXT_SET(list, index_mailbox_list_module, ilist);

	ilist->mail_index = mail_index_alloc(dir, MAIL_INDEX_PREFIX);

	/* sync_init allocates the extensions. do it here before opening the
	   index files, so that our initial memory pool size guesses are a
	   bit more optimal */
	index_mailbox_list_sync_init_list(list);

	if (index_mailbox_list_open_indexes(list, dir) < 0) {
		list->v = ilist->module_ctx.super;
		mail_index_free(&ilist->mail_index);
		MODULE_CONTEXT_UNSET(list, index_mailbox_list_module);
	}
}

static struct mail_storage_hooks index_mailbox_list_hooks = {
	.mailbox_list_created = index_mailbox_list_created
};

void index_mailbox_list_init(void); /* called in mailbox-list-register.c */

void index_mailbox_list_init(void)
{
	mail_storage_hooks_add_internal(&index_mailbox_list_hooks);
	index_mailbox_list_sync_init();
}
