/* Copyright (C) 2002-2006 Timo Sirainen */

#include "lib.h"
#include "str.h"
#include "home-expand.h"
#include "imap-match.h"
#include "mailbox-tree.h"
#include "mailbox-list-subscriptions.h"
#include "mailbox-list-maildir.h"

#include <dirent.h>

struct maildir_list_iterate_context {
	struct mailbox_list_iterate_context ctx;
	pool_t pool;

	const char *dir;

        struct mailbox_tree_context *tree_ctx;
	struct mailbox_tree_iterate_context *tree_iter;

	struct mailbox_info info;
};

static void node_fix_parents(struct mailbox_node *node)
{
	/* Fix parent nodes' children states. also if we happened to create any
	   of the parents, we need to mark them nonexistent. */
	node = node->parent;
	for (; node != NULL; node = node->parent) {
		if ((node->flags & MAILBOX_MATCHED) == 0)
			node->flags |= MAILBOX_NONEXISTENT;

		node->flags |= MAILBOX_CHILDREN;
		node->flags &= ~MAILBOX_NOCHILDREN;
	}
}

static void maildir_fill_parents(struct maildir_list_iterate_context *ctx,
				 struct imap_match_glob *glob, bool update_only,
				 string_t *mailbox, const char *mailbox_c,
				 enum mailbox_info_flags flags)
{
	struct mailbox_node *node;
	const char *p;
	char hierarchy_sep;
	bool created;

	hierarchy_sep = ctx->ctx.list->hierarchy_sep;

	t_push();
	while ((p = strrchr(mailbox_c, hierarchy_sep)) != NULL) {
		str_truncate(mailbox, (size_t) (p-mailbox_c));
		mailbox_c = str_c(mailbox);
		if (imap_match(glob, mailbox_c) == IMAP_MATCH_YES) {
			created = FALSE;
			node = update_only ?
				mailbox_tree_lookup(ctx->tree_ctx, mailbox_c) :
				mailbox_tree_get(ctx->tree_ctx,
						 mailbox_c, &created);
			if (node != NULL) {
				if (created) {
					/* we haven't yet seen this mailbox,
					   but we might see it later */
					node->flags = MAILBOX_NONEXISTENT;
				}
				if (!update_only)
					node->flags |= MAILBOX_MATCHED;
				node->flags |= MAILBOX_CHILDREN | flags;
				node->flags &= ~MAILBOX_NOCHILDREN;
				node_fix_parents(node);
			}
		}
	}
	t_pop();
}

static int
maildir_fill_readdir(struct maildir_list_iterate_context *ctx,
		     struct imap_match_glob *glob, bool update_only)
{
	DIR *dirp;
	struct dirent *d;
	const char *mailbox_c;
	string_t *mailbox;
	enum mailbox_info_flags flags;
	enum imap_match_result match;
	struct mailbox_node *node;
	bool created;
	char hierarchy_sep;
	int ret;

	dirp = opendir(ctx->dir);
	if (dirp == NULL) {
		if (errno != ENOENT) {
			mailbox_list_set_critical(ctx->ctx.list,
				"opendir(%s) failed: %m", ctx->dir);
			return -1;
		}
		return 0;
	}

	hierarchy_sep = ctx->ctx.list->hierarchy_sep;

	t_push();
	mailbox = t_str_new(PATH_MAX);
	while ((d = readdir(dirp)) != NULL) {
		const char *fname = d->d_name;

		if (fname[0] != hierarchy_sep)
			continue;

		/* skip . and .. */
		if (fname[0] == '.' &&
		    (fname[1] == '\0' || (fname[1] == '.' && fname[2] == '\0')))
			continue;

		/* make sure the pattern matches */
		str_truncate(mailbox, 0);
		if ((ctx->ctx.list->ns->flags & NAMESPACE_FLAG_INBOX) == 0 ||
		    strcasecmp(fname + 1, "INBOX") != 0)
			str_append(mailbox, ctx->ctx.list->ns->prefix);
		str_append(mailbox, fname + 1);
                mailbox_c = str_c(mailbox);

		match = imap_match(glob, mailbox_c);
		if ((match & (IMAP_MATCH_YES | IMAP_MATCH_PARENT)) == 0)
			continue;

		/* check if this is an actual mailbox */
		flags = 0;
		ret = ctx->ctx.list->v.
			iter_is_mailbox(&ctx->ctx, ctx->dir, fname,
					mailbox_list_get_file_type(d), &flags);
		if (ret < 0) {
			t_pop();
			return -1;
		}
		if (ret == 0)
			continue;

		/* we know the children flags ourself, so ignore if any of
		   them were set. */
		flags &= ~(MAILBOX_NOINFERIORS |
			   MAILBOX_CHILDREN | MAILBOX_NOCHILDREN);

		if ((match & IMAP_MATCH_PARENT) != 0) {
			maildir_fill_parents(ctx, glob, update_only,
					     mailbox, mailbox_c, flags);
		} else {
			created = FALSE;
			node = update_only ?
				mailbox_tree_lookup(ctx->tree_ctx, mailbox_c) :
				mailbox_tree_get(ctx->tree_ctx,
						 mailbox_c, &created);

			if (node != NULL) {
				if (created)
					node->flags = MAILBOX_NOCHILDREN;
				else
					node->flags &= ~MAILBOX_NONEXISTENT;
				if (!update_only)
					node->flags |= MAILBOX_MATCHED;
				node->flags |= flags;
				node_fix_parents(node);
			}
		}
	}
	t_pop();

	if (closedir(dirp) < 0) {
		mailbox_list_set_critical(ctx->ctx.list,
					  "readdir(%s) failed: %m", ctx->dir);
		return -1;
	}

	if ((ctx->ctx.list->ns->flags & NAMESPACE_FLAG_INBOX) != 0) {
		/* make sure INBOX is there */
		created = FALSE;
		node = update_only ?
			mailbox_tree_lookup(ctx->tree_ctx, "INBOX") :
			mailbox_tree_get(ctx->tree_ctx, "INBOX", &created);
		if (created)
			node->flags = MAILBOX_NOCHILDREN;
		else if (node != NULL)
			node->flags &= ~MAILBOX_NONEXISTENT;

		match = imap_match(glob, "INBOX");
		if ((match & (IMAP_MATCH_YES | IMAP_MATCH_PARENT)) != 0) {
			if (!update_only)
				node->flags |= MAILBOX_MATCHED;
		}
	} else if (mailbox_tree_lookup(ctx->tree_ctx, "INBOX") == NULL &&
		   imap_match(glob, "INBOX")) {
		/* see if INBOX exists. */
		ret = ctx->ctx.list->v.
			iter_is_mailbox(&ctx->ctx, ctx->dir, "",
					MAILBOX_LIST_FILE_TYPE_UNKNOWN, &flags);
		if (ret > 0) {
			mailbox_c = t_strconcat(ctx->ctx.list->ns->prefix,
						"INBOX", NULL);
			node = mailbox_tree_get(ctx->tree_ctx, mailbox_c, NULL);
			node->flags = MAILBOX_NOCHILDREN | MAILBOX_MATCHED;
		}
	}
	return 0;
}

struct mailbox_list_iterate_context *
maildir_list_iter_init(struct mailbox_list *_list, const char *const *patterns,
		       enum mailbox_list_iter_flags flags)
{
	struct maildir_list_iterate_context *ctx;
        struct imap_match_glob *glob;
	pool_t pool;

	pool = pool_alloconly_create("maildir_list", 1024);
	ctx = p_new(pool, struct maildir_list_iterate_context, 1);
	ctx->ctx.list = _list;
	ctx->ctx.flags = flags;
	ctx->pool = pool;
	ctx->tree_ctx = mailbox_tree_init(_list->hierarchy_sep);

	glob = imap_match_init_multiple(pool, patterns, TRUE,
					_list->hierarchy_sep);

	ctx->dir = _list->set.root_dir;

	if ((flags & MAILBOX_LIST_ITER_SELECT_SUBSCRIBED) != 0) {
		/* Listing only subscribed mailboxes.
		   Flags are set later if needed. */
		if (mailbox_list_subscriptions_fill(&ctx->ctx, ctx->tree_ctx,
						    glob, FALSE) < 0) {
			ctx->ctx.failed = TRUE;
			return &ctx->ctx;
		}
	}

	if ((flags & MAILBOX_LIST_ITER_SELECT_SUBSCRIBED) == 0 ||
	    (flags & MAILBOX_LIST_ITER_RETURN_NO_FLAGS) == 0) {
		/* Add/update mailbox list with flags */
		bool update_only =
			(flags & MAILBOX_LIST_ITER_SELECT_SUBSCRIBED) != 0;

		if (maildir_fill_readdir(ctx, glob, update_only) < 0) {
			ctx->ctx.failed = TRUE;
			return &ctx->ctx;
		}
	}

	if ((flags & MAILBOX_LIST_ITER_RETURN_SUBSCRIBED) != 0 &&
	    (flags & MAILBOX_LIST_ITER_SELECT_SUBSCRIBED) == 0) {
		/* we're listing all mailboxes but we want to know
		   \Subscribed flags */
		if (mailbox_list_subscriptions_fill(&ctx->ctx, ctx->tree_ctx,
						    glob, TRUE) < 0) {
			ctx->ctx.failed = TRUE;
			return &ctx->ctx;
		}
	}

	ctx->tree_iter = mailbox_tree_iterate_init(ctx->tree_ctx, NULL,
						   MAILBOX_MATCHED);
	return &ctx->ctx;
}

int maildir_list_iter_deinit(struct mailbox_list_iterate_context *_ctx)
{
	struct maildir_list_iterate_context *ctx =
		(struct maildir_list_iterate_context *)_ctx;
	int ret = ctx->ctx.failed ? -1 : 0;

	if (ctx->tree_iter != NULL)
		mailbox_tree_iterate_deinit(&ctx->tree_iter);
	mailbox_tree_deinit(&ctx->tree_ctx);
	pool_unref(ctx->pool);
	return ret;
}

const struct mailbox_info *
maildir_list_iter_next(struct mailbox_list_iterate_context *_ctx)
{
	struct maildir_list_iterate_context *ctx =
		(struct maildir_list_iterate_context *)_ctx;
	struct mailbox_node *node;

	if (ctx->ctx.failed)
		return NULL;

	node = mailbox_tree_iterate_next(ctx->tree_iter, &ctx->info.name);
	if (node == NULL)
		return NULL;

	ctx->info.flags = node->flags;
	return &ctx->info;
}
