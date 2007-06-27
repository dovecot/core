/* Copyright (C) 2002-2006 Timo Sirainen */

#include "lib.h"
#include "str.h"
#include "home-expand.h"
#include "imap-match.h"
#include "subscription-file.h"
#include "mailbox-tree.h"
#include "mailbox-list-maildir.h"

#include <dirent.h>

#define MAILBOX_FLAG_MATCHED 0x40000000

struct maildir_list_iterate_context {
	struct mailbox_list_iterate_context ctx;
	pool_t pool;

	const char *dir, *prefix;

        struct mailbox_tree_context *tree_ctx;
	struct mailbox_tree_iterate_context *tree_iter;

	struct mailbox_info info;
};

static void maildir_nodes_fix(struct mailbox_node *node, bool is_subs)
{
	while (node != NULL) {
		if (node->children != NULL) {
			node->flags |= MAILBOX_CHILDREN;
			node->flags &= ~MAILBOX_NOCHILDREN;
			maildir_nodes_fix(node->children, is_subs);
		} else if ((node->flags & MAILBOX_NONEXISTENT) != 0) {
			if (!is_subs) {
				node->flags &= ~MAILBOX_NONEXISTENT;
				node->flags |= MAILBOX_NOSELECT;
			}
			node->flags |= MAILBOX_CHILDREN;
		}
		node = node->next;
	}
}

static int
maildir_fill_readdir(struct maildir_list_iterate_context *ctx,
		     struct imap_match_glob *glob, bool update_only)
{
	DIR *dirp;
	struct dirent *d;
	const char *p, *mailbox_c;
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

		/* make sure the mask matches */
		str_truncate(mailbox, 0);
		str_append(mailbox, ctx->prefix);
		str_append(mailbox, fname + 1);
                mailbox_c = str_c(mailbox);

		match = imap_match(glob, mailbox_c);

		if (match != IMAP_MATCH_YES &&
		    match != IMAP_MATCH_PARENT)
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

		if (match == IMAP_MATCH_PARENT) {
			t_push();
			while ((p = strrchr(mailbox_c,
					    hierarchy_sep)) != NULL) {
				str_truncate(mailbox, (size_t) (p-mailbox_c));
				mailbox_c = str_c(mailbox);
				if (imap_match(glob, mailbox_c) > 0)
					break;
			}
			i_assert(p != NULL);

			created = FALSE;
			node = update_only ?
				mailbox_tree_update(ctx->tree_ctx, mailbox_c) :
				mailbox_tree_get(ctx->tree_ctx,
						 mailbox_c, &created);
			if (node != NULL) {
				if (created)
					node->flags = MAILBOX_NONEXISTENT;

				node->flags |= MAILBOX_CHILDREN |
					MAILBOX_FLAG_MATCHED;
				node->flags &= ~MAILBOX_NOCHILDREN;
			}

			t_pop();
		} else {
			created = FALSE;
			node = update_only ?
				mailbox_tree_update(ctx->tree_ctx, mailbox_c) :
				mailbox_tree_get(ctx->tree_ctx,
						 mailbox_c, &created);

			if (node != NULL) {
				if (created)
					node->flags = MAILBOX_NOCHILDREN;
				node->flags &= ~MAILBOX_NONEXISTENT;
				node->flags |= MAILBOX_FLAG_MATCHED;
			}
		}
		if (node != NULL) {
			node->flags |= flags & ~(MAILBOX_NOINFERIORS |
						 MAILBOX_CHILDREN |
						 MAILBOX_NOCHILDREN);
		}
	}
	t_pop();

	if (closedir(dirp) < 0) {
		mailbox_list_set_critical(ctx->ctx.list,
					  "readdir(%s) failed: %m", ctx->dir);
		return -1;
	}

	if ((ctx->ctx.list->ns->flags & NAMESPACE_FLAG_INBOX) != 0 &&
	    (ctx->ctx.flags & MAILBOX_LIST_ITER_SUBSCRIBED) == 0) {
		/* make sure INBOX is there */
		node = mailbox_tree_get(ctx->tree_ctx, "INBOX", &created);
		if (created)
			node->flags = MAILBOX_NOCHILDREN;
		else
			node->flags &= ~MAILBOX_NONEXISTENT;

		switch (imap_match(glob, "INBOX")) {
		case IMAP_MATCH_YES:
		case IMAP_MATCH_PARENT:
			node->flags |= MAILBOX_FLAG_MATCHED;
			break;
		default:
			break;
		}
	}
	maildir_nodes_fix(mailbox_tree_get(ctx->tree_ctx, NULL, NULL),
			  (ctx->ctx.flags & MAILBOX_LIST_ITER_SUBSCRIBED) != 0);
	return 0;
}

static int maildir_fill_subscribed(struct maildir_list_iterate_context *ctx,
				   struct imap_match_glob *glob)
{
	struct subsfile_list_context *subsfile_ctx;
	const char *path, *name, *p;
	struct mailbox_node *node;
	char hierarchy_sep;
	bool created;

	path = t_strconcat(ctx->ctx.list->set.control_dir != NULL ?
			   ctx->ctx.list->set.control_dir :
			   ctx->ctx.list->set.root_dir,
			   "/", ctx->ctx.list->set.subscription_fname, NULL);
	subsfile_ctx = subsfile_list_init(ctx->ctx.list, path);

	hierarchy_sep = ctx->ctx.list->hierarchy_sep;
	while ((name = subsfile_list_next(subsfile_ctx)) != NULL) {
		switch (imap_match(glob, name)) {
		case IMAP_MATCH_YES:
			node = mailbox_tree_get(ctx->tree_ctx, name, NULL);
			node->flags = MAILBOX_FLAG_MATCHED;
			if ((ctx->ctx.flags &
			     MAILBOX_LIST_ITER_FAST_FLAGS) == 0) {
				node->flags |= MAILBOX_NONEXISTENT |
					MAILBOX_NOCHILDREN;
			}
			break;
		case IMAP_MATCH_PARENT:
			/* placeholder */
			while ((p = strrchr(name, hierarchy_sep)) != NULL) {
				name = t_strdup_until(name, p);
				if (imap_match(glob, name) > 0)
					break;
			}
			i_assert(p != NULL);

			node = mailbox_tree_get(ctx->tree_ctx, name, &created);
			if (created) node->flags = MAILBOX_NONEXISTENT;
			node->flags |= MAILBOX_FLAG_MATCHED | MAILBOX_CHILDREN;
			node->flags &= ~MAILBOX_NOCHILDREN;
			break;
		default:
			break;
		}
	}

	return subsfile_list_deinit(subsfile_ctx);
}

struct mailbox_list_iterate_context *
maildir_list_iter_init(struct mailbox_list *_list, const char *mask,
		       enum mailbox_list_iter_flags flags)
{
	struct maildir_list_iterate_context *ctx;
        struct imap_match_glob *glob;
	const char *dir, *p;
	pool_t pool;

	pool = pool_alloconly_create("maildir_list", 1024);
	ctx = p_new(pool, struct maildir_list_iterate_context, 1);
	ctx->ctx.list = _list;
	ctx->ctx.flags = flags;
	ctx->pool = pool;
	ctx->tree_ctx = mailbox_tree_init(_list->hierarchy_sep);

	glob = imap_match_init(pool, mask, TRUE, _list->hierarchy_sep);

	ctx->dir = _list->set.root_dir;
	ctx->prefix = "";

	if ((flags & MAILBOX_LIST_ITER_SUBSCRIBED) != 0) {
		if (maildir_fill_subscribed(ctx, glob) < 0) {
			ctx->ctx.failed = TRUE;
			return &ctx->ctx;
		}
	} else if ((_list->flags & MAILBOX_LIST_FLAG_FULL_FS_ACCESS) != 0 &&
		   (p = strrchr(mask, '/')) != NULL) {
		dir = t_strdup_until(mask, p);
		ctx->prefix = p_strdup_until(pool, mask, p+1);

		if (*mask != '/' && *mask != '~')
			dir = t_strconcat(_list->set.root_dir, "/", dir, NULL);
		ctx->dir = p_strdup(pool, home_expand(dir));
	}

	if ((flags & MAILBOX_LIST_ITER_SUBSCRIBED) == 0 ||
	    (ctx->ctx.flags & MAILBOX_LIST_ITER_FAST_FLAGS) == 0) {
		bool update_only = (flags & MAILBOX_LIST_ITER_SUBSCRIBED) != 0;
		if (maildir_fill_readdir(ctx, glob, update_only) < 0) {
			ctx->ctx.failed = TRUE;
			return &ctx->ctx;
		}
	}

	ctx->tree_iter = mailbox_tree_iterate_init(ctx->tree_ctx, NULL,
						   MAILBOX_FLAG_MATCHED);
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
