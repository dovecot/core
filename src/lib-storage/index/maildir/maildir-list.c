/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "ioloop.h"
#include "str.h"
#include "home-expand.h"
#include "unlink-directory.h"
#include "imap-match.h"
#include "subscription-file/subscription-file.h"
#include "maildir-storage.h"
#include "mailbox-tree.h"

#include <dirent.h>
#include <sys/stat.h>

#define MAILBOX_FLAG_MATCHED 0x40000000

struct mailbox_list_context {
	pool_t pool;

	struct mail_storage *storage;
	const char *dir, *prefix;
        enum mailbox_list_flags flags;

        struct mailbox_tree_context *tree_ctx;

	string_t *node_path;
	size_t parent_pos;
	struct mailbox_node *root, *next_node;
	struct mailbox_list list;
	int failed;
};

static void maildir_nodes_fix(struct mailbox_node *node, int is_subs)
{
	while (node != NULL) {
		if (node->children != NULL) {
			node->flags |= MAILBOX_CHILDREN;
			maildir_nodes_fix(node->children, is_subs);
		} else if ((node->flags & MAILBOX_PLACEHOLDER) != 0) {
			if (!is_subs) {
				node->flags &= ~MAILBOX_PLACEHOLDER;
				node->flags |= MAILBOX_NOSELECT;
			}
		} else {
			if ((node->flags & MAILBOX_CHILDREN) == 0)
				node->flags |= MAILBOX_NOCHILDREN;
		}
		node = node->next;
	}
}

static int maildir_fill_readdir(struct mailbox_list_context *ctx,
				struct imap_match_glob *glob, int update_only)
{
	DIR *dirp;
	struct dirent *d;
	const char *path, *p;
	string_t *mailbox;
	enum imap_match_result match;
	struct mailbox_node *node;
	int created;

	dirp = opendir(ctx->dir);
	if (dirp == NULL) {
		if (errno != ENOENT) {
			mail_storage_set_critical(ctx->storage,
				"opendir(%s) failed: %m", ctx->dir);
			return FALSE;
		}
	}

	/* INBOX exists always */
	if (imap_match(glob, "INBOX") > 0 && !update_only) {
		node = mailbox_tree_get(ctx->tree_ctx, "INBOX", NULL);
		node->flags |= MAILBOX_FLAG_MATCHED;
		node->flags &= ~(MAILBOX_PLACEHOLDER | MAILBOX_NONEXISTENT);
	}

	mailbox = t_str_new(PATH_MAX);
	while ((d = readdir(dirp)) != NULL) {
		const char *fname = d->d_name;

		if (fname[0] != '.')
			continue;

		/* skip . and .. */
		if (fname[1] == '\0' || (fname[1] == '.' && fname[2] == '\0'))
			continue;

		/* FIXME: kludges. these files must be renamed later */
		if (strcmp(fname, ".customflags") == 0 ||
		    strcmp(fname, ".subscriptions") == 0)
			continue;

		fname++;
		if (*fname == '.') {
			/* this mailbox is in the middle of being deleted,
			   or the process trying to delete it had died.

			   delete it ourself if it's been there longer than
			   one hour. don't touch it if it's outside our
			   mail root dir. */
			struct stat st;

			if (*ctx->prefix == '\0')
				continue;

			t_push();
			path = t_strdup_printf("%s/%s", ctx->dir, fname);
			if (stat(path, &st) == 0 &&
			    st.st_mtime < ioloop_time - 3600)
				(void)unlink_directory(path, TRUE);
			t_pop();
			continue;
		}

		/* make sure the mask matches */
		str_truncate(mailbox, 0);
		str_append(mailbox, ctx->prefix);
		str_append(mailbox, fname);

		match = imap_match(glob, str_c(mailbox));

		if (match != IMAP_MATCH_YES &&
		    (match != IMAP_MATCH_PARENT || update_only))
			continue;

		if (strcasecmp(str_c(mailbox), "INBOX") == 0)
			continue; /* ignore inboxes */

		if (match == IMAP_MATCH_PARENT) {
			t_push();
			while ((p = strrchr(fname, '.')) != NULL) {
				fname = t_strdup_until(fname, p);
				p = t_strconcat(ctx->prefix, fname, NULL);
				if (imap_match(glob, p) > 0)
					break;
			}
			i_assert(p != NULL);

			node = mailbox_tree_get(ctx->tree_ctx, p, &created);
			if (created)
				node->flags = MAILBOX_PLACEHOLDER;
			node->flags |= MAILBOX_CHILDREN | MAILBOX_FLAG_MATCHED;

			t_pop();
		} else {
			p = str_c(mailbox);
			if (update_only)
				node = mailbox_tree_update(ctx->tree_ctx, p);
			else
				node = mailbox_tree_get(ctx->tree_ctx, p, NULL);

			if (node != NULL) {
				node->flags &= ~(MAILBOX_PLACEHOLDER |
						 MAILBOX_NONEXISTENT);
				node->flags |= MAILBOX_FLAG_MATCHED;
			}
		}
	}

	if (closedir(dirp) < 0) {
		mail_storage_set_critical(ctx->storage,
					  "readdir(%s) failed: %m", ctx->dir);
		return FALSE;
	}

	maildir_nodes_fix(mailbox_tree_get(ctx->tree_ctx, NULL, NULL),
			  (ctx->flags & MAILBOX_LIST_SUBSCRIBED) != 0);
	return TRUE;
}

static int maildir_fill_subscribed(struct mailbox_list_context *ctx,
				   struct imap_match_glob *glob,
				   int nonexistent)
{
	struct subsfile_list_context *subsfile_ctx;
	const char *name, *p;
	struct mailbox_node *node;
	int created;

	subsfile_ctx = subsfile_list_init(ctx->storage);
	if (subsfile_ctx == NULL)
		return FALSE;

	while ((name = subsfile_list_next(subsfile_ctx)) != NULL) {
		switch (imap_match(glob, name)) {
		case IMAP_MATCH_YES:
			node = mailbox_tree_get(ctx->tree_ctx, name, NULL);
			node->flags = MAILBOX_FLAG_MATCHED;
			if (nonexistent && strcasecmp(name, "INBOX") != 0)
				node->flags |= MAILBOX_NONEXISTENT;
			break;
		case IMAP_MATCH_PARENT:
			/* placeholder */
			while ((p = strrchr(name, '.')) != NULL) {
				name = t_strdup_until(name, p);
				if (imap_match(glob, name) > 0)
					break;
			}
			i_assert(p != NULL);

			node = mailbox_tree_get(ctx->tree_ctx, name, &created);
			if (created) node->flags = MAILBOX_PLACEHOLDER;
			node->flags |= MAILBOX_FLAG_MATCHED;
			break;
		default:
			break;
		}
	}

	return subsfile_list_deinit(subsfile_ctx);

}

struct mailbox_list_context *
maildir_list_mailbox_init(struct mail_storage *storage,
			  const char *mask, enum mailbox_list_flags flags)
{
        struct mailbox_list_context *ctx;
        struct imap_match_glob *glob;
	const char *dir, *p;
	int nonexistent;
	pool_t pool;

	mail_storage_clear_error(storage);

	pool = pool_alloconly_create("maildir_list", 1024);
	ctx = p_new(pool, struct mailbox_list_context, 1);
	ctx->pool = pool;
	ctx->storage = storage;
	ctx->flags = flags;
	ctx->tree_ctx = mailbox_tree_init('.');

	glob = imap_match_init(pool, mask, TRUE, '.');

	if ((flags & MAILBOX_LIST_SUBSCRIBED) != 0) {
		ctx->dir = storage->dir;
		ctx->prefix = "";

		nonexistent = (flags & MAILBOX_LIST_FAST_FLAGS) == 0;
		if (!maildir_fill_subscribed(ctx, glob, nonexistent)) {
                        mailbox_tree_deinit(ctx->tree_ctx);
			pool_unref(pool);
			return NULL;
		}
	} else {
		if (!full_filesystem_access ||
		    (p = strrchr(mask, '/')) == NULL) {
			ctx->dir = storage->dir;
			ctx->prefix = "";
		} else {
			dir = t_strdup_until(mask, p);
			ctx->prefix = t_strdup_until(mask, p+1);

			if (*mask != '/' && *mask != '~')
				dir = t_strconcat(storage->dir, "/", dir, NULL);
			ctx->dir = p_strdup(pool, home_expand(dir));
		}
	}

	if ((flags & MAILBOX_LIST_SUBSCRIBED) == 0 ||
	    (ctx->flags & MAILBOX_LIST_FAST_FLAGS) == 0) {
		int update_only = (flags & MAILBOX_LIST_SUBSCRIBED) != 0;
		if (!maildir_fill_readdir(ctx, glob, update_only)) {
			mailbox_tree_deinit(ctx->tree_ctx);
			pool_unref(pool);
			return NULL;
		}
	}

	ctx->node_path = str_new(pool, 256);
	ctx->root = mailbox_tree_get(ctx->tree_ctx, NULL, NULL);
	return ctx;
}

int maildir_list_mailbox_deinit(struct mailbox_list_context *ctx)
{
	mailbox_tree_deinit(ctx->tree_ctx);
	pool_unref(ctx->pool);
	return TRUE;
}

static struct mailbox_node *find_next(struct mailbox_node **node,
				      string_t *path)
{
	struct mailbox_node *child;
	size_t len;

	while (*node != NULL) {
		if (((*node)->flags & MAILBOX_FLAG_MATCHED) != 0)
			return *node;

		if ((*node)->children != NULL) {
			len = str_len(path);
			if (len != 0)
				str_append_c(path, '.');
			str_append(path, (*node)->name);

			child = find_next(&(*node)->children, path);
			if (child != NULL)
				return child;

			str_truncate(path, len);
		}

		*node = (*node)->next;
	}

	return NULL;
}

struct mailbox_list *
maildir_list_mailbox_next(struct mailbox_list_context *ctx)
{
	struct mailbox_node *node;

	for (node = ctx->next_node; node != NULL; node = node->next) {
		if ((node->flags & MAILBOX_FLAG_MATCHED) != 0)
			break;
	}

	if (node == NULL) {
		str_truncate(ctx->node_path, 0);
		node = find_next(&ctx->root, ctx->node_path);
                ctx->parent_pos = str_len(ctx->node_path);

		if (node == NULL)
			return NULL;
	}
	ctx->next_node = node->next;

	i_assert((node->flags & MAILBOX_FLAG_MATCHED) != 0);
	node->flags &= ~MAILBOX_FLAG_MATCHED;

	str_truncate(ctx->node_path, ctx->parent_pos);
	if (ctx->parent_pos != 0)
		str_append_c(ctx->node_path, '.');
	str_append(ctx->node_path, node->name);

	ctx->list.name = str_c(ctx->node_path);
	ctx->list.flags = node->flags;
	return &ctx->list;
}
