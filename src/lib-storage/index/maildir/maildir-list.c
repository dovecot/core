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

struct maildir_list_context {
	struct mailbox_list_context mailbox_ctx;
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
			node->flags &= ~MAILBOX_NOCHILDREN;
			maildir_nodes_fix(node->children, is_subs);
		} else if ((node->flags & MAILBOX_PLACEHOLDER) != 0) {
			if (!is_subs) {
				node->flags &= ~MAILBOX_PLACEHOLDER;
				node->flags |= MAILBOX_NOSELECT;
			}
		}
		node = node->next;
	}
}

static int maildir_fill_readdir(struct maildir_list_context *ctx,
				struct imap_match_glob *glob, int update_only)
{
	DIR *dirp;
	struct dirent *d;
	const char *path, *p, *mailbox_c;
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
		node->flags |= MAILBOX_FLAG_MATCHED | MAILBOX_NOCHILDREN;
		node->flags &= ~(MAILBOX_PLACEHOLDER | MAILBOX_NONEXISTENT);
	}

	mailbox = t_str_new(PATH_MAX);
	while ((d = readdir(dirp)) != NULL) {
		const char *fname = d->d_name;

		if (fname[0] != MAILDIR_FS_SEP)
			continue;

		/* skip . and .. */
		if (fname[0] == '.' &&
		    (fname[1] == '\0' || (fname[1] == '.' && fname[2] == '\0')))
			continue;

		/* FIXME: kludges. these files must be renamed later */
		if (strcmp(fname, ".customflags") == 0 ||
		    strcmp(fname, ".subscriptions") == 0)
			continue;

		if (fname[1] == MAILDIR_FS_SEP) {
			/* this mailbox is in the middle of being deleted,
			   or the process trying to delete it had died.

			   delete it ourself if it's been there longer than
			   one hour. don't touch it if it's outside our
			   mail root dir. */
			struct stat st;

			t_push();
			path = t_strdup_printf("%s/%s", ctx->dir, fname);
			if (stat(path, &st) == 0 &&
			    st.st_mtime < ioloop_time - 3600)
				(void)unlink_directory(path, TRUE);
			t_pop();
			continue;
		}
		fname++;

		/* make sure the mask matches */
		str_truncate(mailbox, 0);
		str_append(mailbox, ctx->prefix);
		str_append(mailbox, fname);
                mailbox_c = str_c(mailbox);

		match = imap_match(glob, mailbox_c);

		if (match != IMAP_MATCH_YES &&
		    match != IMAP_MATCH_PARENT)
			continue;

		if (strcasecmp(fname, "INBOX") == 0)
			continue; /* ignore inboxes */

		if (match == IMAP_MATCH_PARENT) {
			t_push();
			while ((p = strrchr(mailbox_c,
					    MAILDIR_FS_SEP)) != NULL) {
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
					node->flags = MAILBOX_PLACEHOLDER;

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

static int maildir_fill_subscribed(struct maildir_list_context *ctx,
				   struct imap_match_glob *glob)
{
	struct index_storage *istorage = (struct index_storage *)ctx->storage;
	struct subsfile_list_context *subsfile_ctx;
	const char *path, *name, *p;
	struct mailbox_node *node;
	int created;

	path = t_strconcat(istorage->control_dir != NULL ?
			   istorage->control_dir : istorage->dir,
			   "/" SUBSCRIPTION_FILE_NAME, NULL);
	subsfile_ctx = subsfile_list_init(ctx->storage, path);
	if (subsfile_ctx == NULL)
		return FALSE;

	while ((name = subsfile_list_next(subsfile_ctx)) != NULL) {
		switch (imap_match(glob, name)) {
		case IMAP_MATCH_YES:
			node = mailbox_tree_get(ctx->tree_ctx, name, NULL);
			node->flags = MAILBOX_FLAG_MATCHED;
			if ((ctx->flags & MAILBOX_LIST_FAST_FLAGS) == 0) {
				if (strcasecmp(name, "INBOX") != 0)
					node->flags |= MAILBOX_NONEXISTENT;
				node->flags |= MAILBOX_NOCHILDREN;
			}
			break;
		case IMAP_MATCH_PARENT:
			/* placeholder */
			while ((p = strrchr(name, MAILDIR_FS_SEP)) != NULL) {
				name = t_strdup_until(name, p);
				if (imap_match(glob, name) > 0)
					break;
			}
			i_assert(p != NULL);

			node = mailbox_tree_get(ctx->tree_ctx, name, &created);
			if (created) node->flags = MAILBOX_PLACEHOLDER;
			node->flags |= MAILBOX_FLAG_MATCHED | MAILBOX_CHILDREN;
			node->flags &= ~MAILBOX_NOCHILDREN;
			break;
		default:
			break;
		}
	}

	return subsfile_list_deinit(subsfile_ctx) == 0;

}

struct mailbox_list_context *
maildir_mailbox_list_init(struct mail_storage *storage,
			  const char *mask, enum mailbox_list_flags flags)
{
	struct index_storage *istorage = (struct index_storage *)storage;
        struct maildir_list_context *ctx;
        struct imap_match_glob *glob;
	const char *dir, *p;
	pool_t pool;

	mail_storage_clear_error(storage);

	pool = pool_alloconly_create("maildir_list", 1024);
	ctx = p_new(pool, struct maildir_list_context, 1);
	ctx->pool = pool;
	ctx->storage = storage;
	ctx->flags = flags;
	ctx->tree_ctx = mailbox_tree_init(MAILDIR_FS_SEP);

	if (storage->hierarchy_sep != MAILDIR_FS_SEP &&
	    strchr(mask, MAILDIR_FS_SEP) != NULL) {
		/* this will never match, return nothing */
		return &ctx->mailbox_ctx;
	}

	mask = maildir_fix_mailbox_name(istorage, mask, FALSE);
	glob = imap_match_init(pool, mask, TRUE, MAILDIR_FS_SEP);

	ctx->dir = istorage->dir;
	ctx->prefix = storage->namespace == NULL ? "" :
		maildir_fix_mailbox_name(istorage, storage->namespace, FALSE);

	if ((flags & MAILBOX_LIST_SUBSCRIBED) != 0) {
		if (!maildir_fill_subscribed(ctx, glob)) {
                        mailbox_tree_deinit(ctx->tree_ctx);
			pool_unref(pool);
			return NULL;
		}
	} else if (full_filesystem_access && (p = strrchr(mask, '/')) != NULL) {
		dir = t_strdup_until(mask, p);
		ctx->prefix = t_strconcat(ctx->prefix,
					  t_strdup_until(mask, p+1), NULL);

		if (*mask != '/' && *mask != '~')
			dir = t_strconcat(istorage->dir, "/", dir, NULL);
		ctx->dir = p_strdup(pool, home_expand(dir));
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

	ctx->prefix = p_strdup(pool, ctx->prefix);
	ctx->node_path = str_new(pool, 256);
	ctx->root = mailbox_tree_get(ctx->tree_ctx, NULL, NULL);
	ctx->mailbox_ctx.storage = storage;
	return &ctx->mailbox_ctx;
}

int maildir_mailbox_list_deinit(struct mailbox_list_context *_ctx)
{
	struct maildir_list_context *ctx = (struct maildir_list_context *)_ctx;

	mailbox_tree_deinit(ctx->tree_ctx);
	pool_unref(ctx->pool);
	return TRUE;
}

static struct mailbox_node *find_next(struct mailbox_node **node,
				      string_t *path, char hierarchy_sep)
{
	struct mailbox_node *child;
	size_t len;

	while (*node != NULL) {
		if (((*node)->flags & MAILBOX_FLAG_MATCHED) != 0)
			return *node;

		if ((*node)->children != NULL) {
			len = str_len(path);
			if (len != 0)
				str_append_c(path, hierarchy_sep);
			str_append(path, (*node)->name);

			child = find_next(&(*node)->children, path,
					  hierarchy_sep);
			if (child != NULL)
				return child;

			str_truncate(path, len);
		}

		*node = (*node)->next;
	}

	return NULL;
}

struct mailbox_list *
maildir_mailbox_list_next(struct mailbox_list_context *_ctx)
{
	struct maildir_list_context *ctx = (struct maildir_list_context *)_ctx;
	struct mailbox_node *node;

	for (node = ctx->next_node; node != NULL; node = node->next) {
		if ((node->flags & MAILBOX_FLAG_MATCHED) != 0)
			break;
	}

	if (node == NULL) {
		if (ctx->root == NULL)
			return NULL;

		str_truncate(ctx->node_path, 0);
		node = find_next(&ctx->root, ctx->node_path,
				 ctx->storage->hierarchy_sep);
                ctx->parent_pos = str_len(ctx->node_path);

		if (node == NULL)
			return NULL;
	}
	ctx->next_node = node->next;

	i_assert((node->flags & MAILBOX_FLAG_MATCHED) != 0);
	node->flags &= ~MAILBOX_FLAG_MATCHED;

	str_truncate(ctx->node_path, ctx->parent_pos);
	if (ctx->parent_pos != 0)
		str_append_c(ctx->node_path, ctx->storage->hierarchy_sep);
	str_append(ctx->node_path, node->name);

	ctx->list.name = str_c(ctx->node_path);
	ctx->list.flags = node->flags;
	return &ctx->list;
}
