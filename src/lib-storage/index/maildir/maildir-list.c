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

#include <stdlib.h>
#include <dirent.h>
#include <sys/stat.h>

#define MAILBOX_FLAG_MATCHED 0x40000000

struct maildir_list_context {
	struct mailbox_list_context mailbox_ctx;
	pool_t pool;

	const char *dir, *prefix;

        struct mailbox_tree_context *tree_ctx;

	string_t *node_path;
	size_t parent_pos;
	struct mailbox_node *root, *next_node;
	struct mailbox_list list;
};

static void maildir_nodes_fix(struct mailbox_node *node, bool is_subs)
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

static bool
maildir_fill_readdir(struct maildir_list_context *ctx,
		     struct imap_match_glob *glob, bool update_only)
{
	DIR *dirp;
	struct dirent *d;
	struct stat st;
	const char *path, *p, *mailbox_c;
	string_t *mailbox;
	enum imap_match_result match;
	struct mailbox_node *node;
	bool stat_dirs, created, hide;

	dirp = opendir(ctx->dir);
	if (dirp == NULL) {
		if (errno != ENOENT) {
			mail_storage_set_critical(ctx->mailbox_ctx.storage,
				"opendir(%s) failed: %m", ctx->dir);
			return FALSE;
		}
		return TRUE;
	}

	stat_dirs = getenv("MAILDIR_STAT_DIRS") != NULL;

	t_push();
	mailbox = t_str_new(PATH_MAX);
	while ((d = readdir(dirp)) != NULL) {
		const char *fname = d->d_name;

		if (fname[0] != MAILDIR_FS_SEP)
			continue;

		/* skip . and .. */
		if (fname[0] == '.' &&
		    (fname[1] == '\0' || (fname[1] == '.' && fname[2] == '\0')))
			continue;

#ifdef HAVE_DIRENT_D_TYPE
		/* check the type always since there's no extra cost */
		if (d->d_type == DT_DIR)
			;
		else if (d->d_type != DT_UNKNOWN && d->d_type != DT_LNK)
			continue;
		else if (d->d_type == DT_LNK && !stat_dirs)
			;
		else
#endif
		if (stat_dirs) {
			t_push();
			path = t_strdup_printf("%s/%s", ctx->dir, fname);
			hide = stat(path, &st) < 0 || !S_ISDIR(st.st_mode);
			t_pop();
			if (hide)
				continue;
		}

		if (fname[1] == MAILDIR_FS_SEP &&
		    strcmp(fname+1, MAILDIR_UNLINK_DIRNAME) == 0) {
			/* this directory is in the middle of being deleted,
			   or the process trying to delete it had died.
			   delete it ourself if it's been there longer than
			   one hour. */
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
	t_pop();

	if (closedir(dirp) < 0) {
		mail_storage_set_critical(ctx->mailbox_ctx.storage,
					  "readdir(%s) failed: %m", ctx->dir);
		return FALSE;
	}

	if ((ctx->mailbox_ctx.flags &
	     (MAILBOX_LIST_SUBSCRIBED |
	      MAILBOX_LIST_INBOX)) == MAILBOX_LIST_INBOX) {
		/* make sure INBOX is there */
		node = mailbox_tree_get(ctx->tree_ctx, "INBOX", &created);
		if (created)
			node->flags = MAILBOX_NOCHILDREN;
		else
			node->flags &= ~MAILBOX_PLACEHOLDER;
	}
	maildir_nodes_fix(mailbox_tree_get(ctx->tree_ctx, NULL, NULL),
			  (ctx->mailbox_ctx.flags &
			   MAILBOX_LIST_SUBSCRIBED) != 0);
	return TRUE;
}

static bool maildir_fill_subscribed(struct maildir_list_context *ctx,
				    struct imap_match_glob *glob)
{
	struct maildir_storage *storage =
		(struct maildir_storage *)ctx->mailbox_ctx.storage;
	struct subsfile_list_context *subsfile_ctx;
	const char *path, *name, *p;
	struct mailbox_node *node;
	bool created;

	path = t_strconcat(storage->control_dir != NULL ?
			   storage->control_dir : INDEX_STORAGE(storage)->dir,
			   "/" SUBSCRIPTION_FILE_NAME, NULL);
	subsfile_ctx = subsfile_list_init(ctx->mailbox_ctx.storage, path);
	if (subsfile_ctx == NULL)
		return FALSE;

	while ((name = subsfile_list_next(subsfile_ctx)) != NULL) {
		switch (imap_match(glob, name)) {
		case IMAP_MATCH_YES:
			node = mailbox_tree_get(ctx->tree_ctx, name, NULL);
			node->flags = MAILBOX_FLAG_MATCHED;
			if ((ctx->mailbox_ctx.flags &
			     MAILBOX_LIST_FAST_FLAGS) == 0) {
				node->flags |= MAILBOX_NONEXISTENT |
					MAILBOX_NOCHILDREN;
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
			  const char *ref, const char *mask,
			  enum mailbox_list_flags flags)
{
	struct index_storage *istorage = (struct index_storage *)storage;
        struct maildir_list_context *ctx;
        struct imap_match_glob *glob;
	const char *dir, *p;
	pool_t pool;

	mail_storage_clear_error(storage);

	pool = pool_alloconly_create("maildir_list", 1024);
	ctx = p_new(pool, struct maildir_list_context, 1);
	ctx->mailbox_ctx.storage = storage;
	ctx->mailbox_ctx.flags = flags;
	ctx->pool = pool;
	ctx->tree_ctx = mailbox_tree_init(MAILDIR_FS_SEP);

	if (*ref != '\0') {
		/* join reference + mask */
		if (*mask == MAILDIR_FS_SEP &&
		    ref[strlen(ref)-1] == MAILDIR_FS_SEP) {
			/* A. .B -> A.B */
			mask++;
		} else if (*mask != MAILDIR_FS_SEP &&
			   ref[strlen(ref)-1] != MAILDIR_FS_SEP) {
			/* A B -> A.B */
			mask = t_strconcat(ref, MAILDIR_FS_SEP_S, mask, NULL);
		} else {
			mask = t_strconcat(ref, mask, NULL);
		}
	}

	glob = imap_match_init(pool, mask, TRUE, MAILDIR_FS_SEP);

	ctx->dir = istorage->dir;
	ctx->prefix = "";

	if ((flags & MAILBOX_LIST_SUBSCRIBED) != 0) {
		if (!maildir_fill_subscribed(ctx, glob)) {
			ctx->mailbox_ctx.failed = TRUE;
			return &ctx->mailbox_ctx;
		}
	} else if ((storage->flags & MAIL_STORAGE_FLAG_FULL_FS_ACCESS) != 0 &&
		   (p = strrchr(mask, '/')) != NULL) {
		dir = t_strdup_until(mask, p);
		ctx->prefix = p_strdup_until(pool, mask, p+1);

		if (*mask != '/' && *mask != '~')
			dir = t_strconcat(istorage->dir, "/", dir, NULL);
		ctx->dir = p_strdup(pool, home_expand(dir));
	}

	if ((flags & MAILBOX_LIST_SUBSCRIBED) == 0 ||
	    (ctx->mailbox_ctx.flags & MAILBOX_LIST_FAST_FLAGS) == 0) {
		bool update_only = (flags & MAILBOX_LIST_SUBSCRIBED) != 0;
		if (!maildir_fill_readdir(ctx, glob, update_only)) {
			ctx->mailbox_ctx.failed = TRUE;
			return &ctx->mailbox_ctx;
		}
	}

	ctx->node_path = str_new(pool, 256);
	ctx->root = mailbox_tree_get(ctx->tree_ctx, NULL, NULL);
	ctx->mailbox_ctx.storage = storage;
	return &ctx->mailbox_ctx;
}

int maildir_mailbox_list_deinit(struct mailbox_list_context *_ctx)
{
	struct maildir_list_context *ctx = (struct maildir_list_context *)_ctx;
	int ret = ctx->mailbox_ctx.failed ? -1 : 0;

	mailbox_tree_deinit(ctx->tree_ctx);
	pool_unref(ctx->pool);
	return ret;
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
				 ctx->mailbox_ctx.storage->hierarchy_sep);
                ctx->parent_pos = str_len(ctx->node_path);

		if (node == NULL)
			return NULL;
	}
	ctx->next_node = node->next;

	i_assert((node->flags & MAILBOX_FLAG_MATCHED) != 0);
	node->flags &= ~MAILBOX_FLAG_MATCHED;

	str_truncate(ctx->node_path, ctx->parent_pos);
	if (ctx->parent_pos != 0) {
		str_append_c(ctx->node_path,
			     ctx->mailbox_ctx.storage->hierarchy_sep);
	}
	str_append(ctx->node_path, node->name);

	ctx->list.name = str_c(ctx->node_path);
	ctx->list.flags = node->flags;
	return &ctx->list;
}
