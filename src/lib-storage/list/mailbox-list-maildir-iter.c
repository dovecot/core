/* Copyright (c) 2002-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "ioloop.h"
#include "unlink-directory.h"
#include "imap-match.h"
#include "mailbox-tree.h"
#include "mailbox-list-delete.h"
#include "mailbox-list-subscriptions.h"
#include "mailbox-list-maildir.h"

#include <dirent.h>
#include <sys/stat.h>

struct maildir_list_iterate_context {
	struct mailbox_list_iterate_context ctx;
	pool_t pool;

	const char *dir;
	char prefix_char;

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

static void
maildir_fill_parents(struct maildir_list_iterate_context *ctx,
		     struct imap_match_glob *glob, bool update_only,
		     string_t *mailbox)
{
	struct mail_namespace *ns = ctx->ctx.list->ns;
	struct mailbox_node *node;
	const char *p, *mailbox_c;
	bool created;

	mailbox_c = str_c(mailbox);
	while ((p = strrchr(mailbox_c, ns->sep)) != NULL) {
		str_truncate(mailbox, (size_t) (p-mailbox_c));
		mailbox_c = str_c(mailbox);
		if (imap_match(glob, mailbox_c) != IMAP_MATCH_YES)
			continue;

		if (ns->prefix_len > 0 && str_len(mailbox) == ns->prefix_len-1 &&
		    strncmp(mailbox_c, ns->prefix, ns->prefix_len - 1) == 0 &&
		    mailbox_c[ns->prefix_len-1] == ns->sep) {
			/* don't return matches to namespace prefix itself */
			continue;
		}

		created = FALSE;
		node = update_only ?
			mailbox_tree_lookup(ctx->tree_ctx, mailbox_c) :
			mailbox_tree_get(ctx->tree_ctx, mailbox_c, &created);
		if (node != NULL) {
			if (created) {
				/* we haven't yet seen this mailbox,
				   but we might see it later */
				node->flags = MAILBOX_NONEXISTENT;
			}
			if (!update_only)
				node->flags |= MAILBOX_MATCHED;
			node->flags |= MAILBOX_CHILDREN;
			node->flags &= ~MAILBOX_NOCHILDREN;
			node_fix_parents(node);
		}
	}
}

static void maildir_set_children(struct maildir_list_iterate_context *ctx,
				 string_t *mailbox)
{
	struct mailbox_node *node;
	const char *p, *mailbox_c;
	char hierarchy_sep;

	hierarchy_sep = ctx->ctx.list->ns->sep;

	/* mark the first existing parent as containing children */
	mailbox_c = str_c(mailbox);
	while ((p = strrchr(mailbox_c, hierarchy_sep)) != NULL) {
		str_truncate(mailbox, (size_t) (p-mailbox_c));
		mailbox_c = str_c(mailbox);

		node = mailbox_tree_lookup(ctx->tree_ctx, mailbox_c);
		if (node != NULL) {
			node->flags &= ~MAILBOX_NOCHILDREN;
			node->flags |= MAILBOX_CHILDREN;
			break;
		}
	}
}

static int
maildir_fill_inbox(struct maildir_list_iterate_context *ctx,
		   struct imap_match_glob *glob, const char *inbox_name,
		   bool update_only)
{
	struct mailbox_node *node;
	enum mailbox_info_flags flags;
	enum imap_match_result match;
	bool created;
	int ret;

	if ((ctx->ctx.flags & MAILBOX_LIST_ITER_NO_AUTO_INBOX) == 0) {
		/* always show INBOX */
	} else {
		/* INBOX may be Maildir root or completely elsewhere.
		   show it only if it has already been created */
		ret = mailbox_list_mailbox(ctx->ctx.list, "INBOX", &flags);
		if (ret < 0)
			return -1;
		if ((flags & MAILBOX_NONEXISTENT) != 0)
			update_only = TRUE;
	}

	if (update_only) {
		node = mailbox_tree_lookup(ctx->tree_ctx, inbox_name);
		if (node != NULL)
			node->flags &= ~MAILBOX_NONEXISTENT;
	} else {
		node = mailbox_tree_get(ctx->tree_ctx, inbox_name, &created);
		if (created)
			node->flags = MAILBOX_NOCHILDREN;
		else
			node->flags &= ~MAILBOX_NONEXISTENT;

		match = imap_match(glob, inbox_name);
		if ((match & (IMAP_MATCH_YES | IMAP_MATCH_PARENT)) != 0)
			node->flags |= MAILBOX_MATCHED;
	}
	return 0;
}

static bool
maildir_get_type(const char *dir, const char *fname,
		 enum mailbox_list_file_type *type_r,
		 struct stat *st_r,
		 enum mailbox_info_flags *flags)
{
	const char *path;
	struct stat st;

	path = *fname == '\0' ? dir :
		t_strdup_printf("%s/%s", dir, fname);
	if (stat(path, &st) < 0) {
		if (errno == ENOENT) {
			/* just deleted? */
			*flags |= MAILBOX_NONEXISTENT;
		} else {
			*flags |= MAILBOX_NOSELECT;
		}
		return FALSE;
	}

	*st_r = st;
	if (S_ISDIR(st.st_mode)) {
		*type_r = MAILBOX_LIST_FILE_TYPE_DIR;
		return TRUE;
	} else {
		if (strncmp(fname, ".nfs", 4) == 0)
			*flags |= MAILBOX_NONEXISTENT;
		else
			*flags |= MAILBOX_NOSELECT;
		return FALSE;
	}
}

int maildir_list_get_mailbox_flags(struct mailbox_list *list,
				   const char *dir, const char *fname,
				   enum mailbox_list_file_type type,
				   struct stat *st_r,
				   enum mailbox_info_flags *flags_r)
{
	memset(st_r, 0, sizeof(*st_r));
	*flags_r = 0;

	switch (type) {
	case MAILBOX_LIST_FILE_TYPE_DIR:
	case MAILBOX_LIST_FILE_TYPE_FILE:
	case MAILBOX_LIST_FILE_TYPE_OTHER:
		break;
	case MAILBOX_LIST_FILE_TYPE_UNKNOWN:
	case MAILBOX_LIST_FILE_TYPE_SYMLINK:
		/* need to check with stat() to be sure */
		if (!list->mail_set->maildir_stat_dirs && *fname != '\0' &&
		    strcmp(list->name, MAILBOX_LIST_NAME_MAILDIRPLUSPLUS) == 0 &&
		    strncmp(fname, ".nfs", 4) != 0) {
			/* just assume it's a valid mailbox */
			return 1;
		}

		if (!maildir_get_type(dir, fname, &type, st_r, flags_r))
			return 0;
		break;
	}

	switch (type) {
	case MAILBOX_LIST_FILE_TYPE_DIR:
		if ((list->flags & MAILBOX_LIST_FLAG_MAILBOX_FILES) != 0) {
			*flags_r |= MAILBOX_NOSELECT;
			return 0;
		}
		break;
	case MAILBOX_LIST_FILE_TYPE_FILE:
		if ((list->flags & MAILBOX_LIST_FLAG_MAILBOX_FILES) == 0) {
			*flags_r |= MAILBOX_NOSELECT;
			return 0;
		}
		break;
	case MAILBOX_LIST_FILE_TYPE_OTHER:
		*flags_r |= MAILBOX_NOSELECT;
		return 0;

	case MAILBOX_LIST_FILE_TYPE_UNKNOWN:
	case MAILBOX_LIST_FILE_TYPE_SYMLINK:
		i_unreached();
	}
	if (*fname != '\0') {
		/* this tells maildir storage code that it doesn't need to
		   see if cur/ exists, because just the existence of .dir/
		   assumes that the mailbox exists. */
		*flags_r |= MAILBOX_SELECT;
	}
	return 1;
}

static bool maildir_delete_trash_dir(struct maildir_list_iterate_context *ctx,
				     const char *fname)
{
	const char *path;
	struct stat st;

	if (fname[1] != ctx->prefix_char || ctx->prefix_char == '\0' ||
	    strcmp(fname+2, MAILBOX_LIST_MAILDIR_TRASH_DIR_NAME) != 0)
		return FALSE;

	/* this directory is in the middle of being deleted, or the process
	   trying to delete it had died. delete it ourself if it's been there
	   longer than one hour. */
	path = t_strdup_printf("%s/%s", ctx->dir, fname);
	if (stat(path, &st) == 0 &&
	    st.st_mtime < ioloop_time - 3600)
		(void)mailbox_list_delete_trash(path);

	return TRUE;
}

static int
maildir_fill_readdir(struct maildir_list_iterate_context *ctx,
		     struct imap_match_glob *glob, bool update_only)
{
	struct mailbox_list *list = ctx->ctx.list;
	struct mail_namespace *ns = list->ns;
	DIR *dirp;
	struct dirent *d;
	const char *mailbox_name;
	string_t *mailbox;
	enum mailbox_info_flags flags;
	enum imap_match_result match;
	struct mailbox_node *node;
	bool created;
	struct stat st;
	int ret;

	dirp = opendir(ctx->dir);
	if (dirp == NULL) {
		if (errno == EACCES) {
			mailbox_list_set_critical(list, "%s",
				mail_error_eacces_msg("opendir", ctx->dir));
		} else if (errno != ENOENT) {
			mailbox_list_set_critical(list,
				"opendir(%s) failed: %m", ctx->dir);
			return -1;
		}
		return 0;
	}

	mailbox = t_str_new(MAILBOX_LIST_NAME_MAX_LENGTH);
	while ((d = readdir(dirp)) != NULL) {
		const char *fname = d->d_name;

		if (fname[0] == ctx->prefix_char)
			mailbox_name = fname + 1;
		else {
			if (ctx->prefix_char != '\0' || fname[0] == '.')
				continue;
			mailbox_name = fname;
		}

		/* skip . and .. */
		if (fname[0] == '.' &&
		    (fname[1] == '\0' || (fname[1] == '.' && fname[2] == '\0')))
			continue;

		mailbox_name = mail_namespace_get_vname(ns, mailbox,
							mailbox_name);

		/* make sure the pattern matches */
		match = imap_match(glob, mailbox_name);
		if ((match & (IMAP_MATCH_YES | IMAP_MATCH_PARENT)) == 0)
			continue;

		/* check if this is an actual mailbox */
		if (maildir_delete_trash_dir(ctx, fname))
			continue;

		T_BEGIN {
			ret = list->v.get_mailbox_flags(list, ctx->dir, fname,
				mailbox_list_get_file_type(d), &st, &flags);
		} T_END;
		if (ret <= 0) {
			if (ret < 0)
				return -1;
			continue;
		}

		/* we know the children flags ourself, so ignore if any of
		   them were set. */
		flags &= ~(MAILBOX_NOINFERIORS |
			   MAILBOX_CHILDREN | MAILBOX_NOCHILDREN);

		if ((match & IMAP_MATCH_PARENT) != 0) {
			T_BEGIN {
				maildir_fill_parents(ctx, glob, update_only,
						     mailbox);
			} T_END;
		} else {
			created = FALSE;
			node = update_only ?
				mailbox_tree_lookup(ctx->tree_ctx,
						    mailbox_name) :
				mailbox_tree_get(ctx->tree_ctx,
						 mailbox_name, &created);

			if (node != NULL) {
				if (created)
					node->flags = MAILBOX_NOCHILDREN;
				else
					node->flags &= ~MAILBOX_NONEXISTENT;
				if (!update_only)
					node->flags |= MAILBOX_MATCHED;
				node->flags |= flags;
				node_fix_parents(node);
			} else {
				i_assert(update_only);
				maildir_set_children(ctx, mailbox);
			}
		}
	}

	if (closedir(dirp) < 0) {
		mailbox_list_set_critical(list, "readdir(%s) failed: %m",
					  ctx->dir);
		return -1;
	}

	if ((ns->flags & NAMESPACE_FLAG_INBOX_USER) != 0) {
		/* make sure INBOX is listed */
		return maildir_fill_inbox(ctx, glob, "INBOX", update_only);
	} else if ((ns->flags & NAMESPACE_FLAG_INBOX_ANY) != 0) {
		/* show shared INBOX. */
		return maildir_fill_inbox(ctx, glob,
			t_strconcat(ns->prefix, "INBOX", NULL), update_only);
	} else {
		return 0;
	}
}

static int
maildir_fill_other_ns_subscriptions(struct maildir_list_iterate_context *ctx,
				    struct mail_namespace *ns)
{
	struct mailbox_list_iterate_context *iter;
	const struct mailbox_info *info;
	struct mailbox_node *node;

	iter = mailbox_list_iter_init(ns->list, "*",
				      MAILBOX_LIST_ITER_RETURN_CHILDREN);
	while ((info = mailbox_list_iter_next(iter)) != NULL) {
		node = mailbox_tree_lookup(ctx->tree_ctx, info->name);
		if (node != NULL) {
			node->flags &= ~MAILBOX_NONEXISTENT;
			node->flags |= info->flags;
		}
	}
	if (mailbox_list_iter_deinit(&iter) < 0) {
		enum mail_error error;
		const char *errstr;

		errstr = mailbox_list_get_last_error(ns->list, &error);
		mailbox_list_set_error(ctx->ctx.list, error, errstr);
		return -1;
	}
	return 0;
}

static int
maildir_fill_other_subscriptions(struct maildir_list_iterate_context *ctx)
{
	struct mail_namespace *ns;
	const char *path;

	ns = ctx->ctx.list->ns->user->namespaces;
	for (; ns != NULL; ns = ns->next) {
		if ((ns->flags & NAMESPACE_FLAG_SUBSCRIPTIONS) != 0 ||
		    ns->prefix_len == 0)
			continue;

		path = t_strndup(ns->prefix, ns->prefix_len-1);
		if (mailbox_tree_lookup(ctx->tree_ctx, path) != NULL) {
			if (maildir_fill_other_ns_subscriptions(ctx, ns) < 0)
				return -1;
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
	int ret;

	pool = pool_alloconly_create("maildir_list", 1024);
	ctx = p_new(pool, struct maildir_list_iterate_context, 1);
	ctx->ctx.list = _list;
	ctx->ctx.flags = flags;
	ctx->pool = pool;
	ctx->tree_ctx = mailbox_tree_init(_list->ns->sep);
	ctx->info.ns = _list->ns;
	ctx->prefix_char = strcmp(_list->name, MAILBOX_LIST_NAME_IMAPDIR) == 0 ?
		'\0' : _list->hierarchy_sep;

	glob = imap_match_init_multiple(pool, patterns, TRUE, _list->ns->sep);

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

		T_BEGIN {
			ret = maildir_fill_readdir(ctx, glob, update_only);
		} T_END;
		if (ret < 0) {
			ctx->ctx.failed = TRUE;
			return &ctx->ctx;
		}
	}

	if ((flags & MAILBOX_LIST_ITER_SELECT_SUBSCRIBED) != 0 &&
	    (flags & MAILBOX_LIST_ITER_RETURN_NO_FLAGS) == 0) {
		/* if there are subscriptions=no namespaces, we may have some
		   of their subscriptions whose flags need to be filled */
		ret = maildir_fill_other_subscriptions(ctx);
		if (ret < 0) {
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
	pool_unref(&ctx->pool);
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
