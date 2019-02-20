/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "ioloop.h"
#include "unlink-directory.h"
#include "unichar.h"
#include "imap-match.h"
#include "imap-utf7.h"
#include "mailbox-tree.h"
#include "mailbox-list-delete.h"
#include "mailbox-list-subscriptions.h"
#include "mailbox-list-maildir.h"

#include <stdio.h>
#include <dirent.h>
#include <sys/stat.h>

struct maildir_list_iterate_context {
	struct mailbox_list_iterate_context ctx;

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
		     const char *vname)
{
	struct mail_namespace *ns = ctx->ctx.list->ns;
	struct mailbox_node *node;
	const char *p;
	size_t vname_len = strlen(vname);
	bool created;
	char ns_sep = mail_namespace_get_sep(ns);

	while ((p = strrchr(vname, ns_sep)) != NULL) {
		vname = t_strdup_until(vname, p);
		if (imap_match(glob, vname) != IMAP_MATCH_YES)
			continue;

		if (ns->prefix_len > 0 && vname_len == ns->prefix_len-1 &&
		    strncmp(vname, ns->prefix, ns->prefix_len - 1) == 0 &&
		    vname[ns->prefix_len-1] == ns_sep) {
			/* don't return matches to namespace prefix itself */
			continue;
		}

		created = FALSE;
		node = update_only ?
			mailbox_tree_lookup(ctx->tree_ctx, vname) :
			mailbox_tree_get(ctx->tree_ctx, vname, &created);
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
				 const char *vname)
{
	struct mailbox_node *node;
	const char *p;
	char hierarchy_sep;

	hierarchy_sep = mail_namespace_get_sep(ctx->ctx.list->ns);

	/* mark the first existing parent as containing children */
	while ((p = strrchr(vname, hierarchy_sep)) != NULL) {
		vname = t_strdup_until(vname, p);

		node = mailbox_tree_lookup(ctx->tree_ctx, vname);
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

	if ((ctx->ctx.flags & MAILBOX_LIST_ITER_NO_AUTO_BOXES) == 0) {
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
		return 0;
	}

	/* add the INBOX only if it matches the patterns */
	match = imap_match(glob, inbox_name);
	if (match == IMAP_MATCH_PARENT)
		maildir_fill_parents(ctx, glob, FALSE, inbox_name);
	else if (match == IMAP_MATCH_YES) {
		node = mailbox_tree_get(ctx->tree_ctx, inbox_name, &created);
		if (created)
			node->flags = MAILBOX_NOCHILDREN;
		else
			node->flags &= ~MAILBOX_NONEXISTENT;
		node->flags |= MAILBOX_MATCHED;
	}
	return 0;
}

static bool
maildir_get_type(const char *dir, const char *fname,
		 enum mailbox_list_file_type *type_r,
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

	if (S_ISDIR(st.st_mode)) {
		*type_r = MAILBOX_LIST_FILE_TYPE_DIR;
		return TRUE;
	} else {
		if (str_begins(fname, ".nfs"))
			*flags |= MAILBOX_NONEXISTENT;
		else
			*flags |= MAILBOX_NOSELECT;
		return FALSE;
	}
}

int maildir_list_get_mailbox_flags(struct mailbox_list *list,
				   const char *dir, const char *fname,
				   enum mailbox_list_file_type type,
				   enum mailbox_info_flags *flags_r)
{
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
		    !str_begins(fname, ".nfs")) {
			/* just assume it's a valid mailbox */
			return 1;
		}

		if (!maildir_get_type(dir, fname, &type, flags_r))
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
	const char *path, *error;
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
		(void)mailbox_list_delete_trash(path, &error);

	return TRUE;
}

static int
maildir_fill_readdir_entry(struct maildir_list_iterate_context *ctx,
			   struct imap_match_glob *glob, const struct dirent *d,
			   bool update_only)
{
	struct mailbox_list *list = ctx->ctx.list;
	const char *fname, *storage_name, *vname;
	enum mailbox_info_flags flags;
	enum imap_match_result match;
	struct mailbox_node *node;
	bool created;
	int ret;

	fname = d->d_name;
	if (fname[0] == ctx->prefix_char)
		storage_name = fname + 1;
	else {
		if (ctx->prefix_char != '\0' || fname[0] == '.')
			return 0;
		storage_name = fname;
	}

	/* skip . and .. */
	if (fname[0] == '.' &&
	    (fname[1] == '\0' || (fname[1] == '.' && fname[2] == '\0')))
		return 0;

	vname = mailbox_list_get_vname(list, storage_name);
	if (!uni_utf8_str_is_valid(vname)) {
		/* the storage_name is completely invalid, rename it to
		   something more sensible. we could do this for all names that
		   aren't valid mUTF-7, but that might lead to accidents in
		   future when UTF-8 storage names are used */
		const char *src = t_strdup_printf("%s/%s", ctx->dir, fname);
		string_t *destvname = t_str_new(128);
		string_t *dest = t_str_new(128);

		if (uni_utf8_get_valid_data((const void *)fname,
					    strlen(fname), destvname))
			i_unreached(); /* already checked that it was invalid */

		str_append(dest, ctx->dir);
		str_append_c(dest, '/');
		(void)imap_utf8_to_utf7(str_c(destvname), dest);

		if (rename(src, str_c(dest)) < 0 && errno != ENOENT)
			i_error("rename(%s, %s) failed: %m", src, str_c(dest));
		/* just skip this in this iteration, we'll see it on the
		   next list */
		return 0;
	}

	/* make sure the pattern matches */
	match = imap_match(glob, vname);
	if ((match & (IMAP_MATCH_YES | IMAP_MATCH_PARENT)) == 0)
		return 0;

	/* check if this is an actual mailbox */
	if (maildir_delete_trash_dir(ctx, fname))
		return 0;

	if ((ctx->ctx.flags & MAILBOX_LIST_ITER_SKIP_ALIASES) != 0) {
		ret = mailbox_list_dirent_is_alias_symlink(list, ctx->dir, d);
		if (ret != 0)
			return ret < 0 ? -1 : 0;
	}
	T_BEGIN {
		ret = list->v.get_mailbox_flags(list, ctx->dir, fname,
				mailbox_list_get_file_type(d), &flags);
	} T_END;
	if (ret <= 0)
		return ret;

	/* we know the children flags ourself, so ignore if any of
	   them were set. */
	flags &= ~(MAILBOX_NOINFERIORS | MAILBOX_CHILDREN | MAILBOX_NOCHILDREN);

	if ((match & IMAP_MATCH_PARENT) != 0)
		maildir_fill_parents(ctx, glob, update_only, vname);
	else {
		created = FALSE;
		node = update_only ?
			mailbox_tree_lookup(ctx->tree_ctx, vname) :
			mailbox_tree_get(ctx->tree_ctx, vname, &created);

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
			maildir_set_children(ctx, vname);
		}
	}
	return 0;
}

static int
maildir_fill_readdir(struct maildir_list_iterate_context *ctx,
		     struct imap_match_glob *glob, bool update_only)
{
	struct mailbox_list *list = ctx->ctx.list;
	struct mail_namespace *ns = list->ns;
	DIR *dirp;
	struct dirent *d;
	const char *vname;
	int ret = 0;

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

	while ((d = readdir(dirp)) != NULL) {
		T_BEGIN {
			ret = maildir_fill_readdir_entry(ctx, glob, d,
							 update_only);
		} T_END;
		if (ret < 0)
			break;
	}

	if (closedir(dirp) < 0) {
		mailbox_list_set_critical(list, "readdir(%s) failed: %m",
					  ctx->dir);
		return -1;
	}
	if (ret < 0)
		return -1;

	if ((ns->flags & NAMESPACE_FLAG_INBOX_USER) != 0) {
		/* make sure INBOX is listed */
		return maildir_fill_inbox(ctx, glob, "INBOX", update_only);
	} else if ((ns->flags & NAMESPACE_FLAG_INBOX_ANY) != 0) {
		/* show shared INBOX. */
		vname = mailbox_list_get_vname(ns->list, "INBOX");
		return maildir_fill_inbox(ctx, glob, vname, update_only);
	} else {
		return 0;
	}
}

struct mailbox_list_iterate_context *
maildir_list_iter_init(struct mailbox_list *_list, const char *const *patterns,
		       enum mailbox_list_iter_flags flags)
{
	struct maildir_mailbox_list *list =
		(struct maildir_mailbox_list *)_list;
	struct maildir_list_iterate_context *ctx;
	pool_t pool;
	char ns_sep = mail_namespace_get_sep(_list->ns);
	int ret;

	pool = pool_alloconly_create("mailbox list maildir iter", 1024);
	ctx = p_new(pool, struct maildir_list_iterate_context, 1);
	ctx->ctx.pool = pool;
	ctx->ctx.list = _list;
	ctx->ctx.flags = flags;
	ctx->ctx.glob = imap_match_init_multiple(pool, patterns, TRUE, ns_sep);
	array_create(&ctx->ctx.module_contexts, pool, sizeof(void *), 5);

	ctx->tree_ctx = mailbox_tree_init(ns_sep);
	ctx->info.ns = _list->ns;
	ctx->prefix_char = strcmp(_list->name, MAILBOX_LIST_NAME_IMAPDIR) == 0 ?
		'\0' : list->sep;

	if (_list->set.iter_from_index_dir)
		ctx->dir = _list->set.index_dir;
	else
		ctx->dir = _list->set.root_dir;

	if ((flags & MAILBOX_LIST_ITER_SELECT_SUBSCRIBED) != 0) {
		/* Listing only subscribed mailboxes.
		   Flags are set later if needed. */
		bool default_nonexistent =
			(flags & MAILBOX_LIST_ITER_RETURN_NO_FLAGS) == 0;

		mailbox_list_subscriptions_fill(&ctx->ctx, ctx->tree_ctx,
						default_nonexistent);
	}

	if ((flags & MAILBOX_LIST_ITER_SELECT_SUBSCRIBED) == 0 ||
	    (flags & MAILBOX_LIST_ITER_RETURN_NO_FLAGS) == 0) {
		/* Add/update mailbox list with flags */
		bool update_only =
			(flags & MAILBOX_LIST_ITER_SELECT_SUBSCRIBED) != 0;

		T_BEGIN {
			ret = maildir_fill_readdir(ctx, ctx->ctx.glob,
						   update_only);
		} T_END;
		if (ret < 0) {
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
	int ret = _ctx->failed ? -1 : 0;

	if (ctx->tree_iter != NULL)
		mailbox_tree_iterate_deinit(&ctx->tree_iter);
	mailbox_tree_deinit(&ctx->tree_ctx);
	pool_unref(&ctx->ctx.pool);
	return ret;
}

const struct mailbox_info *
maildir_list_iter_next(struct mailbox_list_iterate_context *_ctx)
{
	struct maildir_list_iterate_context *ctx =
		(struct maildir_list_iterate_context *)_ctx;
	struct mailbox_node *node;

	if (_ctx->failed)
		return NULL;

	node = mailbox_tree_iterate_next(ctx->tree_iter, &ctx->info.vname);
	if (node == NULL)
		return mailbox_list_iter_default_next(_ctx);

	ctx->info.flags = node->flags;
	if (strcmp(ctx->info.vname, "INBOX") == 0 &&
	    mail_namespace_is_inbox_noinferiors(ctx->info.ns)) {
		i_assert((ctx->info.flags & MAILBOX_NOCHILDREN) != 0);
		ctx->info.flags &= ~MAILBOX_NOCHILDREN;
		ctx->info.flags |= MAILBOX_NOINFERIORS;
	}
	if ((_ctx->flags & MAILBOX_LIST_ITER_RETURN_SUBSCRIBED) != 0 &&
	    (_ctx->flags & MAILBOX_LIST_ITER_SELECT_SUBSCRIBED) == 0) {
		/* we're listing all mailboxes but we want to know
		   \Subscribed flags */
		mailbox_list_set_subscription_flags(_ctx->list, ctx->info.vname,
						    &ctx->info.flags);
	}
	return &ctx->info;
}
