/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "unichar.h"
#include "imap-match.h"
#include "imap-utf7.h"
#include "mail-storage.h"
#include "mailbox-tree.h"
#include "mailbox-list-subscriptions.h"
#include "mailbox-list-iter-private.h"
#include "mailbox-list-fs.h"

#include <stdio.h>
#include <ctype.h>
#include <dirent.h>
#include <sys/stat.h>

struct list_dir_entry {
	const char *fname;
	enum mailbox_info_flags info_flags;
};

struct list_dir_context {
	struct list_dir_context *parent;

	pool_t pool;
	const char *storage_name;
	/* this directory's info flags. */
	enum mailbox_info_flags info_flags;

	/* all files in this directory */
	ARRAY(struct list_dir_entry) entries;
	unsigned int entry_idx;
};

struct fs_list_iterate_context {
	struct mailbox_list_iterate_context ctx;

	const char *const *valid_patterns;
	/* roots can be either /foo, ~user/bar or baz */
	ARRAY(const char *) roots;
	unsigned int root_idx;
	char sep;

	pool_t info_pool;
	struct mailbox_info info;
	/* current directory we're handling */
	struct list_dir_context *dir;

	bool inbox_found:1;
	bool inbox_has_children:1;
	bool listed_prefix_inbox:1;
};

static int
fs_get_existence_info_flag(struct fs_list_iterate_context *ctx,
			   const char *vname,
			   enum mailbox_info_flags *info_flags)
{
	struct mailbox *box;
	enum mailbox_flags flags = 0;
	enum mailbox_existence existence;
	bool auto_boxes;
	int ret;

	if ((ctx->ctx.flags & MAILBOX_LIST_ITER_RAW_LIST) != 0)
		flags |= MAILBOX_FLAG_IGNORE_ACLS;
	auto_boxes = (ctx->ctx.flags & MAILBOX_LIST_ITER_NO_AUTO_BOXES) == 0;
	box = mailbox_alloc(ctx->ctx.list, vname, flags);
	ret = mailbox_exists(box, auto_boxes, &existence);
	mailbox_free(&box);

	if (ret < 0) {
		/* this can only be an internal error */
		mailbox_list_set_internal_error(ctx->ctx.list);
		return -1;
	}
	switch (existence) {
	case MAILBOX_EXISTENCE_NONE:
		/* We already found out that this mailbox exists. So this is
		   either a race condition or ACL plugin prevented access to
		   this. In any case treat this as a \NoSelect mailbox so that
		   we'll recurse into its potential children. This is
		   especially important if ACL disabled access to the parent
		   mailbox, but child mailboxes would be accessible. */
	case MAILBOX_EXISTENCE_NOSELECT:
		*info_flags |= MAILBOX_NOSELECT;
		break;
	case MAILBOX_EXISTENCE_SELECT:
		*info_flags |= MAILBOX_SELECT;
		break;
	}
	return 0;
}

static void
fs_list_rename_invalid(struct fs_list_iterate_context *ctx,
		       const char *storage_name)
{
	/* the storage_name is completely invalid, rename it to
	   something more sensible. we could do this for all names that
	   aren't valid mUTF-7, but that might lead to accidents in
	   future when UTF-8 storage names are used */
	string_t *destname = t_str_new(128);
	string_t *dest = t_str_new(128);
	const char *root, *src;

	root = mailbox_list_get_root_forced(ctx->ctx.list,
					  MAILBOX_LIST_PATH_TYPE_MAILBOX);
	src = t_strconcat(root, "/", storage_name, NULL);

	if (uni_utf8_get_valid_data((const void *)storage_name,
				    strlen(storage_name), destname))
		i_unreached(); /* already checked that it was invalid */

	str_append(dest, root);
	str_append_c(dest, '/');
	(void)imap_utf8_to_utf7(str_c(destname), dest);

	if (rename(src, str_c(dest)) < 0 && errno != ENOENT)
		i_error("rename(%s, %s) failed: %m", src, str_c(dest));
}

static const char *
dir_get_storage_name(struct list_dir_context *dir, const char *fname)
{
	if (*dir->storage_name == '\0') {
		/* regular root */
		return fname;
	} else if (strcmp(dir->storage_name, "/") == 0) {
		/* full_filesystem_access=yes "/" root */
		return t_strconcat("/", fname, NULL);
	} else {
		/* child */
		return *fname == '\0' ? dir->storage_name :
			t_strconcat(dir->storage_name, "/", fname, NULL);
	}
}

static int
dir_entry_get(struct fs_list_iterate_context *ctx, const char *dir_path,
	      struct list_dir_context *dir, const struct dirent *d)
{
	const char *storage_name, *vname, *root_dir;
	struct list_dir_entry *entry;
	enum imap_match_result match;
	enum mailbox_info_flags info_flags;
	int ret;

	/* skip . and .. */
	if (d->d_name[0] == '.' &&
	    (d->d_name[1] == '\0' ||
	     (d->d_name[1] == '.' && d->d_name[2] == '\0')))
		return 0;

	if (strcmp(d->d_name, ctx->ctx.list->set.maildir_name) == 0) {
		/* mail storage's internal directory (e.g. dbox-Mails).
		   this also means that the parent is selectable */
		dir->info_flags &= ~MAILBOX_NOSELECT;
		dir->info_flags |= MAILBOX_SELECT;
		return 0;
	}
	if (ctx->ctx.list->set.subscription_fname != NULL &&
	    strcmp(d->d_name, ctx->ctx.list->set.subscription_fname) == 0) {
		/* if this is the subscriptions file, skip it */
		root_dir = mailbox_list_get_root_forced(ctx->ctx.list,
							MAILBOX_LIST_PATH_TYPE_DIR);
		if (strcmp(root_dir, dir_path) == 0)
			return 0;
	}

	/* check the pattern */
	storage_name = dir_get_storage_name(dir, d->d_name);
	vname = mailbox_list_get_vname(ctx->ctx.list, storage_name);
	if (!uni_utf8_str_is_valid(vname)) {
		fs_list_rename_invalid(ctx, storage_name);
		/* just skip this in this iteration, we'll see it on the
		   next list */
		return 0;
	}

	match = imap_match(ctx->ctx.glob, vname);
	if (strcmp(d->d_name, "INBOX") == 0 && strcmp(vname, "INBOX") == 0 &&
	    ctx->ctx.list->ns->prefix_len > 0) {
		/* The glob was matched only against "INBOX", but this
		   directory may hold also prefix/INBOX. Just assume here
		   that it matches and verify later whether it was needed
		   or not. */
		match = IMAP_MATCH_YES;
	}

	if ((dir->info_flags & (MAILBOX_CHILDREN | MAILBOX_NOCHILDREN |
				MAILBOX_NOINFERIORS)) == 0 &&
	    (ctx->ctx.flags & MAILBOX_LIST_ITER_RETURN_CHILDREN) != 0) {
		/* we don't know yet if the parent has children. need to figure
		   out if this file is actually a visible mailbox */
	} else if (match != IMAP_MATCH_YES &&
		   (match & IMAP_MATCH_CHILDREN) == 0) {
		/* mailbox doesn't match any patterns, we don't care about it */
		return 0;
	}
	if ((ctx->ctx.flags & MAILBOX_LIST_ITER_SKIP_ALIASES) != 0) {
		ret = mailbox_list_dirent_is_alias_symlink(ctx->ctx.list,
							   dir_path, d);
		if (ret != 0)
			return ret < 0 ? -1 : 0;
	}
	ret = ctx->ctx.list->v.
		get_mailbox_flags(ctx->ctx.list, dir_path, d->d_name,
				  mailbox_list_get_file_type(d), &info_flags);
	if (ret <= 0)
		return ret;
	if (!MAILBOX_INFO_FLAGS_FINISHED(info_flags)) {
		/* mailbox existence isn't known yet. need to figure it out
		   the hard way. */
		if (fs_get_existence_info_flag(ctx, vname, &info_flags) < 0)
			return -1;
	}
	if ((info_flags & MAILBOX_NONEXISTENT) != 0)
		return 0;

	/* mailbox exists - make sure parent knows it has children */
	dir->info_flags &= ~(MAILBOX_NOCHILDREN | MAILBOX_NOINFERIORS);
	dir->info_flags |= MAILBOX_CHILDREN;

	if (match != IMAP_MATCH_YES && (match & IMAP_MATCH_CHILDREN) == 0) {
		/* this mailbox didn't actually match any pattern,
		   we just needed to know the children state */
		return 0;
	}

	/* entry matched a pattern. we're going to return this. */
	entry = array_append_space(&dir->entries);
	entry->fname = p_strdup(dir->pool, d->d_name);
	entry->info_flags = info_flags;
	return 0;
}

static bool
fs_list_get_storage_path(struct fs_list_iterate_context *ctx,
			 const char *storage_name, const char **path_r)
{
	const char *root, *path = storage_name;

	if (*path == '~') {
		if (!mailbox_list_try_get_absolute_path(ctx->ctx.list, &path)) {
			/* a) couldn't expand ~user/
			   b) mailbox is under our mail root, we changed
			   path to storage_name */
		}
		/* NOTE: the path may have been translated to a storage_name
		   instead of path */
	}
	if (*path != '/') {
		/* non-absolute path. add the mailbox root dir as prefix. */
		enum mailbox_list_path_type type =
			ctx->ctx.list->set.iter_from_index_dir ?
			MAILBOX_LIST_PATH_TYPE_INDEX :
			MAILBOX_LIST_PATH_TYPE_MAILBOX;
		if (!mailbox_list_get_root_path(ctx->ctx.list, type, &root))
			return FALSE;
		if (ctx->ctx.list->set.iter_from_index_dir &&
		    ctx->ctx.list->set.mailbox_dir_name[0] != '\0') {
			/* append "mailboxes/" to the index root */
			root = t_strconcat(root, "/",
				ctx->ctx.list->set.mailbox_dir_name, NULL);
		}
		path = *path == '\0' ? root :
			t_strconcat(root, "/", path, NULL);
	}
	*path_r = path;
	return TRUE;
}

static int
fs_list_dir_read(struct fs_list_iterate_context *ctx,
		 struct list_dir_context *dir)
{
	DIR *fsdir;
	struct dirent *d;
	const char *path;
	int ret = 0;

	if (!fs_list_get_storage_path(ctx, dir->storage_name, &path))
		return 0;
	if (path == NULL) {
		/* no mailbox root dir */
		return 0;
	}

	fsdir = opendir(path);
	if (fsdir == NULL) {
		if (ENOTFOUND(errno)) {
			/* root) user gave invalid hierarchy, ignore
			   sub) probably just race condition with other client
			   deleting the mailbox. */
			return 0;
		}
		if (errno == EACCES) {
			/* ignore permission errors */
			return 0;
		}
		mailbox_list_set_critical(ctx->ctx.list,
					  "opendir(%s) failed: %m", path);
		return -1;
	}
	if ((dir->info_flags & (MAILBOX_SELECT | MAILBOX_NOSELECT)) == 0) {
		/* we don't know if the parent is selectable or not. start with
		   the assumption that it isn't, until we see maildir_name */
		dir->info_flags |= MAILBOX_NOSELECT;
	}

	errno = 0;
	while ((d = readdir(fsdir)) != NULL) T_BEGIN {
		if (dir_entry_get(ctx, path, dir, d) < 0)
			ret = -1;
		errno = 0;
	} T_END;
	if (errno != 0) {
		mailbox_list_set_critical(ctx->ctx.list,
			"readdir(%s) failed: %m", path);
		ret = -1;
	}
	if (closedir(fsdir) < 0) {
		mailbox_list_set_critical(ctx->ctx.list,
			"closedir(%s) failed: %m", path);
		ret = -1;
	}
	return ret;
}

static struct list_dir_context *
fs_list_read_dir(struct fs_list_iterate_context *ctx, const char *storage_name,
		 enum mailbox_info_flags info_flags)
{
	struct list_dir_context *dir;
	pool_t pool;

	pool = pool_alloconly_create(MEMPOOL_GROWING"fs iter dir", 256);
	dir = p_new(pool, struct list_dir_context, 1);
	dir->pool = pool;
	dir->storage_name = p_strdup(pool, storage_name);
	dir->info_flags = info_flags;
	p_array_init(&dir->entries, pool, 16);

	if (fs_list_dir_read(ctx, dir) < 0)
		ctx->ctx.failed = TRUE;

	if ((dir->info_flags & (MAILBOX_CHILDREN | MAILBOX_NOCHILDREN |
				MAILBOX_NOINFERIORS)) == 0) {
		/* assume this directory has no children */
		dir->info_flags |= MAILBOX_NOCHILDREN;
	}
	return dir;
}

static bool
fs_list_get_valid_patterns(struct fs_list_iterate_context *ctx,
			   const char *const *patterns)
{
	struct mailbox_list *_list = ctx->ctx.list;
	ARRAY(const char *) valid_patterns;
	const char *pattern, *test_pattern, *real_pattern, *error;
	size_t prefix_len;

	prefix_len = strlen(_list->ns->prefix);
	p_array_init(&valid_patterns, ctx->ctx.pool, 8);
	for (; *patterns != NULL; patterns++) {
		/* check that we're not trying to do any "../../" lists */
		test_pattern = *patterns;
		/* skip namespace prefix if possible. this allows using
		   e.g. ~/mail/ prefix and have it pass the pattern
		   validation. */
		if (strncmp(test_pattern, _list->ns->prefix, prefix_len) == 0)
			test_pattern += prefix_len;
		if (!uni_utf8_str_is_valid(test_pattern)) {
			/* ignore invalid UTF8 patterns */
			continue;
		}
		/* check pattern also when it's converted to use real
		   separators. */
		real_pattern =
			mailbox_list_get_storage_name(_list, test_pattern);
		if (mailbox_list_is_valid_name(_list, test_pattern, &error) &&
		    mailbox_list_is_valid_name(_list, real_pattern, &error)) {
			pattern = p_strdup(ctx->ctx.pool, *patterns);
			array_push_back(&valid_patterns, &pattern);
		}
	}
	array_append_zero(&valid_patterns); /* NULL-terminate */
	ctx->valid_patterns = array_front(&valid_patterns);

	return array_count(&valid_patterns) > 1;
}

static void fs_list_get_roots(struct fs_list_iterate_context *ctx)
{
	struct mail_namespace *ns = ctx->ctx.list->ns;
	char ns_sep = mail_namespace_get_sep(ns);
	bool full_fs_access =
		ctx->ctx.list->mail_set->mail_full_filesystem_access;
	const char *const *patterns, *pattern, *const *parentp, *const *childp;
	const char *p, *last, *root, *prefix_vname;
	unsigned int i;
	size_t parentlen;

	i_assert(*ctx->valid_patterns != NULL);

	/* get the root dirs for all the patterns */
	p_array_init(&ctx->roots, ctx->ctx.pool, 8);
	for (patterns = ctx->valid_patterns; *patterns != NULL; patterns++) {
		pattern = *patterns;

		if (strncmp(pattern, ns->prefix, ns->prefix_len) != 0) {
			/* typically e.g. prefix=foo/bar/, pattern=foo/%/%
			   we'll use root="" for this.

			   it might of course also be pattern=foo/%/prefix/%
			   where we could optimize with root=prefix, but
			   probably too much trouble to implement. */
			prefix_vname = "";
		} else {
			for (p = last = pattern; *p != '\0'; p++) {
				if (*p == '%' || *p == '*')
					break;
				if (*p == ns_sep)
					last = p;
			}
			prefix_vname = t_strdup_until(pattern, last);
		}

		if (*pattern == ns_sep && full_fs_access) {
			/* pattern=/something with full filesystem access.
			   (without full filesystem access we want to skip this
			   if namespace prefix begins with separator) */
			root = "/";
		} else if ((ns->flags & NAMESPACE_FLAG_INBOX_USER) != 0 &&
			 ns->prefix_len == 6 &&
			 strcasecmp(prefix_vname, "INBOX") == 0 &&
			 strncasecmp(ns->prefix, pattern, ns->prefix_len) == 0) {
			/* special case: Namespace prefix is INBOX/ and
			   we just want to see its contents (not the
			   INBOX's children). */
			root = "";
		} else if ((ns->flags & NAMESPACE_FLAG_INBOX_ANY) != 0 &&
			   ns->type == MAIL_NAMESPACE_TYPE_SHARED &&
			   !ctx->ctx.list->mail_set->mail_shared_explicit_inbox &&
			   (prefix_vname[0] == '\0' ||
			    (strncmp(ns->prefix, prefix_vname, ns->prefix_len-1) == 0 &&
			     prefix_vname[ns->prefix_len-1] == '\0'))) {
			/* we need to handle ns prefix explicitly here, because
			   getting storage name with
			   mail_shared_explicit_inbox=no would return
			   root=INBOX. (e.g. LIST "" shared/user/box has to
			   return the box when it doesn't exist but
			   shared/user/box/child exists) */
			root = "";
		} else {
			root = mailbox_list_get_storage_name(ctx->ctx.list,
							     prefix_vname);
		}

		if (*root == '/') {
			/* /absolute/path */
			i_assert(full_fs_access);
		} else if (*root == '~') {
			/* ~user/path - don't expand the ~user/ path, since we
			   need to be able to convert the path back to vname */
			i_assert(full_fs_access);
		} else {
			/* mailbox name */
		}
		root = p_strdup(ctx->ctx.pool, root);
		array_push_back(&ctx->roots, &root);
	}
	/* sort the root dirs so that /foo is before /foo/bar */
	array_sort(&ctx->roots, i_strcmp_p);
	/* remove /foo/bar when there already exists /foo parent */
	for (i = 1; i < array_count(&ctx->roots); ) {
		parentp = array_idx(&ctx->roots, i-1);
		childp = array_idx(&ctx->roots, i);
		parentlen = strlen(*parentp);
		if (str_begins(*childp, *parentp) &&
		    (parentlen == 0 ||
		     (*childp)[parentlen] == ctx->sep ||
		     (*childp)[parentlen] == '\0'))
			array_delete(&ctx->roots, i, 1);
		else
			i++;
	}
}

static void fs_list_next_root(struct fs_list_iterate_context *ctx)
{
	const char *const *roots;
	unsigned int count;

	i_assert(ctx->dir == NULL);

	roots = array_get(&ctx->roots, &count);
	if (ctx->root_idx == count)
		return;
	ctx->dir = fs_list_read_dir(ctx, roots[ctx->root_idx],
				    MAILBOX_NOSELECT);
	ctx->root_idx++;
}

struct mailbox_list_iterate_context *
fs_list_iter_init(struct mailbox_list *_list, const char *const *patterns,
		  enum mailbox_list_iter_flags flags)
{
	struct fs_list_iterate_context *ctx;
	pool_t pool;

	if ((flags & MAILBOX_LIST_ITER_SELECT_SUBSCRIBED) != 0) {
		/* we're listing only subscribed mailboxes. we can't optimize
		   it, so just use the generic code. */
		return mailbox_list_subscriptions_iter_init(_list, patterns,
							    flags);
	}

	pool = pool_alloconly_create("mailbox list fs iter", 2048);
	ctx = p_new(pool, struct fs_list_iterate_context, 1);
	ctx->ctx.pool = pool;
	ctx->ctx.list = _list;
	ctx->ctx.flags = flags;
	array_create(&ctx->ctx.module_contexts, pool, sizeof(void *), 5);

	ctx->info_pool = pool_alloconly_create("fs list", 1024);
	ctx->sep = mail_namespace_get_sep(_list->ns);
	ctx->info.ns = _list->ns;

	if (!fs_list_get_valid_patterns(ctx, patterns)) {
		/* we've only invalid patterns (or INBOX). create a glob
		   anyway to avoid any crashes due to glob being accessed
		   elsewhere */
		ctx->ctx.glob = imap_match_init(pool, "", TRUE, ctx->sep);
		return &ctx->ctx;
	}
	ctx->ctx.glob = imap_match_init_multiple(pool, ctx->valid_patterns,
						 TRUE, ctx->sep);
	fs_list_get_roots(ctx);
	fs_list_next_root(ctx);
	return &ctx->ctx;
}

int fs_list_iter_deinit(struct mailbox_list_iterate_context *_ctx)
{
	struct fs_list_iterate_context *ctx =
		(struct fs_list_iterate_context *)_ctx;
	int ret = _ctx->failed ? -1 : 0;

	if ((_ctx->flags & MAILBOX_LIST_ITER_SELECT_SUBSCRIBED) != 0)
		return mailbox_list_subscriptions_iter_deinit(_ctx);

	while (ctx->dir != NULL) {
		struct list_dir_context *dir = ctx->dir;

		ctx->dir = dir->parent;
		pool_unref(&dir->pool);
	}

	pool_unref(&ctx->info_pool);
	pool_unref(&_ctx->pool);
	return ret;
}

static void inbox_flags_set(struct fs_list_iterate_context *ctx)
{
	/* INBOX is always selectable */
	ctx->info.flags &= ~(MAILBOX_NOSELECT | MAILBOX_NONEXISTENT);

	if (mail_namespace_is_inbox_noinferiors(ctx->info.ns)) {
		ctx->info.flags &= ~(MAILBOX_CHILDREN|MAILBOX_NOCHILDREN);
		ctx->info.flags |= MAILBOX_NOINFERIORS;
	}
}

static const char *
fs_list_get_inbox_vname(struct fs_list_iterate_context *ctx)
{
	struct mail_namespace *ns = ctx->ctx.list->ns;

	if ((ns->flags & NAMESPACE_FLAG_INBOX_USER) != 0)
		return "INBOX";
	else
		return p_strconcat(ctx->info_pool, ns->prefix, "INBOX", NULL);
}

static bool
list_file_unfound_inbox(struct fs_list_iterate_context *ctx)
{
	ctx->info.flags = 0;
	ctx->info.vname = fs_list_get_inbox_vname(ctx);

	if (mailbox_list_mailbox(ctx->ctx.list, "INBOX", &ctx->info.flags) < 0)
		ctx->ctx.failed = TRUE;

	if ((ctx->ctx.flags & MAILBOX_LIST_ITER_NO_AUTO_BOXES) != 0 &&
	    (ctx->info.flags & MAILBOX_NONEXISTENT) != 0)
		return FALSE;

	inbox_flags_set(ctx);
	if (ctx->inbox_has_children)
		ctx->info.flags |= MAILBOX_CHILDREN;
	else {
		/* we got here because we didn't see INBOX among other mailboxes,
		   which means it has no children. */
		ctx->info.flags |= MAILBOX_NOCHILDREN;
	}
	return TRUE;
}

static bool
list_file_is_any_inbox(struct fs_list_iterate_context *ctx,
		       const char *storage_name)
{
	const char *path, *inbox_path;

	if (!fs_list_get_storage_path(ctx, storage_name, &path))
		return FALSE;

	if (mailbox_list_get_path(ctx->ctx.list, "INBOX",
				  MAILBOX_LIST_PATH_TYPE_DIR, &inbox_path) <= 0)
		i_unreached();
	return strcmp(path, inbox_path) == 0;
}

static int
fs_list_entry(struct fs_list_iterate_context *ctx,
	      const struct list_dir_entry *entry)
{
	struct mail_namespace *ns = ctx->ctx.list->ns;
	struct list_dir_context *dir, *subdir = NULL;
	enum imap_match_result match, child_dir_match;
	const char *storage_name, *vname, *child_dir_name;

	dir = ctx->dir;
	storage_name = dir_get_storage_name(dir, entry->fname);

	vname = mailbox_list_get_vname(ctx->ctx.list, storage_name);
	ctx->info.vname = p_strdup(ctx->info_pool, vname);
	ctx->info.flags = entry->info_flags;

	match = imap_match(ctx->ctx.glob, ctx->info.vname);

	if (strcmp(ctx->info.vname, "INBOX") == 0 &&
	    ctx->ctx.list->ns->prefix_len > 0) {
		/* INBOX's children are matched as prefix/INBOX */
		child_dir_name = t_strdup_printf("%sINBOX", ns->prefix);
	} else {
		child_dir_name =
			t_strdup_printf("%s%c", ctx->info.vname, ctx->sep);
	}
	child_dir_match = imap_match(ctx->ctx.glob, child_dir_name);
	if (child_dir_match == IMAP_MATCH_YES)
		child_dir_match |= IMAP_MATCH_CHILDREN;

	if ((ctx->info.flags &
	     (MAILBOX_NOCHILDREN | MAILBOX_NOINFERIORS)) != 0) {
		/* mailbox has no children */
	} else if ((ctx->info.flags & MAILBOX_CHILDREN) != 0 &&
		   (child_dir_match & IMAP_MATCH_CHILDREN) == 0) {
		/* mailbox has children, but we don't want to list them */
	} else if (((ctx->ctx.flags & MAILBOX_LIST_ITER_RETURN_CHILDREN) != 0 ||
		    (child_dir_match & IMAP_MATCH_CHILDREN) != 0) &&
		   *entry->fname != '\0') {
		/* a) mailbox has children and we want to return them
		   b) we don't want to return mailbox's children, but we need
		   to know if it has any */
		subdir = fs_list_read_dir(ctx, storage_name, entry->info_flags);
		subdir->parent = dir;
		ctx->dir = subdir;
		/* the scanning may have updated the dir's info flags */
		ctx->info.flags = subdir->info_flags;
	}

	/* handle INBOXes correctly */
	if (strcasecmp(ctx->info.vname, "INBOX") == 0 &&
	    (ns->flags & NAMESPACE_FLAG_INBOX_USER) != 0) {
		/* either this is user's INBOX, or it's a naming conflict */
		if (!list_file_is_any_inbox(ctx, storage_name)) {
			if (subdir == NULL) {
				/* no children */
			} else if ((ctx->ctx.list->flags &
				    MAILBOX_LIST_FLAG_MAILBOX_FILES) == 0) {
				if (strcmp(storage_name, "INBOX") == 0) {
					/* INBOX and its children are in
					   different paths */
					ctx->inbox_has_children = TRUE;
				} else {
					/* naming conflict, skip its
					   children also */
					ctx->dir = dir;
					pool_unref(&subdir->pool);
				}
			} else if ((ctx->info.flags & MAILBOX_NOINFERIORS) == 0) {
				/* INBOX itself is \NoInferiors, but this INBOX
				   is a directory, and we can make INBOX have
				   children using it. */
				ctx->inbox_has_children = TRUE;
			}
			return 0;
		}
		if (subdir != NULL)
			ctx->inbox_has_children = TRUE;
		inbox_flags_set(ctx);
		ctx->info.vname = "INBOX"; /* always return uppercased */
		ctx->inbox_found = TRUE;
	} else if (strcmp(storage_name, "INBOX") == 0 &&
		   (ns->flags & NAMESPACE_FLAG_INBOX_USER) != 0) {
		/* this is <ns prefix>/INBOX. don't return it, unless it has
		   children. */
		i_assert(*ns->prefix != '\0');
		if ((ctx->info.flags & MAILBOX_CHILDREN) == 0)
			return 0;
		/* although it could be selected with this name,
		   it would be confusing for clients to see the same
		   mails in both INBOX and <ns prefix>/INBOX. */
		ctx->info.flags &= ~MAILBOX_SELECT;
		ctx->info.flags |= MAILBOX_NOSELECT;
	} else if ((ns->flags & NAMESPACE_FLAG_INBOX_ANY) != 0 &&
		   list_file_is_any_inbox(ctx, storage_name)) {
		if ((ns->flags & NAMESPACE_FLAG_INBOX_USER) != 0) {
			/* probably mbox inbox file */
			return 0;
		}
		/* shared/user/INBOX */
		ctx->info.flags &= ~(MAILBOX_NOSELECT | MAILBOX_NONEXISTENT);
		ctx->info.flags |= MAILBOX_SELECT;
		ctx->inbox_found = TRUE;
	}

	if (match != IMAP_MATCH_YES) {
		/* mailbox's children may match, but the mailbox itself
		   doesn't */
		return 0;
	}
	if (mailbox_list_iter_try_delete_noselect(&ctx->ctx, &ctx->info, storage_name))
		return 0;
	return 1;
}

static int
fs_list_next(struct fs_list_iterate_context *ctx)
{
	struct list_dir_context *dir;
	const struct list_dir_entry *entries;
	unsigned int count;
	int ret;

	while (ctx->dir != NULL) {
		/* NOTE: fs_list_entry() may change ctx->dir */
		entries = array_get(&ctx->dir->entries, &count);
		while (ctx->dir->entry_idx < count) {
			p_clear(ctx->info_pool);
			ret = fs_list_entry(ctx, &entries[ctx->dir->entry_idx++]);
			if (ret > 0)
				return 1;
			if (ret < 0)
				ctx->ctx.failed = TRUE;
			entries = array_get(&ctx->dir->entries, &count);
		}

		dir = ctx->dir;
		ctx->dir = dir->parent;
		pool_unref(&dir->pool);

		if (ctx->dir == NULL)
			fs_list_next_root(ctx);
	}

	if (ctx->inbox_has_children && ctx->ctx.list->ns->prefix_len > 0 &&
	    !ctx->listed_prefix_inbox) {
		ctx->info.flags = MAILBOX_CHILDREN | MAILBOX_NOSELECT;
		ctx->info.vname =
			p_strconcat(ctx->info_pool,
				    ctx->ctx.list->ns->prefix, "INBOX", NULL);
		ctx->listed_prefix_inbox = TRUE;
		if (imap_match(ctx->ctx.glob, ctx->info.vname) == IMAP_MATCH_YES)
			return 1;
	}
	if (!ctx->inbox_found && ctx->ctx.glob != NULL &&
	    (ctx->ctx.list->ns->flags & NAMESPACE_FLAG_INBOX_ANY) != 0 &&
	    imap_match(ctx->ctx.glob,
		       fs_list_get_inbox_vname(ctx)) == IMAP_MATCH_YES) {
		/* INBOX wasn't seen while listing other mailboxes. It might
		   be located elsewhere. */
		ctx->inbox_found = TRUE;
		return list_file_unfound_inbox(ctx) ? 1 : 0;
	}

	/* finished */
	return 0;
}

const struct mailbox_info *
fs_list_iter_next(struct mailbox_list_iterate_context *_ctx)
{
	struct fs_list_iterate_context *ctx =
		(struct fs_list_iterate_context *)_ctx;
	int ret;

	if ((_ctx->flags & MAILBOX_LIST_ITER_SELECT_SUBSCRIBED) != 0)
		return mailbox_list_subscriptions_iter_next(_ctx);

	T_BEGIN {
		ret = fs_list_next(ctx);
	} T_END;

	if (ret == 0)
		return mailbox_list_iter_default_next(_ctx);
	else if (ret < 0)
		return NULL;

	if (_ctx->list->ns->type == MAIL_NAMESPACE_TYPE_SHARED &&
	    !_ctx->list->ns->list->mail_set->mail_shared_explicit_inbox &&
	    strlen(ctx->info.vname) < _ctx->list->ns->prefix_len) {
		/* shared/user INBOX, IMAP code already lists it */
		return fs_list_iter_next(_ctx);
	}

	if ((ctx->ctx.flags & MAILBOX_LIST_ITER_RETURN_SUBSCRIBED) != 0) {
		mailbox_list_set_subscription_flags(ctx->ctx.list,
						    ctx->info.vname,
						    &ctx->info.flags);
	}
	i_assert(ctx->info.vname != NULL);
	return &ctx->info;
}
