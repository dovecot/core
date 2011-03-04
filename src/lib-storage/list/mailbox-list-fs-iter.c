/* Copyright (c) 2002-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "imap-match.h"
#include "mailbox-tree.h"
#include "mailbox-list-subscriptions.h"
#include "mailbox-list-fs.h"

#include <ctype.h>
#include <dirent.h>
#include <sys/stat.h>

struct list_dir_entry {
	const char *fname;
	enum mailbox_list_file_type type;
};

struct list_dir_context {
	struct list_dir_context *prev;

	DIR *dirp;
	char *real_path, *virtual_path;

	const struct list_dir_entry *next_entry;
	struct list_dir_entry entry;
	char *entry_fname;
	struct mailbox_info info;

	unsigned int pattern_pos;

	unsigned int delayed_send:1;
};

struct fs_list_iterate_context {
	struct mailbox_list_iterate_context ctx;

	ARRAY_DEFINE(valid_patterns, char *);
	struct imap_match_glob *glob;
	struct mailbox_tree_context *subs_tree;
	struct mailbox_tree_iterate_context *tree_iter;
	char sep;

	enum mailbox_info_flags inbox_flags;

	const struct mailbox_info *(*next)(struct fs_list_iterate_context *ctx);

	pool_t info_pool;
	struct mailbox_info info;
        struct list_dir_context *dir;

	unsigned int inbox_match:1;
	unsigned int inbox_found:1;
	unsigned int inbox_listed:1;
};

static const struct mailbox_info *
fs_list_subs(struct fs_list_iterate_context *ctx);
static const struct mailbox_info *
fs_list_next(struct fs_list_iterate_context *ctx);

static int
pattern_get_path_pos(struct fs_list_iterate_context *ctx, const char *pattern,
		     const char *path, unsigned int *pos_r)
{
	unsigned int i, j;

	if (strncasecmp(path, "INBOX", 5) == 0 && path[5] == ctx->sep) {
		/* make sure INBOX prefix is matched case-insensitively */
		char *tmp = t_strdup_noconst(pattern);

		if (strncmp(path, "INBOX", 5) != 0)
			path = t_strdup_printf("INBOX%c%s", ctx->sep, path + 6);

		for (i = 0; tmp[i] != ctx->sep && tmp[i] != '\0'; i++)
			tmp[i] = i_toupper(tmp[i]);
		pattern = tmp;
	}

	for (i = j = 0; path[i] != '\0'; i++) {
		if (pattern[j] == '*')
			return -1;

		if (pattern[j] == '%') {
			/* skip until we're at the next hierarchy separator */
			if (path[i] == ctx->sep) {
				/* assume that pattern matches. we can't be
				   sure, but it'll be checked later. */
				for (j++; pattern[j] != '\0'; j++) {
					if (pattern[j] == '*')
						return -1;
					if (pattern[j] == ctx->sep) {
						j++;
						break;
					}
				}
			}
		} else {
			if (path[i] != pattern[j]) {
				/* pattern doesn't match path at all */
				return 0;
			}
			j++;
		}
	}
	*pos_r = j;
	return 1;
}

static bool
pattern_has_wildcard_at(struct fs_list_iterate_context *ctx,
			const char *pattern, const char *path)
{
	unsigned int pos;
	int ret;

	if ((ret = pattern_get_path_pos(ctx, pattern, path, &pos)) < 0)
		return TRUE;
	if (ret == 0)
		return FALSE;

	if (pattern[pos] == '\0')
		return TRUE;

	for (; pattern[pos] != '\0' && pattern[pos] != ctx->sep; pos++) {
		if (pattern[pos] == '%' || pattern[pos] == '*')
			return TRUE;
	}
	return FALSE;
}

static int list_opendir(struct fs_list_iterate_context *ctx,
			const char *path, const char *list_path, DIR **dirp)
{
	char *const *patterns;
	unsigned int i;

	/* if no patterns have wildcards at this point of the path, we don't
	   have to readdir() the files. instead we can just go through the
	   mailboxes listed in patterns. */
	T_BEGIN {
		patterns = array_idx(&ctx->valid_patterns, 0);
		for (i = 0; patterns[i] != NULL; i++) {
			if (pattern_has_wildcard_at(ctx, patterns[i],
						    list_path))
				break;
		}
	} T_END;
	if (patterns[i] == NULL) {
		*dirp = NULL;
		return 1;
	}

	*dirp = opendir(*path == '\0' ? "/" : path);
	if (*dirp != NULL)
		return 1;

	if (ENOTFOUND(errno)) {
		/* root) user gave invalid hiearchy, ignore
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

static const char *list_get_rootdir(struct fs_list_iterate_context *ctx,
				    const char **vpath)
{
	const char *const *patterns, *name, *p, *last;

	if (!ctx->ctx.list->mail_set->mail_full_filesystem_access)
		return NULL;

	/* see if there are any absolute paths in patterns */
	patterns = (const void *)array_idx(&ctx->valid_patterns, 0);
	for (; *patterns != NULL; patterns++) {
		name = *patterns;

		if (*name == '/') {
			*vpath = "/";
			return "/";
		}
		if (*name == '~') {
			for (p = last = name; *p != '\0'; p++) {
				if (*p == '%' || *p == '*')
					break;
				if (*p == '/')
					last = p;
			}
			name = p = t_strdup_until(name, last+1);
			if (mailbox_list_try_get_absolute_path(ctx->ctx.list,
							       &name)) {
				*vpath = p;
				return name;
			}
		}
	}
	return NULL;
}

struct mailbox_list_iterate_context *
fs_list_iter_init(struct mailbox_list *_list, const char *const *patterns,
		  enum mailbox_list_iter_flags flags)
{
	struct fs_list_iterate_context *ctx;
	const char *path, *vpath, *rootdir, *test_pattern, *real_pattern;
	char *pattern;
	DIR *dirp;
	unsigned int prefix_len;
	int ret;

	ctx = i_new(struct fs_list_iterate_context, 1);
	ctx->ctx.list = _list;
	ctx->ctx.flags = flags;
	ctx->info_pool = pool_alloconly_create("fs list", 1024);
	ctx->next = fs_list_next;
	ctx->sep = _list->ns->sep;
	ctx->info.ns = _list->ns;

	prefix_len = strlen(_list->ns->prefix);
	i_array_init(&ctx->valid_patterns, 8);
	for (; *patterns != NULL; patterns++) {
		/* check that we're not trying to do any "../../" lists */
		test_pattern = *patterns;
		/* skip namespace prefix if possible. this allows using
		   e.g. ~/mail/ prefix and have it pass the pattern
		   validation. */
		if (strncmp(test_pattern, _list->ns->prefix, prefix_len) == 0)
			test_pattern += prefix_len;
		/* check pattern also when it's converted to use real
		   separators. */
		real_pattern = mail_namespace_fix_sep(_list->ns, test_pattern);
		if (mailbox_list_is_valid_pattern(_list, test_pattern) &&
		    mailbox_list_is_valid_pattern(_list, real_pattern)) {
			if (strcasecmp(*patterns, "INBOX") == 0) {
				ctx->inbox_match = TRUE;
				continue;
			}
			pattern = i_strdup(*patterns);
			array_append(&ctx->valid_patterns, &pattern, 1);
		}
	}
	(void)array_append_space(&ctx->valid_patterns); /* NULL-terminate */

	if (array_count(&ctx->valid_patterns) == 1) {
		/* we've only invalid patterns (or INBOX) */
		return &ctx->ctx;
	}
	patterns = (const void *)array_idx(&ctx->valid_patterns, 0);
	ctx->glob = imap_match_init_multiple(default_pool, patterns, TRUE,
					     ctx->sep);

	if ((flags & (MAILBOX_LIST_ITER_SELECT_SUBSCRIBED |
		      MAILBOX_LIST_ITER_RETURN_SUBSCRIBED)) != 0) {
		/* we want to return MAILBOX_SUBSCRIBED flags, possibly for all
		   mailboxes. Build a mailbox tree of all the subscriptions. */
		ctx->subs_tree = mailbox_tree_init(ctx->sep);
		if (mailbox_list_subscriptions_fill(&ctx->ctx, ctx->subs_tree,
						    ctx->glob, FALSE) < 0) {
			ctx->ctx.failed = TRUE;
			return &ctx->ctx;
		}
	}

	if ((flags & MAILBOX_LIST_ITER_SELECT_SUBSCRIBED) != 0) {
		ctx->next = fs_list_subs;
		ctx->tree_iter = mailbox_tree_iterate_init(ctx->subs_tree, NULL,
							   MAILBOX_MATCHED);
		return &ctx->ctx;
	}

	vpath = _list->ns->prefix;
	rootdir = list_get_rootdir(ctx, &vpath);
	if (rootdir == NULL) {
		path = mailbox_list_get_path(_list, NULL,
					     MAILBOX_LIST_PATH_TYPE_MAILBOX);
	} else {
		path = mailbox_list_get_path(_list, rootdir,
					     MAILBOX_LIST_PATH_TYPE_DIR);
	}
	if ((ret = list_opendir(ctx, path, vpath, &dirp)) < 0)
		return &ctx->ctx;

	if (ret > 0) {
		ctx->dir = i_new(struct list_dir_context, 1);
		ctx->dir->dirp = dirp;
		ctx->dir->real_path = i_strdup(path);
		ctx->dir->virtual_path = i_strdup(vpath);
	}
	return &ctx->ctx;
}

static void list_dir_context_free(struct list_dir_context *dir)
{
	if (dir->dirp != NULL)
		(void)closedir(dir->dirp);
	i_free(dir->entry_fname);
	i_free(dir->real_path);
	i_free(dir->virtual_path);
	i_free(dir);
}

int fs_list_iter_deinit(struct mailbox_list_iterate_context *_ctx)
{
	struct fs_list_iterate_context *ctx =
		(struct fs_list_iterate_context *)_ctx;
	char **patterns;
	unsigned int i, count;
	int ret = ctx->ctx.failed ? -1 : 0;

	patterns = array_get_modifiable(&ctx->valid_patterns, &count);
	for (i = 0; i < count; i++)
		i_free(patterns[i]);
	array_free(&ctx->valid_patterns);

	while (ctx->dir != NULL) {
		struct list_dir_context *dir = ctx->dir;

		ctx->dir = dir->prev;
                list_dir_context_free(dir);
	}

	if (ctx->tree_iter != NULL)
		mailbox_tree_iterate_deinit(&ctx->tree_iter);
	if (ctx->subs_tree != NULL)
		mailbox_tree_deinit(&ctx->subs_tree);
	if (ctx->info_pool != NULL)
		pool_unref(&ctx->info_pool);
	if (ctx->glob != NULL)
		imap_match_deinit(&ctx->glob);
	i_free(ctx);

	return ret;
}

const struct mailbox_info *
fs_list_iter_next(struct mailbox_list_iterate_context *_ctx)
{
	struct fs_list_iterate_context *ctx =
		(struct fs_list_iterate_context *)_ctx;
	const struct mailbox_info *info;

	if (ctx->ctx.failed)
		return NULL;

	T_BEGIN {
		info = ctx->next(ctx);
	} T_END;
	i_assert(info == NULL || info->name != NULL);
	return info;
}

static void
path_split(const char *path, const char **dir_r, const char **fname_r)
{
	const char *p;

	p = strrchr(path, '/');
	if (p == NULL) {
		*dir_r = "";
		*fname_r = path;
	} else {
		*dir_r = t_strdup_until(path, p);
		*fname_r = p + 1;
	}
}

static enum mailbox_info_flags
fs_list_get_subscription_flags(struct fs_list_iterate_context *ctx,
			       const char *mailbox)
{
	struct mailbox_node *node;

	if (ctx->subs_tree == NULL)
		return 0;

	node = mailbox_tree_lookup(ctx->subs_tree, mailbox);
	if (node == NULL)
		return 0;

	return node->flags & (MAILBOX_SUBSCRIBED | MAILBOX_CHILD_SUBSCRIBED);
}

static void inbox_flags_set(struct fs_list_iterate_context *ctx)
{
	struct mail_namespace *ns = ctx->ctx.list->ns;

	/* INBOX is always selectable */
	ctx->info.flags &= ~(MAILBOX_NOSELECT | MAILBOX_NONEXISTENT);

	if (*ns->prefix != '\0' &&
	    (ns->flags & NAMESPACE_FLAG_INBOX_USER) != 0) {
		/* we're listing INBOX for a namespace with a prefix.
		   if there are children for the INBOX, they're returned under
		   the mailbox prefix, not under the INBOX itself. */
		ctx->info.flags &= ~MAILBOX_CHILDREN;
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

static struct mailbox_info *fs_list_inbox(struct fs_list_iterate_context *ctx)
{
	ctx->info.flags = 0;
	ctx->info.name = fs_list_get_inbox_vname(ctx);

	if (mailbox_list_mailbox(ctx->ctx.list, "INBOX", &ctx->info.flags) < 0)
		ctx->ctx.failed = TRUE;

	if ((ctx->ctx.flags & MAILBOX_LIST_ITER_NO_AUTO_INBOX) != 0 &&
	    (ctx->info.flags & MAILBOX_NONEXISTENT) != 0)
		return NULL;

	ctx->info.flags |= fs_list_get_subscription_flags(ctx, "INBOX");
	inbox_flags_set(ctx);
	/* we got here because we didn't see INBOX among other mailboxes,
	   which means it has no children. */
	ctx->info.flags |= MAILBOX_NOCHILDREN;
	return &ctx->info;
}

static bool
list_file_is_inbox(struct fs_list_iterate_context *ctx, const char *fname)
{
	const char *real_path, *inbox_path;

	real_path = t_strconcat(ctx->dir->real_path, "/", fname, NULL);
	inbox_path = mailbox_list_get_path(ctx->ctx.list, "INBOX",
					   MAILBOX_LIST_PATH_TYPE_DIR);
	return strcmp(real_path, inbox_path) == 0;
}

static bool
list_file_inbox(struct fs_list_iterate_context *ctx, const char *fname)
{
	if (ctx->inbox_listed) {
		/* already listed the INBOX */
		return FALSE;
	}
	inbox_flags_set(ctx);

	if (list_file_is_inbox(ctx, fname) &&
	    (ctx->ctx.list->flags & MAILBOX_LIST_FLAG_MAILBOX_FILES) != 0) {
		/* delay listing in case there's a INBOX/ directory.
		   do this only when INBOX is a file! otherwise we won't list
		   INBOX children. */
		ctx->inbox_found = TRUE;
		ctx->inbox_flags = ctx->info.flags;
		return FALSE;
	}
	if (strcmp(fname, "INBOX") != 0 ||
	    (ctx->info.flags & MAILBOX_NOINFERIORS) != 0) {
		/* duplicate INBOX, can't show this */
		return FALSE;
	}

	/* INBOX/ directory. show the INBOX list now */
	if ((ctx->ctx.list->flags & MAILBOX_LIST_FLAG_MAILBOX_FILES) == 0) {
		/* this directory is the INBOX */
		ctx->inbox_found = TRUE;
	} else if (!ctx->inbox_found) {
		(void)fs_list_inbox(ctx);
		ctx->info.flags &= ~(MAILBOX_NOSELECT | MAILBOX_NONEXISTENT |
				     MAILBOX_NOINFERIORS | MAILBOX_NOCHILDREN);
		ctx->inbox_found = TRUE;
	} else {
		ctx->info.flags &= ~(MAILBOX_NOSELECT | MAILBOX_NONEXISTENT);
		ctx->info.flags |= ctx->inbox_flags;
	}
	ctx->inbox_listed = TRUE;
	return TRUE;
}

static int
list_file_subdir(struct fs_list_iterate_context *ctx,
		 enum imap_match_result match, const char *list_path,
		 const char *fname)
{
	struct list_dir_context *dir;
	DIR *dirp;
	enum imap_match_result match2;
	const char *vpath, *real_path;
	bool scan_subdir, delayed_send = FALSE;
	int ret;

	vpath = t_strdup_printf("%s%c", list_path, ctx->sep);
	match2 = imap_match(ctx->glob, vpath);

	if (match == IMAP_MATCH_YES)
		ctx->info.name = p_strdup(ctx->info_pool, list_path);
	else if (match2 == IMAP_MATCH_YES)
		ctx->info.name = p_strdup(ctx->info_pool, vpath);
	else
		ctx->info.name = NULL;

	scan_subdir = (match2 & (IMAP_MATCH_YES | IMAP_MATCH_CHILDREN)) != 0;
	if ((match == IMAP_MATCH_YES || scan_subdir) &&
	    ctx->info.name != NULL &&
	    (ctx->ctx.flags & MAILBOX_LIST_ITER_RETURN_CHILDREN) != 0 &&
	    (ctx->info.flags & (MAILBOX_CHILDREN | MAILBOX_NOCHILDREN)) == 0) {
		scan_subdir = TRUE;
		delayed_send = TRUE;
	}

	if ((ctx->ctx.flags & MAILBOX_LIST_ITER_SHOW_EXISTING_PARENT) == 0) {
		/* LIST "" foo/% - we don't want to see foo/ returned */
		delayed_send = FALSE;
		match2 = IMAP_MATCH_CHILDREN;
	}

	if (scan_subdir) {
		real_path = t_strconcat(ctx->dir->real_path, "/", fname, NULL);
		ret = list_opendir(ctx, real_path, vpath, &dirp);
	} else {
		ret = 0;
	}
	if (ret > 0) {
		dir = i_new(struct list_dir_context, 1);
		dir->dirp = dirp;
		dir->real_path = i_strdup(real_path);
		dir->virtual_path =
			i_strdup_printf("%s%c", list_path, ctx->sep);

		dir->prev = ctx->dir;
		ctx->dir = dir;

		if (delayed_send) {
			dir->delayed_send = TRUE;
			dir->info = ctx->info;
			return 0;
		}
	} else if (ret < 0)
		return -1;
	return match == IMAP_MATCH_YES || match2 == IMAP_MATCH_YES;
}

static int
list_file(struct fs_list_iterate_context *ctx,
	  const struct list_dir_entry *entry)
{
	struct mail_namespace *ns = ctx->ctx.list->ns;
	const char *fname = entry->fname;
	const char *list_path, *root_dir;
	enum imap_match_result match;
	struct stat st;
	int ret;

	/* skip . and .. */
	if (fname[0] == '.' &&
	    (fname[1] == '\0' ||
	     (fname[1] == '.' && fname[2] == '\0')))
		return 0;

	/* check the pattern */
	list_path = t_strconcat(ctx->dir->virtual_path, fname, NULL);
	match = imap_match(ctx->glob, list_path);
	if (match != IMAP_MATCH_YES && (match & IMAP_MATCH_CHILDREN) == 0 &&
	    !ctx->dir->delayed_send)
		return 0;

	if (strcmp(fname, ctx->ctx.list->set.maildir_name) == 0) {
		/* mail storage's internal directory */
		return 0;
	}

	if (strcmp(fname, ctx->ctx.list->set.subscription_fname) == 0) {
		/* skip subscriptions file */
		root_dir = mailbox_list_get_path(ctx->ctx.list, NULL,
						 MAILBOX_LIST_PATH_TYPE_DIR);
		if (strcmp(root_dir, ctx->dir->real_path) == 0)
			return 0;
	}


	/* get the info.flags using callback */
	ret = ctx->ctx.list->v.
		get_mailbox_flags(ctx->ctx.list, ctx->dir->real_path, fname,
				  entry->type, &st, &ctx->info.flags);
	if (ret <= 0)
		return ret;

	if (ctx->dir->delayed_send) {
		/* send the parent directory first, then handle this
		   file again if needed */
		ctx->dir->delayed_send = FALSE;
		if (match == IMAP_MATCH_YES ||
		    (match & IMAP_MATCH_CHILDREN) != 0)
			ctx->dir->next_entry = entry;
		ctx->info = ctx->dir->info;
		ctx->info.flags |= MAILBOX_CHILDREN;
		return 1;
	}

	ctx->info.flags |= fs_list_get_subscription_flags(ctx, list_path);

	/* make sure we give only one correct INBOX */
	if ((ns->flags & NAMESPACE_FLAG_INBOX_USER) != 0) {
		if (strcasecmp(list_path, "INBOX") == 0) {
			if (!list_file_inbox(ctx, fname))
				return 0;
		} else if (strcasecmp(fname, "INBOX") == 0 &&
			   list_file_is_inbox(ctx, fname) &&
			   (ctx->info.flags & MAILBOX_CHILDREN) == 0) {
			/* This is the INBOX. Don't return it under the mailbox
			   prefix unless it has children. */
			return 0;
		}
	} else if ((ns->flags & NAMESPACE_FLAG_INBOX_ANY) != 0) {
		/* shared namespace */
		if (strcasecmp(fname, "INBOX") == 0 &&
		    list_file_is_inbox(ctx, fname)) {
			if (!list_file_inbox(ctx, fname))
				return 0;
		}
	}

	if ((ctx->info.flags & MAILBOX_NOINFERIORS) == 0)
		return list_file_subdir(ctx, match, list_path, fname);

	if (match == IMAP_MATCH_YES) {
		ctx->info.name = p_strdup(ctx->info_pool, list_path);
		return 1;
	}
	return 0;
}

static const struct mailbox_info *
fs_list_subs(struct fs_list_iterate_context *ctx)
{
	struct mailbox_node *node;
	enum mailbox_info_flags flags;
	struct mail_namespace *ns;
	const char *path, *dir, *fname, *storage_name;
	unsigned int len;
	struct stat st;

	node = mailbox_tree_iterate_next(ctx->tree_iter, &ctx->info.name);
	if (node == NULL)
		return NULL;

	/* subscription list has real knowledge of only subscription flags */
	flags = node->flags & (MAILBOX_SUBSCRIBED | MAILBOX_CHILD_SUBSCRIBED);

	if ((ctx->ctx.flags & MAILBOX_LIST_ITER_RETURN_NO_FLAGS) != 0 &&
	    (ctx->ctx.flags & MAILBOX_LIST_ITER_RETURN_CHILDREN) == 0) {
		ctx->info.flags = flags;
		return &ctx->info;
	}

	/* see if this is for another subscriptions=no namespace */
	storage_name = ctx->info.name;
	ns = mail_namespace_find_unsubscribable(ctx->info.ns->user->namespaces,
						&storage_name);
	if (ns == NULL) {
		ns = ctx->info.ns;
		storage_name = mail_namespace_get_storage_name(ns, storage_name);
	}

	/* if name ends with hierarchy separator, drop the separator */
	len = strlen(storage_name);
	if (len > 0 && storage_name[len-1] == ns->real_sep)
		storage_name = t_strndup(storage_name, len-1);

	if (!mailbox_list_is_valid_pattern(ns->list, storage_name)) {
		/* broken entry in subscriptions file */
		ctx->info.flags = MAILBOX_NONEXISTENT;
	} else {
		struct mailbox_list *list = ns->list;

		path = mailbox_list_get_path(list, storage_name,
					     MAILBOX_LIST_PATH_TYPE_DIR);
		path_split(path, &dir, &fname);
		if (list->v.get_mailbox_flags(list, dir, fname,
					      MAILBOX_LIST_FILE_TYPE_UNKNOWN,
					      &st, &ctx->info.flags) < 0)
			ctx->ctx.failed = TRUE;
	}

	ctx->info.flags |= flags;
	return &ctx->info;
}

static const struct list_dir_entry *
fs_list_dir_next(struct fs_list_iterate_context *ctx)
{
	struct list_dir_context *dir = ctx->dir;
	struct dirent *d;
	char *const *patterns;
	const char *fname, *path, *p;
	unsigned int pos;
	struct stat st;
	int ret;

	if (dir->dirp != NULL) {
		if (dir->next_entry != NULL) {
			const struct list_dir_entry *entry = dir->next_entry;
			dir->next_entry = NULL;
			return entry;
		}
		d = readdir(dir->dirp);
		if (d == NULL)
			return NULL;
		dir->entry.fname = d->d_name;
		dir->entry.type = mailbox_list_get_file_type(d);
		return &dir->entry;
	}

	for (;;) {
		patterns = array_idx(&ctx->valid_patterns, 0);
		if (patterns[dir->pattern_pos] == NULL)
			return NULL;

		patterns += dir->pattern_pos;
		dir->pattern_pos++;

		ret = pattern_get_path_pos(ctx, *patterns, dir->virtual_path,
					   &pos);
		if (ret == 0)
			continue;
		i_assert(ret > 0);

		/* get the filename from the pattern */
		p = strchr(*patterns + pos, ctx->sep);
		fname = p == NULL ? *patterns + pos :
			t_strdup_until(*patterns + pos, p);

		/* lstat() it to make sure it exists */
		path = t_strdup_printf("%s/%s", dir->real_path, fname);
		if (lstat(path, &st) < 0) {
			if (!ENOTFOUND(errno) && errno != EACCES &&
			    errno != ENAMETOOLONG)
				i_error("fs list: lstat(%s) failed: %m", path);
			continue;
		}

		if (S_ISREG(st.st_mode))
			dir->entry.type = MAILBOX_LIST_FILE_TYPE_FILE;
		else if (S_ISDIR(st.st_mode))
			dir->entry.type = MAILBOX_LIST_FILE_TYPE_DIR;
		else if (S_ISLNK(st.st_mode))
			dir->entry.type = MAILBOX_LIST_FILE_TYPE_SYMLINK;
		else
			dir->entry.type = MAILBOX_LIST_FILE_TYPE_UNKNOWN;
		i_free(dir->entry_fname);
		dir->entry.fname = dir->entry_fname = i_strdup(fname);
		break;
	}

	return &dir->entry;
}

static const struct mailbox_info *
fs_list_next(struct fs_list_iterate_context *ctx)
{
	struct list_dir_context *dir;
	const struct list_dir_entry *entry;
	int ret;

	if (ctx->dir == NULL || !ctx->dir->delayed_send)
		p_clear(ctx->info_pool);

	while (ctx->dir != NULL) {
		/* NOTE: list_file() may change ctx->dir */
		while ((entry = fs_list_dir_next(ctx)) != NULL) {
			T_BEGIN {
				ret = list_file(ctx, entry);
			} T_END;

			if (ret > 0)
				return &ctx->info;
			if (ret < 0) {
				ctx->ctx.failed = TRUE;
				return NULL;
			}
		}

		dir = ctx->dir;
		if (dir->delayed_send) {
			/* wanted to know if the mailbox had children.
			   it didn't. */
			dir->delayed_send = FALSE;
			ctx->info = dir->info;
			ctx->info.flags |= MAILBOX_NOCHILDREN;
			return &ctx->info;
		}

		ctx->dir = dir->prev;
		list_dir_context_free(dir);
	}

	if (!ctx->inbox_found &&
	    (ctx->ctx.list->ns->flags & NAMESPACE_FLAG_INBOX_ANY) != 0 &&
	    ((ctx->glob != NULL &&
	      imap_match(ctx->glob,
			 fs_list_get_inbox_vname(ctx)) == IMAP_MATCH_YES) ||
	     ctx->inbox_match)) {
		/* INBOX wasn't seen while listing other mailboxes. It might
		   be located elsewhere. */
		ctx->inbox_listed = TRUE;
		ctx->inbox_found = TRUE;
		return fs_list_inbox(ctx);
	}
	if (!ctx->inbox_listed && ctx->inbox_found) {
		/* INBOX was found, but we delayed listing it. Show it now. */
		ctx->inbox_listed = TRUE;
		ctx->info.flags = ctx->inbox_flags;
		ctx->info.name = "INBOX";
		return &ctx->info;
	}

	/* finished */
	return NULL;
}
