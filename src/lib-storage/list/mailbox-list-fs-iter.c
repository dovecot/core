/* Copyright (C) 2002-2006 Timo Sirainen */

#include "lib.h"
#include "home-expand.h"
#include "unlink-directory.h"
#include "imap-match.h"
#include "subscription-file.h"
#include "mailbox-list-fs.h"

#include <dirent.h>

struct list_dir_context {
	struct list_dir_context *prev;

	DIR *dirp;
	char *real_path, *virtual_path;
};

struct fs_list_iterate_context {
	struct mailbox_list_iterate_context ctx;

	struct imap_match_glob *glob;
	struct subsfile_list_context *subsfile_ctx;

	bool inbox_found, inbox_listed;
	enum mailbox_info_flags inbox_flags;

	struct mailbox_info *(*next)(struct fs_list_iterate_context *ctx);

	pool_t info_pool;
	struct mailbox_info info;
        struct list_dir_context *dir;
};

static struct mailbox_info *fs_list_subs(struct fs_list_iterate_context *ctx);
static struct mailbox_info *fs_list_path(struct fs_list_iterate_context *ctx);
static struct mailbox_info *fs_list_next(struct fs_list_iterate_context *ctx);

static const char *mask_get_dir(const char *mask)
{
	const char *p, *last_dir;

	last_dir = NULL;
	for (p = mask; *p != '\0' && *p != '%' && *p != '*'; p++) {
		if (*p == '/')
			last_dir = p;
	}

	return last_dir == NULL ? NULL : t_strdup_until(mask, last_dir);
}

static int list_opendir(struct mailbox_list *list,
			const char *path, bool root, DIR **dirp)
{
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
		if (!root) {
			/* subfolder, ignore */
			return 0;
		}
		mailbox_list_set_error(list, "Access denied");
		return -1;
	}

	mailbox_list_set_critical(list, "opendir(%s) failed: %m", path);
	return -1;
}

struct mailbox_list_iterate_context *
fs_list_iter_init(struct mailbox_list *_list, const char *mask,
		  enum mailbox_list_iter_flags flags)
{
	struct fs_list_iterate_context *ctx;
	const char *path, *virtual_path;
	DIR *dirp;

	ctx = i_new(struct fs_list_iterate_context, 1);
	ctx->ctx.list = _list;
	ctx->ctx.flags = flags;
	ctx->info_pool = pool_alloconly_create("fs list", 1024);
        ctx->next = fs_list_next;

	/* check that we're not trying to do any "../../" lists */
	if (!mailbox_list_is_valid_mask(_list, mask)) {
		mailbox_list_set_error(_list, "Invalid mask");
		ctx->ctx.failed = TRUE;
		return &ctx->ctx;
	}

	if ((flags & MAILBOX_LIST_ITER_SUBSCRIBED) != 0) {
		ctx->next = fs_list_subs;

		path = t_strconcat(_list->set.control_dir != NULL ?
				   _list->set.control_dir : _list->set.root_dir,
				   "/", _list->set.subscription_fname, NULL);
		ctx->subsfile_ctx = subsfile_list_init(_list, path);
		if (ctx->subsfile_ctx == NULL) {
			ctx->next = fs_list_next;
			ctx->ctx.failed = TRUE;
			return &ctx->ctx;
		}
		ctx->glob = imap_match_init(default_pool, mask, TRUE, '/');
		return &ctx->ctx;
	}

	/* if we're matching only subdirectories, don't bother scanning the
	   parent directories */
	virtual_path = mask_get_dir(mask);

	path = mailbox_list_get_path(_list, virtual_path,
				     MAILBOX_LIST_PATH_TYPE_DIR);
	if (list_opendir(_list, path, TRUE, &dirp) < 0)
		return &ctx->ctx;
	/* if user gave invalid directory, we just don't show any results. */

	ctx->ctx.flags = flags;
	ctx->glob = imap_match_init(default_pool, mask, TRUE, '/');

	if (virtual_path != NULL && dirp != NULL)
		ctx->next = fs_list_path;

	if (dirp != NULL) {
		ctx->dir = i_new(struct list_dir_context, 1);
		ctx->dir->dirp = dirp;
		ctx->dir->real_path = i_strdup(path);
		ctx->dir->virtual_path = i_strdup(virtual_path);
	}
	return &ctx->ctx;
}

static void list_dir_context_free(struct list_dir_context *dir)
{
	(void)closedir(dir->dirp);
	i_free(dir->real_path);
	i_free(dir->virtual_path);
	i_free(dir);
}

int fs_list_iter_deinit(struct mailbox_list_iterate_context *_ctx)
{
	struct fs_list_iterate_context *ctx =
		(struct fs_list_iterate_context *)_ctx;

	int ret = ctx->ctx.failed ? -1 : 0;

	if (ctx->subsfile_ctx != NULL) {
		if (subsfile_list_deinit(ctx->subsfile_ctx) < 0)
			ret = -1;
	}

	while (ctx->dir != NULL) {
		struct list_dir_context *dir = ctx->dir;

		ctx->dir = dir->prev;
                list_dir_context_free(dir);
	}

	if (ctx->info_pool != NULL)
		pool_unref(ctx->info_pool);
	if (ctx->glob != NULL)
		imap_match_deinit(&ctx->glob);
	i_free(ctx);

	return ret;
}

struct mailbox_info *
fs_list_iter_next(struct mailbox_list_iterate_context *_ctx)
{
	struct fs_list_iterate_context *ctx =
		(struct fs_list_iterate_context *)_ctx;

	if (ctx->ctx.failed)
		return NULL;

	return ctx->next(ctx);
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

static struct mailbox_info *fs_list_inbox(struct fs_list_iterate_context *ctx)
{
	const char *inbox_path, *dir, *fname;

	ctx->info.flags = 0;
	ctx->info.name = "INBOX";

	t_push();
	inbox_path = mailbox_list_get_path(ctx->ctx.list, "INBOX",
					   MAILBOX_LIST_PATH_TYPE_DIR);
	path_split(inbox_path, &dir, &fname);
	if (ctx->ctx.list->v.iter_is_mailbox(&ctx->ctx, dir, fname,
					     MAILBOX_LIST_FILE_TYPE_UNKNOWN,
					     &ctx->info.flags) < 0)
		ctx->ctx.failed = TRUE;
	t_pop();

	return &ctx->info;
}

static int
list_file(struct fs_list_iterate_context *ctx, const struct dirent *d)
{
	const char *fname = d->d_name;
	struct list_dir_context *dir;
	const char *list_path, *real_path, *path, *inbox_path;
	DIR *dirp;
	enum imap_match_result match, match2;
	int ret;

	/* skip . and .. */
	if (fname[0] == '.' &&
	    (fname[1] == '\0' ||
	     (fname[1] == '.' && fname[2] == '\0')))
		return 0;

	/* check the mask */
	if (ctx->dir->virtual_path == NULL)
		list_path = fname;
	else {
		list_path = t_strconcat(ctx->dir->virtual_path,
					"/", fname, NULL);
	}

	if ((match = imap_match(ctx->glob, list_path)) < 0)
		return 0;

	/* get the info.flags using callback */
	ctx->info.flags = 0;
	ret = ctx->ctx.list->v.
		iter_is_mailbox(&ctx->ctx, ctx->dir->real_path, fname,
				mailbox_list_get_file_type(d),
				&ctx->info.flags);
	if (ret <= 0)
		return ret;

	/* make sure we give only one correct INBOX */
	real_path = t_strconcat(ctx->dir->real_path, "/", fname, NULL);
	if (ctx->ctx.list->ns->inbox && strcasecmp(list_path, "INBOX") == 0) {
		if (ctx->inbox_listed) {
			/* already listed the INBOX */
			return 0;
		}

		inbox_path = mailbox_list_get_path(ctx->ctx.list, "INBOX",
						   MAILBOX_LIST_PATH_TYPE_DIR);
		if (strcmp(real_path, inbox_path) == 0) {
			/* delay listing in case there's a INBOX/ directory */
			ctx->inbox_found = TRUE;
			ctx->inbox_flags = ctx->info.flags;
			return 0;
		}
		if (strcmp(fname, "INBOX") != 0 ||
		    (ctx->info.flags & MAILBOX_NOINFERIORS) != 0) {
			/* duplicate INBOX, can't show this */
			return 0;
		}

		/* INBOX/ directory. show the INBOX list now */
		if (!ctx->inbox_found) {
			enum mailbox_info_flags dir_flags = ctx->info.flags;

			(void)fs_list_inbox(ctx);
			ctx->info.flags &= ~(MAILBOX_NOINFERIORS |
					     MAILBOX_NOCHILDREN);
			ctx->info.flags |= dir_flags;
			ctx->inbox_found = TRUE;
		} else {
			ctx->info.flags &= ~MAILBOX_NOSELECT;
			ctx->info.flags |= ctx->inbox_flags;
		}
		ctx->inbox_listed = TRUE;
	}

	if ((ctx->info.flags & MAILBOX_NOINFERIORS) == 0) {
		/* subdirectory. scan inside it. */
		path = t_strconcat(list_path, "/", NULL);
		match2 = imap_match(ctx->glob, path);

		if (match > 0)
			ctx->info.name = p_strdup(ctx->info_pool, list_path);
		else if (match2 > 0)
			ctx->info.name = p_strdup(ctx->info_pool, path);
		else
			ctx->info.name = NULL;

		ret = match2 < 0 ? 0 :
			list_opendir(ctx->ctx.list, real_path, FALSE, &dirp);
		if (ret > 0) {
			dir = i_new(struct list_dir_context, 1);
			dir->dirp = dirp;
			dir->real_path = i_strdup(real_path);
			dir->virtual_path = i_strdup(list_path);

			dir->prev = ctx->dir;
			ctx->dir = dir;
		} else if (ret < 0)
			return -1;
		return match > 0 || match2 > 0;
	} else if (match > 0) {
		ctx->info.name = p_strdup(ctx->info_pool, list_path);
		return 1;
	}

	return 0;
}

static struct mailbox_info *fs_list_subs(struct fs_list_iterate_context *ctx)
{
	const char *name, *path, *p, *dir, *fname;
	enum imap_match_result match = IMAP_MATCH_NO;

	while ((name = subsfile_list_next(ctx->subsfile_ctx)) != NULL) {
		match = imap_match(ctx->glob, name);
		if (match == IMAP_MATCH_YES || match == IMAP_MATCH_PARENT)
			break;
	}

	if (name == NULL)
		return NULL;

	ctx->info.flags = 0;
	ctx->info.name = name;

	if (match == IMAP_MATCH_PARENT) {
		/* placeholder */
		ctx->info.flags = MAILBOX_NONEXISTENT | MAILBOX_CHILDREN;
		while ((p = strrchr(name, '/')) != NULL) {
			name = t_strdup_until(name, p);
			if (imap_match(ctx->glob, name) > 0) {
				p_clear(ctx->info_pool);
				ctx->info.name = p_strdup(ctx->info_pool, name);
				return &ctx->info;
			}
		}
		i_unreached();
	}

	if ((ctx->ctx.flags & MAILBOX_LIST_ITER_FAST_FLAGS) != 0)
		return &ctx->info;

	t_push();
	path = mailbox_list_get_path(ctx->ctx.list, ctx->info.name,
				     MAILBOX_LIST_PATH_TYPE_DIR);
	path_split(path, &dir, &fname);
	if (ctx->ctx.list->v.iter_is_mailbox(&ctx->ctx, dir, fname,
					     MAILBOX_LIST_FILE_TYPE_UNKNOWN,
					     &ctx->info.flags) < 0)
		ctx->ctx.failed = TRUE;
	t_pop();
	return &ctx->info;
}

static struct mailbox_info *fs_list_path(struct fs_list_iterate_context *ctx)
{
	ctx->next = fs_list_next;

	ctx->info.flags = MAILBOX_NOSELECT | MAILBOX_CHILDREN;
	ctx->info.name =
		p_strconcat(ctx->info_pool, ctx->dir->virtual_path, "/", NULL);

	if (imap_match(ctx->glob, ctx->info.name) > 0)
		return &ctx->info;
	else
		return ctx->next(ctx);
}

static struct mailbox_info *fs_list_next(struct fs_list_iterate_context *ctx)
{
	struct list_dir_context *dir;
	struct dirent *d;
	int ret;

	p_clear(ctx->info_pool);

	while (ctx->dir != NULL) {
		/* NOTE: list_file() may change ctx->dir */
		while ((d = readdir(ctx->dir->dirp)) != NULL) {
			t_push();
			ret = list_file(ctx, d);
			t_pop();

			if (ret > 0)
				return &ctx->info;
			if (ret < 0) {
				ctx->ctx.failed = TRUE;
				return NULL;
			}
		}

		dir = ctx->dir;
		ctx->dir = dir->prev;
		list_dir_context_free(dir);
	}

	if (!ctx->inbox_found && ctx->ctx.list->ns->inbox &&
	    ctx->glob != NULL && imap_match(ctx->glob, "INBOX") > 0) {
		/* show inbox */
		ctx->inbox_listed = TRUE;
		ctx->inbox_found = TRUE;
		return fs_list_inbox(ctx);
	}
	if (!ctx->inbox_listed && ctx->inbox_found) {
		ctx->inbox_listed = TRUE;
		ctx->info.flags = ctx->inbox_flags;
		ctx->info.name = "INBOX";
		return &ctx->info;
	}

	/* finished */
	return NULL;
}
