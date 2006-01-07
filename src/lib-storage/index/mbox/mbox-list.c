/* Copyright (C) 2002-2003 Timo Sirainen */

#include "lib.h"
#include "unlink-directory.h"
#include "imap-match.h"
#include "subscription-file/subscription-file.h"
#include "mbox-storage.h"
#include "home-expand.h"

#include <dirent.h>
#include <sys/stat.h>

#define STAT_GET_MARKED(st) \
	((st).st_size == 0 ? MAILBOX_UNMARKED : \
	 (st).st_atime < (st).st_mtime ? MAILBOX_MARKED : MAILBOX_UNMARKED)

struct list_dir_context {
	struct list_dir_context *prev;

	DIR *dirp;
	char *real_path, *virtual_path;
};

struct mbox_list_context {
	struct mailbox_list_context mailbox_ctx;
	struct index_storage *istorage;

	enum mailbox_list_flags flags;

	struct imap_match_glob *glob;
	struct subsfile_list_context *subsfile_ctx;

	int failed, inbox_found;

	struct mailbox_list *(*next)(struct mbox_list_context *ctx);

	pool_t list_pool;
	struct mailbox_list list;
        struct list_dir_context *dir;
};

static struct mailbox_list *mbox_list_subs(struct mbox_list_context *ctx);
static struct mailbox_list *mbox_list_path(struct mbox_list_context *ctx);
static struct mailbox_list *mbox_list_next(struct mbox_list_context *ctx);

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

static const char *
mbox_get_path(struct index_storage *storage, const char *name)
{
	if ((storage->storage.flags & MAIL_STORAGE_FLAG_FULL_FS_ACCESS) == 0 ||
	    name == NULL || (*name != '/' && *name != '~' && *name != '\0'))
		return t_strconcat(storage->dir, "/", name, NULL);
	else
		return home_expand(name);
}

static int list_opendir(struct mail_storage *storage,
			const char *path, int root, DIR **dirp)
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
		mail_storage_set_error(storage, "Access denied");
		return -1;
	}

	mail_storage_set_critical(storage, "opendir(%s) failed: %m", path);
	return -1;
}

struct mailbox_list_context *
mbox_mailbox_list_init(struct mail_storage *storage,
		       const char *ref, const char *mask,
		       enum mailbox_list_flags flags)
{
	struct index_storage *istorage = (struct index_storage *)storage;
	struct mbox_list_context *ctx;
	const char *path, *virtual_path;
	DIR *dirp;

	ctx = i_new(struct mbox_list_context, 1);
	ctx->mailbox_ctx.storage = storage;
	ctx->istorage = istorage;
	ctx->list_pool = pool_alloconly_create("mbox_list", 1024);
        ctx->next = mbox_list_next;

	mail_storage_clear_error(storage);

	/* check that we're not trying to do any "../../" lists */
	if (!mbox_is_valid_mask(storage, ref) ||
	    !mbox_is_valid_mask(storage, mask)) {
		mail_storage_set_error(storage, "Invalid mask");
		return &ctx->mailbox_ctx;
	}

	if (*mask == '/' || *mask == '~') {
		/* mask overrides reference */
	} else if (*ref != '\0') {
		/* merge reference and mask */
		if (ref[strlen(ref)-1] == '/')
			mask = t_strconcat(ref, mask, NULL);
		else
			mask = t_strconcat(ref, "/", mask, NULL);
	}

	if ((flags & MAILBOX_LIST_SUBSCRIBED) != 0) {
		ctx->mailbox_ctx.storage = storage;
		ctx->istorage = istorage;
		ctx->flags = flags;
		ctx->next = mbox_list_subs;

		path = t_strconcat(istorage->dir,
				   "/" SUBSCRIPTION_FILE_NAME, NULL);
		ctx->subsfile_ctx =
			subsfile_list_init(storage, path);
		if (ctx->subsfile_ctx == NULL) {
			ctx->next = mbox_list_next;
			ctx->failed = TRUE;
			return &ctx->mailbox_ctx;
		}
		ctx->glob = imap_match_init(default_pool, mask, TRUE, '/');
		return &ctx->mailbox_ctx;
	}

	/* if we're matching only subdirectories, don't bother scanning the
	   parent directories */
	virtual_path = mask_get_dir(mask);

	path = mbox_get_path(istorage, virtual_path);
	if (list_opendir(storage, path, TRUE, &dirp) < 0)
		return &ctx->mailbox_ctx;
	/* if user gave invalid directory, we just don't show any results. */

	ctx->flags = flags;
	ctx->glob = imap_match_init(default_pool, mask, TRUE, '/');

	if (virtual_path != NULL && dirp != NULL)
		ctx->next = mbox_list_path;

	if (dirp != NULL) {
		ctx->dir = i_new(struct list_dir_context, 1);
		ctx->dir->dirp = dirp;
		ctx->dir->real_path = i_strdup(path);
		ctx->dir->virtual_path = i_strdup(virtual_path);
	}
	return &ctx->mailbox_ctx;
}

static void list_dir_context_free(struct list_dir_context *dir)
{
	(void)closedir(dir->dirp);
	i_free(dir->real_path);
	i_free(dir->virtual_path);
	i_free(dir);
}

int mbox_mailbox_list_deinit(struct mailbox_list_context *_ctx)
{
	struct mbox_list_context *ctx = (struct mbox_list_context *)_ctx;
	int ret = ctx->failed ? -1 : 0;

	if (ctx->subsfile_ctx != NULL) {
		if (subsfile_list_deinit(ctx->subsfile_ctx) < 0)
			ret = -1;
	}

	while (ctx->dir != NULL) {
		struct list_dir_context *dir = ctx->dir;

		ctx->dir = dir->prev;
                list_dir_context_free(dir);
	}

	if (ctx->list_pool != NULL)
		pool_unref(ctx->list_pool);
	if (ctx->glob != NULL)
		imap_match_deinit(ctx->glob);
	i_free(ctx);

	return ret;
}

struct mailbox_list *mbox_mailbox_list_next(struct mailbox_list_context *_ctx)
{
	struct mbox_list_context *ctx = (struct mbox_list_context *)_ctx;

	return ctx->next(ctx);
}

static int list_file(struct mbox_list_context *ctx, const char *fname)
{
        struct list_dir_context *dir;
	const char *list_path, *real_path, *path;
	struct stat st;
	DIR *dirp;
	size_t len;
	enum imap_match_result match, match2;
	int ret, noselect;

	/* skip all hidden files */
	if (fname[0] == '.')
		return 0;

	/* skip all .lock files */
	len = strlen(fname);
	if (len > 5 && strcmp(fname+len-5, ".lock") == 0)
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

	/* see if it's a directory */
	real_path = t_strconcat(ctx->dir->real_path, "/", fname, NULL);
	if (stat(real_path, &st) == 0)
		noselect = FALSE;
	else if (errno == EACCES || errno == ELOOP)
		noselect = TRUE;
	else {
		if (ENOTFOUND(errno))
			return 0;
		mail_storage_set_critical(ctx->mailbox_ctx.storage,
					  "stat(%s) failed: %m", real_path);
		return -1;
	}

	/* make sure we give only one correct INBOX */
	if (strcasecmp(list_path, "INBOX") == 0 &&
	    (ctx->flags & MAILBOX_LIST_INBOX) != 0) {
		if (ctx->inbox_found ||
		    strcmp(real_path, ctx->istorage->inbox_path) != 0)
			return 0;

		ctx->inbox_found = TRUE;
	}

	if (!noselect && S_ISDIR(st.st_mode)) {
		/* subdirectory. scan inside it. */
		path = t_strconcat(list_path, "/", NULL);
		match2 = imap_match(ctx->glob, path);

		ctx->list.flags = MAILBOX_NOSELECT | MAILBOX_CHILDREN;
		if (match > 0)
			ctx->list.name = p_strdup(ctx->list_pool, list_path);
		else if (match2 > 0)
			ctx->list.name = p_strdup(ctx->list_pool, path);
		else
			ctx->list.name = NULL;

		ret = match2 < 0 ? 0 :
			list_opendir(ctx->mailbox_ctx.storage,
				     real_path, FALSE, &dirp);
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
		ctx->list.flags = noselect ? MAILBOX_NOSELECT :
			(MAILBOX_NOINFERIORS | STAT_GET_MARKED(st));
		ctx->list.name = p_strdup(ctx->list_pool, list_path);
		return 1;
	}

	return 0;
}

static struct mailbox_list *mbox_list_subs(struct mbox_list_context *ctx)
{
	struct stat st;
	const char *name, *path, *p;
	enum imap_match_result match = IMAP_MATCH_NO;

	while ((name = subsfile_list_next(ctx->subsfile_ctx)) != NULL) {
		match = imap_match(ctx->glob, name);
		if (match == IMAP_MATCH_YES || match == IMAP_MATCH_PARENT)
			break;
	}

	if (name == NULL)
		return NULL;

	ctx->list.flags = 0;
	ctx->list.name = name;

	if (match == IMAP_MATCH_PARENT) {
		/* placeholder */
		ctx->list.flags = MAILBOX_PLACEHOLDER;
		while ((p = strrchr(name, '/')) != NULL) {
			name = t_strdup_until(name, p);
			if (imap_match(ctx->glob, name) > 0) {
				p_clear(ctx->list_pool);
				ctx->list.name = p_strdup(ctx->list_pool, name);
				return &ctx->list;
			}
		}
		i_unreached();
	}

	if ((ctx->flags & MAILBOX_LIST_FAST_FLAGS) != 0)
		return &ctx->list;

	t_push();
	path = mbox_get_path(ctx->istorage, ctx->list.name);
	if (stat(path, &st) == 0) {
		if (S_ISDIR(st.st_mode))
			ctx->list.flags = MAILBOX_NOSELECT | MAILBOX_CHILDREN;
		else {
			ctx->list.flags = MAILBOX_NOINFERIORS |
				STAT_GET_MARKED(st);
		}
	} else {
		ctx->list.flags = MAILBOX_NONEXISTENT;
	}
	t_pop();
	return &ctx->list;
}

static struct mailbox_list *mbox_list_path(struct mbox_list_context *ctx)
{
	ctx->next = mbox_list_next;

	ctx->list.flags = MAILBOX_NOSELECT | MAILBOX_CHILDREN;
	ctx->list.name =
		p_strconcat(ctx->list_pool, ctx->dir->virtual_path, "/", NULL);

	if (imap_match(ctx->glob, ctx->list.name) > 0)
		return &ctx->list;
	else
		return ctx->next(ctx);
}

static struct mailbox_list *mbox_list_inbox(struct mbox_list_context *ctx)
{
	struct stat st;

	ctx->list.flags = MAILBOX_NOINFERIORS;
	ctx->list.name = "INBOX";

	if (stat(ctx->istorage->inbox_path, &st) == 0)
		ctx->list.flags |= STAT_GET_MARKED(st);
	else if (errno == EACCES || errno == ELOOP)
		ctx->list.flags = MAILBOX_NOSELECT;
	else if (ENOTFOUND(errno))
		ctx->list.flags |= MAILBOX_UNMARKED;
	else {
		mail_storage_set_critical(ctx->mailbox_ctx.storage,
			"stat(%s) failed: %m", ctx->istorage->inbox_path);
		ctx->failed = TRUE;
		return NULL;
	}

	return &ctx->list;
}

static struct mailbox_list *mbox_list_next(struct mbox_list_context *ctx)
{
	struct list_dir_context *dir;
	struct dirent *d;
	int ret;

	p_clear(ctx->list_pool);

	while (ctx->dir != NULL) {
		/* NOTE: list_file() may change ctx->dir */
		while ((d = readdir(ctx->dir->dirp)) != NULL) {
			t_push();
			ret = list_file(ctx, d->d_name);
			t_pop();

			if (ret > 0)
				return &ctx->list;
			if (ret < 0) {
				ctx->failed = TRUE;
				return NULL;
			}
		}

		dir = ctx->dir;
		ctx->dir = dir->prev;
		list_dir_context_free(dir);
	}

	if (!ctx->inbox_found && (ctx->flags & MAILBOX_LIST_INBOX) != 0 &&
	    ctx->glob != NULL && imap_match(ctx->glob, "INBOX")  > 0) {
		/* show inbox */
		ctx->inbox_found = TRUE;
		return mbox_list_inbox(ctx);
	}

	/* finished */
	return NULL;
}
