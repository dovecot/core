/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "hostpid.h"
#include "home-expand.h"
#include "unlink-directory.h"
#include "imap-match.h"
#include "subscription-file/subscription-file.h"
#include "maildir-index.h"
#include "maildir-storage.h"

#include <dirent.h>
#include <sys/stat.h>

struct mailbox_list_context {
	pool_t pool, list_pool;

	struct mail_storage *storage;
	const char *dir, *prefix;
        enum mailbox_list_flags flags;

	DIR *dirp;
	struct imap_match_glob *glob;
	struct subsfile_list_context *subsfile_ctx;

	struct mailbox_list *(*next)(struct mailbox_list_context *ctx);

	struct mailbox_list list;
	int found_inbox, failed;
};

static struct mailbox_list *maildir_list_subs(struct mailbox_list_context *ctx);
static struct mailbox_list *maildir_list_next(struct mailbox_list_context *ctx);

static enum mailbox_flags
maildir_get_marked_flags_from(const char *dir, time_t index_stamp)
{
	struct stat st;
	char path[PATH_MAX];
	time_t cur_stamp;

	if (str_path(path, sizeof(path), dir, "cur") < 0 ||
	    stat(path, &st) < 0) {
		/* no cur/ directory - broken */
		return 0;
	}

	cur_stamp = st.st_mtime;
	if (cur_stamp != index_stamp) {
		/* changes in cur directory */
		return MAILBOX_MARKED;
	}

	if (str_path(path, sizeof(path), dir, "new") < 0 ||
	    stat(path, &st) < 0) {
		/* no new/ directory - broken */
		return 0;
	}

	return st.st_mtime <= cur_stamp ? MAILBOX_UNMARKED : MAILBOX_MARKED;
}

static enum mailbox_flags
maildir_get_marked_flags(struct mail_storage *storage, const char *dir)
{
	const char *path;
	struct stat st;

	hostpid_init();

	/* first try to use .imap.index-hostname */
	path = t_strconcat(dir, "/" INDEX_FILE_PREFIX "-", my_hostname, NULL);
	if (stat(path, &st) == -1 && errno == ENOENT) {
		/* fallback to .imap.index */
		path = t_strconcat(dir, "/" INDEX_FILE_PREFIX, NULL);
	}

	if (stat(path, &st) == -1) {
		/* error, or index simply isn't created yet */
		if (errno != ENOENT) {
			mail_storage_set_critical(storage,
						  "stat(%s) failed: %m", path);
		}
		return 0;
	}

	return maildir_get_marked_flags_from(dir, st.st_mtime);
}

struct mailbox_list_context *
maildir_list_mailbox_init(struct mail_storage *storage,
			  const char *mask, enum mailbox_list_flags flags,
			  int *sorted)
{
        struct mailbox_list_context *ctx;
	pool_t pool;
	const char *dir, *p;

	*sorted = FALSE;
	mail_storage_clear_error(storage);

	pool = pool_alloconly_create("maildir_list", 1024);
	ctx = p_new(pool, struct mailbox_list_context, 1);
	ctx->pool = pool;
	ctx->storage = storage;
	ctx->flags = flags;

	if ((flags & MAILBOX_LIST_SUBSCRIBED) != 0) {
		ctx->glob = imap_match_init(pool, mask, TRUE, '.');
		ctx->subsfile_ctx = subsfile_list_init(storage);
		ctx->next = maildir_list_subs;
		if (ctx->subsfile_ctx == NULL) {
			pool_unref(pool);
			return NULL;
		}
		return ctx;
	}

	if (!full_filesystem_access || (p = strrchr(mask, '/')) == NULL) {
		ctx->dir = storage->dir;
		ctx->prefix = "";
	} else {
		p = strchr(p, storage->hierarchy_sep);
		if (p == NULL) {
			/* this isn't going to work */
			mail_storage_set_error(storage, "Invalid list mask");
			pool_unref(pool);
			return FALSE;
		}

		dir = t_strdup_until(mask, p);
		ctx->prefix = t_strdup_until(mask, p+1);

		if (*mask != '/' && *mask != '~')
			dir = t_strconcat(storage->dir, "/", dir, NULL);
		ctx->dir = p_strdup(pool, home_expand(dir));
	}

	ctx->dirp = opendir(ctx->dir);
	if (ctx->dirp == NULL) {
		mail_storage_set_critical(storage, "opendir(%s) failed: %m",
					  ctx->dir);
		pool_unref(pool);
		return NULL;
	}

	ctx->list_pool = pool_alloconly_create("maildir_list.list", 4096);
	ctx->glob = imap_match_init(pool, mask, TRUE, '.');
	ctx->next = maildir_list_next;
	return ctx;
}

int maildir_list_mailbox_deinit(struct mailbox_list_context *ctx)
{
	int failed;

	if (ctx->subsfile_ctx != NULL)
		failed = !subsfile_list_deinit(ctx->subsfile_ctx);
	else
		failed = ctx->failed;

	if (ctx->dirp != NULL)
		(void)closedir(ctx->dirp);
	if (ctx->list_pool != NULL)
		pool_unref(ctx->list_pool);
	imap_match_deinit(ctx->glob);
	pool_unref(ctx->pool);

	return !failed;
}

static struct mailbox_list *maildir_list_subs(struct mailbox_list_context *ctx)
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

	if ((ctx->flags & MAILBOX_LIST_NO_FLAGS) != 0)
		return &ctx->list;

	if (match == IMAP_MATCH_PARENT) {
		/* placeholder */
		ctx->list.flags = MAILBOX_NOSELECT;
		while ((p = strrchr(name, '.')) != NULL) {
			name = t_strdup_until(name, p);
			if (imap_match(ctx->glob, name) > 0) {
				ctx->list.name = name;
				return &ctx->list;
			}
		}
		i_unreached();
	}

	t_push();
	path = maildir_get_path(ctx->storage, ctx->list.name);
	if (stat(path, &st) == 0 && S_ISDIR(st.st_mode))
		ctx->list.flags = maildir_get_marked_flags(ctx->storage, path);
	else {
		if (strcasecmp(ctx->list.name, "INBOX") == 0)
			ctx->list.flags = 0;
		else
			ctx->list.flags = MAILBOX_NOSELECT;
	}
	t_pop();
	return &ctx->list;
}

static struct mailbox_list *maildir_list_next(struct mailbox_list_context *ctx)
{
	struct dirent *d;
	struct stat st;
	char path[PATH_MAX];
	int ret;

	if (ctx->dirp == NULL)
		return NULL;

	while ((d = readdir(ctx->dirp)) != NULL) {
		const char *fname = d->d_name;

		if (fname[0] != '.')
			continue;

		/* skip . and .. */
		if (fname[1] == '\0' || (fname[1] == '.' && fname[2] == '\0'))
			continue;

		/* make sure the mask matches - dirs beginning with ".."
		   should be deleted and we always want to check those. */
		t_push();
		ret = imap_match(ctx->glob,
				 t_strconcat(ctx->prefix, fname+1, NULL));
		t_pop();
		if (fname[1] == '.' || ret <= 0)
			continue;

		if (str_path(path, sizeof(path), ctx->dir, fname) < 0)
			continue;

		/* make sure it's a directory */
		if (stat(path, &st) < 0) {
			if (errno == ENOENT)
				continue; /* just deleted, ignore */

			mail_storage_set_critical(ctx->storage,
						  "stat(%s) failed: %m", path);
			ctx->failed = TRUE;
			return NULL;
		}

		if (!S_ISDIR(st.st_mode))
			continue;

		if (fname[1] == '.') {
			/* this mailbox is in the middle of being deleted,
			   or the process trying to delete it had died.

			   delete it ourself if it's been there longer than
			   one hour */
			if (st.st_mtime < 3600)
				(void)unlink_directory(path, TRUE);
			continue;
		}

		if (strcasecmp(fname+1, "INBOX") == 0) {
			if (ctx->found_inbox) {
				/* another inbox, ignore it */
				continue;
			}
			ctx->found_inbox = TRUE;
		}

		p_clear(ctx->list_pool);
		if ((ctx->flags & MAILBOX_LIST_NO_FLAGS) == 0) {
			ctx->list.flags =
				maildir_get_marked_flags(ctx->storage, path);
		}
		ctx->list.name = p_strconcat(ctx->list_pool,
					     ctx->prefix, fname+1, NULL);
		return &ctx->list;
	}

	if (closedir(ctx->dirp) < 0) {
		mail_storage_set_critical(ctx->storage,
					  "closedir(%s) failed: %m", ctx->dir);
		ctx->failed = TRUE;
	}
	ctx->dirp = NULL;

	if (!ctx->found_inbox && imap_match(ctx->glob, "INBOX") > 0) {
		/* .INBOX directory doesn't exist yet, but INBOX still exists */
		ctx->list.flags = 0;
		ctx->list.name = "INBOX";
		return &ctx->list;
	}

	/* we're finished */
	return NULL;
}

struct mailbox_list *
maildir_list_mailbox_next(struct mailbox_list_context *ctx)
{
	return ctx->next(ctx);
}
