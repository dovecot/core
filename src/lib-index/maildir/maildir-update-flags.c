/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "hash.h"
#include "ioloop.h"
#include "maildir-index.h"
#include "mail-index-util.h"
#include "mail-cache.h"

#include <stdio.h>
#include <sys/stat.h>

struct update_flags_ctx {
	const char *new_fname;
	int found;

        enum modify_type modify_type;
	enum mail_flags flags;
};

static int update_filename(struct mail_index *index,
			   struct mail_index_record *rec)
{
	const char *old_fname, *old_path, *new_fname, *new_path;
	enum mail_index_record_flag flags;

	old_fname = maildir_get_location(index, rec, NULL);
	if (old_fname == NULL)
		return -1;

	flags = mail_cache_get_index_flags(index->cache, rec);

	old_path = t_strconcat(index->mailbox_path,
			       (flags & MAIL_INDEX_FLAG_MAILDIR_NEW) != 0 ?
			       "/new/" : "/cur/", old_fname, NULL);

	new_fname = maildir_filename_set_flags(old_fname, rec->msg_flags);
	new_path = t_strconcat(index->mailbox_path, "/cur/", new_fname, NULL);

	if (strcmp(old_path, new_path) == 0 ||
	    rename(old_path, new_path) == 0) {
		flags &= ~(MAIL_INDEX_FLAG_DIRTY | MAIL_INDEX_FLAG_MAILDIR_NEW);
		if (!mail_cache_update_index_flags(index->cache, rec, flags))
			return -1;
		return 1;
	} else {
		if (errno != ENOENT && errno != EACCES &&
		    !ENOSPACE(errno)) {
			index_set_error(index,
					"rename(%s, %s) failed: %m",
					old_path, new_path);
			return -1;
		}
		return 0;
	}
}

int maildir_try_flush_dirty_flags(struct mail_index *index, int force)
{
	struct mail_index_record *rec;
	int ret, dirty = FALSE;

	if (index->next_dirty_flags_flush == 0 ||
	    (ioloop_time < index->next_dirty_flags_flush && !force))
		return TRUE;

	if (!index->set_lock(index, MAIL_LOCK_EXCLUSIVE))
		return FALSE;

	ret = mail_cache_lock(index->cache, !force);
	if (ret <= 0)
		return ret == 0;
        mail_cache_unlock_later(index->cache);

	rec = index->lookup(index, 1);
	while (rec != NULL) {
		if ((mail_cache_get_index_flags(index->cache, rec) &
		     MAIL_INDEX_FLAG_DIRTY) != 0) {
			ret = update_filename(index, rec);
			if (ret < 0)
				break;
			if (ret == 0)
				dirty = TRUE;
		}

		rec = index->next(index, rec);
	}

	if (ret < 0)
		return FALSE;

	if (!dirty) {
		index->header->flags &= ~MAIL_INDEX_HDR_FLAG_DIRTY_MESSAGES;
		index->next_dirty_flags_flush = 0;
	} else {
		index->next_dirty_flags_flush =
			ioloop_time + MAILDIR_DIRTY_FLUSH_TIMEOUT;
	}

	return TRUE;
}

static int do_rename(struct mail_index *index, const char *path, void *context)
{
	struct update_flags_ctx *ctx = context;
	const char *fname, *new_path;
	enum mail_flags old_flags, new_flags;
	int new_dir;

        old_flags = maildir_filename_get_flags(path, 0);
	switch (ctx->modify_type) {
	case MODIFY_ADD:
		new_flags = old_flags | ctx->flags;
		break;
	case MODIFY_REMOVE:
		new_flags = old_flags & ~ctx->flags;
		break;
	case MODIFY_REPLACE:
		new_flags = ctx->flags;
		break;
	default:
		new_flags = 0;
		i_unreached();
	}

	fname = strrchr(path, '/');
	ctx->new_fname = maildir_filename_set_flags(fname != NULL ?
						    fname+1 : path, new_flags);

	if (old_flags == new_flags) {
		/* it's what we wanted. verify that the file exists. */
		struct stat st;

		if (stat(path, &st) < 0) {
			if (errno == ENOENT)
				return 0;
			index_file_set_syscall_error(index, path, "stat()");
			return -1;
		}
		ctx->found = TRUE;
		return 1;
	}

	new_dir = fname != NULL && path + 4 <= fname &&
		strncmp(fname-4, "/new", 4) == 0;
	if (new_dir) {
		/* move from new/ to cur/ */
		new_path = t_strconcat(t_strdup_until(path, fname-4),
				       "/cur/", ctx->new_fname, NULL);
	} else {
		new_path = maildir_filename_set_flags(path, new_flags);
	}

	if (rename(path, new_path) < 0) {
		if (errno == ENOENT)
			return 0;

		if (ENOSPACE(errno)) {
			index->nodiskspace = TRUE;
			return 1;
		}

		if (errno == EACCES) {
			index->mailbox_readonly = TRUE;
			return 1;
		}

		index_set_error(index, "rename(%s, %s) failed: %m",
				path, new_path);
		return -1;
	}

	if (index->maildir_keep_new && new_dir) {
		/* looks like we have some more space again, see if we could
		   move mails from new/ to cur/ again */
		index->maildir_keep_new = FALSE;
	}

	/* cur/ was updated, set it dirty-synced */
	index->sync_stamp = ioloop_time;
	index->sync_dirty_stamp = ioloop_time;
	ctx->found = TRUE;
	return 1;
}

int maildir_index_update_flags(struct mail_index *index,
			       struct mail_index_record *rec, unsigned int seq,
			       enum modify_type modify_type,
			       enum mail_flags flags, int external_change)
{
	struct update_flags_ctx ctx;
        enum mail_index_record_flag index_flags;

	memset(&ctx, 0, sizeof(ctx));
	ctx.modify_type = modify_type;
	ctx.flags = flags;

	t_push();
	if (!maildir_file_do(index, rec, do_rename, &ctx)) {
		t_pop();
		return FALSE;
	}

	if (!ctx.found) {
		/* we couldn't actually rename() the file now.
		   leave it's flags dirty so they get changed later. */
		index_flags = mail_cache_get_index_flags(index->cache, rec);
		if ((index_flags & MAIL_INDEX_FLAG_DIRTY) == 0) {
			if (mail_cache_lock(index->cache, FALSE) <= 0)
				return FALSE;
			mail_cache_unlock_later(index->cache);

			index_flags |= MAIL_INDEX_FLAG_DIRTY;
			mail_cache_update_index_flags(index->cache, rec,
						      index_flags);

			index->header->flags |=
				MAIL_INDEX_HDR_FLAG_DIRTY_MESSAGES;
		}

		index->next_dirty_flags_flush =
			ioloop_time + MAILDIR_DIRTY_FLUSH_TIMEOUT;
	} else if (ctx.new_fname != NULL) {
		maildir_index_update_filename(index, rec->uid,
					      ctx.new_fname, FALSE);
	}
	t_pop();

	return mail_index_update_flags(index, rec, seq,
				       modify_type, flags, external_change);
}
