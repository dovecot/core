/* Copyright (C) 2004 Timo Sirainen */

/*
   Here's a description of how we handle Maildir synchronization and
   it's problems:

   We want to be as efficient as we can. The most efficient way to
   check if changes have occured is to stat() the new/ and cur/
   directories and uidlist file - if their mtimes haven't changed,
   there's no changes and we don't need to do anything.

   Problem 1: Multiple changes can happen within a single second -
   nothing guarantees that once we synced it, someone else didn't just
   then make a modification. Such modifications wouldn't get noticed
   until a new modification occured later.

   Problem 2: Syncing cur/ directory is much more costly than syncing
   new/. Moving mails from new/ to cur/ will always change mtime of
   cur/ causing us to sync it as well.

   Problem 3: We may not be able to move mail from new/ to cur/
   because we're out of quota, or simply because we're accessing a
   read-only mailbox.


   MAILDIR_SYNC_SECS
   -----------------

   Several checks below use MAILDIR_SYNC_SECS, which should be maximum
   clock drift between all computers accessing the maildir (eg. via
   NFS), rounded up to next second. Our default is 1 second, since
   everyone should be using NTP.

   Note that setting it to 0 works only if there's only one computer
   accessing the maildir. It's practically impossible to make two
   clocks _exactly_ synchronized.

   It might be possible to only use file server's clock by looking at
   the atime field, but I don't know how well that would actually work.

   cur directory
   -------------

   We have dirty_cur_time variable which is set to cur/ directory's
   mtime when it's >= time() - MAILDIR_SYNC_SECS and we _think_ we have
   synchronized the directory.

   When dirty_cur_time is non-zero, we don't synchronize the cur/
   directory until

      a) cur/'s mtime changes
      b) opening a mail fails with ENOENT
      c) time() > dirty_cur_time + MAILDIR_SYNC_SECS

   This allows us to modify the maildir multiple times without having
   to sync it at every change. The sync will eventually be done to
   make sure we didn't miss any external changes.

   The dirty_cur_time is set when:

      - we change message flags
      - we expunge messages
      - we move mail from new/ to cur/
      - we sync cur/ directory and it's mtime is >= time() - MAILDIR_SYNC_SECS

   It's unset when we do the final syncing, ie. when mtime is
   older than time() - MAILDIR_SYNC_SECS.

   new directory
   -------------

   If new/'s mtime is >= time() - MAILDIR_SYNC_SECS, always synchronize
   it. dirty_cur_time-like feature might save us a few syncs, but
   that might break a client which saves a mail in one connection and
   tries to fetch it in another one. new/ directory is almost always
   empty, so syncing it should be very fast anyway. Actually this can
   still happen if we sync only new/ dir while another client is also
   moving mails from it to cur/ - it takes us a while to see them.
   That's pretty unlikely to happen however, and only way to fix it
   would be to always synchronize cur/ after new/.

   Normally we move all mails from new/ to cur/ whenever we sync it. If
   it's not possible for some reason, we mark the mail with "probably
   exists in new/ directory" flag.

   If rename() still fails because of ENOSPC or EDQUOT, we still save
   the flag changes in index with dirty-flag on. When moving the mail
   to cur/ directory, or when we notice it's already moved there, we
   apply the flag changes to the filename, rename it and remove the
   dirty flag. If there's dirty flags, this should be tried every time
   after expunge or when closing the mailbox.

   uidlist
   -------

   This file contains UID <-> filename mappings. It's updated only when
   new mail arrives, so it may contain filenames that have already been
   deleted. Updating is done by getting uidlist.lock file, writing the
   whole uidlist into it and rename()ing it over the old uidlist. This
   means there's no need to lock the file for reading.

   Whenever uidlist is rewritten, it's mtime must be larger than the old
   one's. Use utime() before rename() if needed. Note that inode checking
   wouldn't have been sufficient as inode numbers can be reused.

   This file is usually read the first time you need to know filename for
   given UID. After that it's not re-read unless new mails come that we
   don't know about.

   broken clients
   --------------

   Originally the middle identifier in Maildir filename was specified
   only as <process id>_<delivery counter>. That however created a
   problem with randomized PIDs which made it possible that the same
   PID was reused within one second.

   So if within one second a mail was delivered, MUA moved it to cur/
   and another mail was delivered by a new process using same PID as
   the first one, we likely ended up overwriting the first mail when
   the second mail was moved over it.

   Nowadays everyone should be giving a bit more specific identifier,
   for example include microseconds in it which Dovecot does.

   There's a simple way to prevent this from happening in some cases:
   Don't move the mail from new/ to cur/ if it's mtime is >= time() -
   MAILDIR_SYNC_SECS. The second delivery's link() call then fails
   because the file is already in new/, and it will then use a
   different filename. There's a few problems with this however:

      - it requires extra stat() call which is unneeded extra I/O
      - another MUA might still move the mail to cur/
      - if first file's flags are modified by either Dovecot or another
        MUA, it's moved to cur/ (you _could_ just do the dirty-flagging
	but that'd be ugly)

   Because this is useful only for very few people and it requires
   extra I/O, I decided not to implement this. It should be however
   quite easy to do since we need to be able to deal with files in new/
   in any case.

   It's also possible to never accidentally overwrite a mail by using
   link() + unlink() rather than rename(). This however isn't very
   good idea as it introduces potential race conditions when multiple
   clients are accessing the mailbox:

   Trying to move the same mail from new/ to cur/ at the same time:

      a) Client 1 uses slightly different filename than client 2,
         for example one sets read-flag on but the other doesn't.
	 You have the same mail duplicated now.

      b) Client 3 sees the mail between Client 1's and 2's link() calls
         and changes it's flag. You have the same mail duplicated now.

   And it gets worse when they're unlink()ing in cur/ directory:

      c) Client 1 changes mails's flag and client 2 changes it back
         between 1's link() and unlink(). The mail is now expunged.

      d) If you try to deal with the duplicates by unlink()ing another
         one of them, you might end up unlinking both of them.

   So, what should we do then if we notice a duplicate? First of all,
   it might not be a duplicate at all, readdir() might have just
   returned it twice because it was just renamed. What we should do is
   create a completely new base name for it and rename() it to that.
   If the call fails with ENOENT, it only means that it wasn't a
   duplicate after all.
*/

#include "lib.h"
#include "ioloop.h"
#include "buffer.h"
#include "hash.h"
#include "str.h"
#include "maildir-storage.h"
#include "maildir-uidlist.h"

#include <stdio.h>
#include <stddef.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>

#define MAILDIR_SYNC_SECS 1

#define MAILDIR_FILENAME_FLAG_FOUND 128

struct maildir_sync_context {
        struct index_mailbox *ibox;
	const char *new_dir, *cur_dir;
	int partial;

        struct maildir_uidlist_sync_ctx *uidlist_sync_ctx;
};

struct maildir_index_sync_context {
        struct index_mailbox *ibox;
	struct mail_index_view *view;
	struct mail_index_sync_ctx *sync_ctx;
	struct mail_index_transaction *trans;

	struct mail_index_sync_rec sync_rec;
	uint32_t seq;
	int have_dirty, last_dirty;
};

static int maildir_expunge(struct index_mailbox *ibox, const char *path,
			   void *context __attr_unused__)
{
	if (unlink(path) == 0) {
		ibox->dirty_cur_time = ioloop_time;
		return 1;
	}
	if (errno == ENOENT)
		return 0;

	mail_storage_set_critical(ibox->box.storage,
				  "unlink(%s) failed: %m", path);
	return -1;
}

static int maildir_sync_flags(struct index_mailbox *ibox, const char *path,
			      void *context)
{
        struct maildir_index_sync_context *ctx = context;
	const char *newpath;
	enum mail_flags flags;
	uint8_t flags8;
        keywords_mask_t keywords;

	ctx->last_dirty = FALSE;

	(void)maildir_filename_get_flags(path, &flags, keywords);

	flags8 = flags;
	mail_index_sync_flags_apply(&ctx->sync_rec, &flags8, keywords);

	newpath = maildir_filename_set_flags(path, flags8, keywords);
	if (rename(path, newpath) == 0) {
		ibox->dirty_cur_time = ioloop_time;
		return 1;
	}
	if (errno == ENOENT)
		return 0;

	if (ENOSPACE(errno) || errno == EACCES) {
		memset(keywords, 0, sizeof(keywords));
		mail_index_update_flags(ctx->trans, ctx->seq, MODIFY_ADD,
					MAIL_INDEX_MAIL_FLAG_DIRTY, keywords);
		ctx->last_dirty = TRUE;
		return 1;
	}

	mail_storage_set_critical(ibox->box.storage,
				  "rename(%s, %s) failed: %m", path, newpath);
	return -1;
}

static int maildir_sync_record(struct index_mailbox *ibox,
                               struct maildir_index_sync_context *ctx)
{
	struct mail_index_sync_rec *sync_rec = &ctx->sync_rec;
	struct mail_index_view *view = ctx->view;
	const struct mail_index_record *rec;
	uint32_t seq, seq1, seq2, uid;

	switch (sync_rec->type) {
	case MAIL_INDEX_SYNC_TYPE_APPEND:
		break;
	case MAIL_INDEX_SYNC_TYPE_EXPUNGE:
		/* make it go through sequences to avoid looping through huge
		   holes in UID range */
		if (mail_index_lookup_uid_range(view, sync_rec->uid1,
						sync_rec->uid2,
						&seq1, &seq2) < 0)
			return -1;

		if (seq1 == 0)
			break;

		for (seq = seq1; seq <= seq2; seq++) {
			if (mail_index_lookup_uid(view, seq, &uid) < 0)
				return -1;
			if (maildir_file_do(ibox, uid, maildir_expunge,
					    NULL) < 0)
				return -1;
		}
		break;
	case MAIL_INDEX_SYNC_TYPE_FLAGS:
		if (mail_index_lookup_uid_range(view, sync_rec->uid1,
						sync_rec->uid2,
						&seq1, &seq2) < 0)
			return -1;

		if (seq1 == 0)
			break;

		for (ctx->seq = seq1; ctx->seq <= seq2; ctx->seq++) {
			if (mail_index_lookup_uid(view, ctx->seq, &uid) < 0)
				return -1;
			if (maildir_file_do(ibox, uid,
					    maildir_sync_flags, ctx) < 0)
				return -1;
			if (!ctx->last_dirty) {
				/* if this flag was dirty, drop it */
				if (mail_index_lookup(view, ctx->seq, &rec) < 0)
					return -1;
				if (rec->flags & MAIL_INDEX_MAIL_FLAG_DIRTY) {
					keywords_mask_t keywords;

					memset(keywords, 0, sizeof(keywords));
					mail_index_update_flags(ctx->trans,
						ctx->seq, MODIFY_REMOVE,
						MAIL_INDEX_MAIL_FLAG_DIRTY,
						keywords);
				}
			}
		}
		break;
	}

	return 0;
}

int maildir_sync_last_commit(struct index_mailbox *ibox)
{
	struct maildir_index_sync_context ctx;
	const struct mail_index_header *hdr;
	uint32_t seq;
	uoff_t offset;
	int ret;

	if (ibox->commit_log_file_seq == 0)
		return 0;

	memset(&ctx, 0, sizeof(ctx));
	ctx.ibox = ibox;

	ret = mail_index_sync_begin(ibox->index, &ctx.sync_ctx, &ctx.view,
				    ibox->commit_log_file_seq,
				    ibox->commit_log_file_offset);
	if (ret > 0) {
		if (mail_index_get_header(ctx.view, &hdr) == 0 &&
		    (hdr->flags & MAIL_INDEX_HDR_FLAG_HAVE_DIRTY) != 0)
			ctx.have_dirty = TRUE;

		ctx.trans = mail_index_transaction_begin(ctx.view, FALSE);

		while ((ret = mail_index_sync_next(ctx.sync_ctx,
						   &ctx.sync_rec)) > 0) {
			if (maildir_sync_record(ibox, &ctx) < 0) {
				ret = -1;
				break;
			}
		}
		if (mail_index_transaction_commit(ctx.trans, &seq, &offset) < 0)
			ret = -1;
		if (mail_index_sync_end(ctx.sync_ctx) < 0)
			ret = -1;
	}

	if (ret == 0) {
		ibox->commit_log_file_seq = 0;
		ibox->commit_log_file_offset = 0;
	} else {
		mail_storage_set_index_error(ibox);
	}
	return ret;
}

static struct maildir_sync_context *
maildir_sync_context_new(struct index_mailbox *ibox)
{
        struct maildir_sync_context *ctx;

	ctx = t_new(struct maildir_sync_context, 1);
	ctx->ibox = ibox;
	ctx->new_dir = t_strconcat(ibox->path, "/new", NULL);
	ctx->cur_dir = t_strconcat(ibox->path, "/cur", NULL);
	return ctx;
}

static void maildir_sync_deinit(struct maildir_sync_context *ctx)
{
	if (ctx->uidlist_sync_ctx != NULL)
		(void)maildir_uidlist_sync_deinit(ctx->uidlist_sync_ctx);
}

static int maildir_fix_duplicate(struct index_mailbox *ibox, const char *dir,
				 const char *old_fname)
{
	const char *new_fname, *old_path, *new_path;
	int ret = 0;

	t_push();

	old_path = t_strconcat(dir, "/", old_fname, NULL);
	new_fname = maildir_generate_tmp_filename(&ioloop_timeval);
	new_path = t_strconcat(ibox->path, "/new/", new_fname, NULL);

	if (rename(old_path, new_path) == 0) {
		i_warning("Fixed duplicate in %s: %s -> %s",
			  ibox->path, old_fname, new_fname);
	} else if (errno != ENOENT) {
		mail_storage_set_critical(ibox->box.storage,
			"rename(%s, %s) failed: %m", old_path, new_path);
		ret = -1;
	}
	t_pop();

	return ret;
}

static int maildir_scan_dir(struct maildir_sync_context *ctx, int new_dir)
{
	struct mail_storage *storage = ctx->ibox->box.storage;
	const char *dir;
	DIR *dirp;
	string_t *src, *dest;
	struct dirent *dp;
        enum maildir_uidlist_rec_flag flags;
	int move_new, ret = 1;

	src = t_str_new(1024);
	dest = t_str_new(1024);

	dir = new_dir ? ctx->new_dir : ctx->cur_dir;
	dirp = opendir(dir);
	if (dirp == NULL) {
		mail_storage_set_critical(storage,
					  "opendir(%s) failed: %m", dir);
		return -1;
	}

	move_new = new_dir && !mailbox_is_readonly(&ctx->ibox->box) &&
		!ctx->ibox->keep_recent;
	while ((dp = readdir(dirp)) != NULL) {
		if (dp->d_name[0] == '.')
			continue;

		ret = maildir_uidlist_sync_next_pre(ctx->uidlist_sync_ctx,
						    dp->d_name);
		if (ret == 0) {
			/* new file and we couldn't lock uidlist, check this
			   later in next sync. */
			if (new_dir)
				ctx->ibox->last_new_mtime = 0;
			else
				ctx->ibox->dirty_cur_time = ioloop_time;
			continue;
		}
		if (ret < 0)
			break;

		flags = 0;
		if (move_new) {
			str_truncate(src, 0);
			str_truncate(dest, 0);
			str_printfa(src, "%s/%s", ctx->new_dir, dp->d_name);
			str_printfa(dest, "%s/%s", ctx->cur_dir, dp->d_name);
			if (strchr(dp->d_name, ':') == NULL)
				str_append(dest, ":2,");
			if (rename(str_c(src), str_c(dest)) == 0) {
				/* we moved it - it's \Recent for us */
                                ctx->ibox->dirty_cur_time = ioloop_time;
				flags |= MAILDIR_UIDLIST_REC_FLAG_MOVED |
					MAILDIR_UIDLIST_REC_FLAG_RECENT;
			} else if (ENOTFOUND(errno)) {
				/* someone else moved it already */
				flags |= MAILDIR_UIDLIST_REC_FLAG_MOVED;
			} else if (ENOSPACE(errno)) {
				/* not enough disk space, leave here */
				flags |= MAILDIR_UIDLIST_REC_FLAG_NEW_DIR |
					MAILDIR_UIDLIST_REC_FLAG_RECENT;
				move_new = FALSE;
			} else {
				flags |= MAILDIR_UIDLIST_REC_FLAG_NEW_DIR |
					MAILDIR_UIDLIST_REC_FLAG_RECENT;
				mail_storage_set_critical(storage,
					"rename(%s, %s) failed: %m",
					str_c(src), str_c(dest));
			}
		} else if (new_dir) {
			flags |= MAILDIR_UIDLIST_REC_FLAG_NEW_DIR |
				MAILDIR_UIDLIST_REC_FLAG_RECENT;
		}

		ret = maildir_uidlist_sync_next(ctx->uidlist_sync_ctx,
						dp->d_name, flags);
		if (ret <= 0) {
			if (ret < 0)
				break;

			/* possibly duplicate - try fixing it */
			if (maildir_fix_duplicate(ctx->ibox,
						  dir, dp->d_name) < 0) {
				ret = -1;
				break;
			}
		}
	}

	if (closedir(dirp) < 0) {
		mail_storage_set_critical(storage,
					  "closedir(%s) failed: %m", dir);
	}
	return ret < 0 ? -1 : 0;
}

static int maildir_sync_quick_check(struct maildir_sync_context *ctx,
				    int *new_changed_r, int *cur_changed_r)
{
	struct index_mailbox *ibox = ctx->ibox;
	struct stat st;
	time_t new_mtime, cur_mtime;

	*new_changed_r = *cur_changed_r = FALSE;

	if (stat(ctx->new_dir, &st) < 0) {
		mail_storage_set_critical(ibox->box.storage,
					  "stat(%s) failed: %m", ctx->new_dir);
		return -1;
	}
	new_mtime = st.st_mtime;

	if (stat(ctx->cur_dir, &st) < 0) {
		mail_storage_set_critical(ibox->box.storage,
					  "stat(%s) failed: %m", ctx->cur_dir);
		return -1;
	}
	cur_mtime = st.st_mtime;

	if (ibox->dirty_cur_time == 0) {
		/* cur stamp is kept in index, we don't have to sync if
		   someone else has done it and updated the index. make sure
		   we have a fresh index with latest sync_stamp. */
		struct mail_index_view *view;
		const struct mail_index_header *hdr;

		if (mail_index_refresh(ibox->index) < 0) {
			mail_storage_set_index_error(ibox);
			return -1;
		}

		view = mail_index_view_open(ibox->index);
		if (mail_index_get_header(view, &hdr) < 0) {
			mail_index_view_close(view);
			mail_storage_set_index_error(ibox);
			return -1;
		}
		ibox->last_cur_mtime = hdr->sync_stamp;
		mail_index_view_close(view);
	}

	if (new_mtime != ibox->last_new_mtime ||
	    new_mtime >= ibox->last_new_sync_time - MAILDIR_SYNC_SECS) {
		*new_changed_r = TRUE;
		ibox->last_new_mtime = new_mtime;
		ibox->last_new_sync_time = ioloop_time;
	}

	if (cur_mtime != ibox->last_cur_mtime ||
	    (ibox->dirty_cur_time != 0 &&
	     ioloop_time - ibox->dirty_cur_time > MAILDIR_SYNC_SECS)) {
		/* cur/ changed, or delayed cur/ check */
		*cur_changed_r = TRUE;
		ibox->last_cur_mtime = cur_mtime;

		ibox->dirty_cur_time =
			cur_mtime >= ioloop_time - MAILDIR_SYNC_SECS ?
			cur_mtime : 0;
	}

	return 0;
}

static int maildir_sync_index(struct maildir_sync_context *ctx)
{
	struct index_mailbox *ibox = ctx->ibox;
	struct maildir_index_sync_context sync_ctx;
	struct maildir_uidlist_iter_ctx *iter;
	struct mail_index_transaction *trans;
	struct mail_index_view *view;
	const struct mail_index_header *hdr;
	const struct mail_index_record *rec;
	uint32_t seq, uid;
        enum maildir_uidlist_rec_flag uflags;
	const char *filename;
	enum mail_flags flags;
	keywords_mask_t keywords;
	uint32_t uid_validity, next_uid;
	int ret;

	memset(&sync_ctx, 0, sizeof(sync_ctx));
	sync_ctx.ibox = ibox;

	if (mail_index_sync_begin(ibox->index, &sync_ctx.sync_ctx, &view,
				  (uint32_t)-1, (uoff_t)-1) <= 0) {
		mail_storage_set_index_error(ibox);
		return -1;
	}
	sync_ctx.view = view;

	ret = mail_index_get_header(view, &hdr);
	i_assert(ret == 0); /* view is locked, can't happen */

	uid_validity = maildir_uidlist_get_uid_validity(ibox->uidlist);
	if (uid_validity != hdr->uid_validity &&
	    uid_validity != 0 && hdr->uid_validity != 0) {
		/* uidvalidity changed and mailbox isn't being initialized,
		   index must be rebuilt */
		mail_storage_set_critical(ibox->box.storage,
			"Maildir %s sync: UIDVALIDITY changed (%u -> %u)",
			ibox->path, hdr->uid_validity, uid_validity);
		mail_index_mark_corrupted(ibox->index);
		(void)mail_index_sync_end(sync_ctx.sync_ctx);
		return -1;
	}

	trans = mail_index_transaction_begin(view, FALSE);
	sync_ctx.trans = trans;

	seq = 0;
	iter = maildir_uidlist_iter_init(ibox->uidlist);
	while (maildir_uidlist_iter_next(iter, &uid, &uflags, &filename)) {
		maildir_filename_get_flags(filename, &flags, keywords);

		if ((uflags & MAILDIR_UIDLIST_REC_FLAG_RECENT) != 0 &&
		    (uflags & MAILDIR_UIDLIST_REC_FLAG_NEW_DIR) != 0 &&
		    (uflags & MAILDIR_UIDLIST_REC_FLAG_MOVED) == 0) {
			/* mail is recent for next session as well */
			flags |= MAIL_RECENT;
		}

	__again:
		seq++;
		if ((uflags & MAILDIR_UIDLIST_REC_FLAG_NONSYNCED) != 0) {
			/* partial syncing */
			continue;
		}

		if (seq > hdr->messages_count) {
			if (uid < hdr->next_uid) {
				/* most likely a race condition: we read the
				   maildir, then someone else expunged messages
				   and committed changes to index. so, this
				   message shouldn't actually exist. mark it
				   racy and check in next sync.

				   the difference between this and the later
				   check is that this one happens when messages
				   are expunged from the end */
				if ((uflags &
				     MAILDIR_UIDLIST_REC_FLAG_RACING) != 0) {
					mail_storage_set_critical(
						ibox->box.storage,
						"Maildir %s sync: "
						"UID < next_uid "
						"(%u < %u, file = %s)",
						ibox->path, uid, hdr->next_uid,
						filename);
					mail_index_mark_corrupted(ibox->index);
					ret = -1;
					break;
				}
				ibox->dirty_cur_time = ioloop_time;
				maildir_uidlist_add_flags(ibox->uidlist,
					filename,
					MAILDIR_UIDLIST_REC_FLAG_RACING);

				seq--;
				continue;
			}

			mail_index_append(trans, uid, &seq);
			mail_index_update_flags(trans, seq, MODIFY_REPLACE,
						flags, keywords);
			continue;
		}

		if (mail_index_lookup(view, seq, &rec) < 0) {
			ret = -1;
			break;
		}

		if (rec->uid < uid) {
			/* expunged */
			mail_index_expunge(trans, seq);
			goto __again;
		}

		if (rec->uid > uid) {
			/* most likely a race condition: we read the
			   maildir, then someone else expunged messages and
			   committed changes to index. so, this message
			   shouldn't actually exist. mark it racy and check
			   in next sync. */
			if ((uflags & MAILDIR_UIDLIST_REC_FLAG_RACING) != 0) {
				mail_storage_set_critical(ibox->box.storage,
					"Maildir %s sync: UID inserted in the "
					"middle of mailbox "
					"(%u > %u, file = %s)",
					ibox->path, rec->uid, uid, filename);
				mail_index_mark_corrupted(ibox->index);
				ret = -1;
				break;
			}

			ibox->dirty_cur_time = ioloop_time;
			maildir_uidlist_add_flags(ibox->uidlist, filename,
				MAILDIR_UIDLIST_REC_FLAG_RACING);

			seq--;
			continue;
		}

		if ((rec->flags & MAIL_INDEX_MAIL_FLAG_DIRTY) != 0) {
			/* we haven't been able to update maildir with this
			   record's flag changes. don't sync them. */
			continue;
		}

		if (((uint8_t)flags & ~MAIL_RECENT) !=
		    (rec->flags & (MAIL_FLAGS_MASK^MAIL_RECENT)) ||
		    memcmp(keywords, rec->keywords,
			   INDEX_KEYWORDS_BYTE_COUNT) != 0) {
			/* FIXME: this is wrong if there's pending changes in
			   transaction log already. it gets fixed in next sync
			   however.. */
			mail_index_update_flags(trans, seq, MODIFY_REPLACE,
						flags, keywords);
		} else if ((flags & MAIL_RECENT) == 0 &&
			   (rec->flags & MAIL_RECENT) != 0) {
			/* just remove recent flag */
			memset(keywords, 0, sizeof(keywords));
			mail_index_update_flags(trans, seq, MODIFY_REMOVE,
						MAIL_RECENT, keywords);
		}
	}
	maildir_uidlist_iter_deinit(iter);

	if (!ctx->partial) {
		/* expunge the rest */
		for (seq++; seq <= hdr->messages_count; seq++)
			mail_index_expunge(trans, seq);
	}

	/* now, sync the index */
	while ((ret = mail_index_sync_next(sync_ctx.sync_ctx,
					   &sync_ctx.sync_rec)) > 0) {
		if (maildir_sync_record(ibox, &sync_ctx) < 0) {
			ret = -1;
			break;
		}
	}

	if (ibox->dirty_cur_time == 0 &&
	    ibox->last_cur_mtime != (time_t)hdr->sync_stamp) {
		uint32_t sync_stamp = ibox->last_cur_mtime;

		mail_index_update_header(trans,
			offsetof(struct mail_index_header, sync_stamp),
			&sync_stamp, sizeof(sync_stamp));
	}

	if (hdr->uid_validity == 0) {
		/* get the initial uidvalidity */
		if (maildir_uidlist_update(ibox->uidlist) < 0)
			ret = -1;
		uid_validity = maildir_uidlist_get_uid_validity(ibox->uidlist);
		if (uid_validity == 0) {
			uid_validity = ioloop_time;
			maildir_uidlist_set_uid_validity(ibox->uidlist,
							 uid_validity);
		}
	} else if (uid_validity == 0) {
		maildir_uidlist_set_uid_validity(ibox->uidlist,
						 hdr->uid_validity);
	}

	if (uid_validity != hdr->uid_validity && uid_validity != 0) {
		mail_index_update_header(trans,
			offsetof(struct mail_index_header, uid_validity),
			&uid_validity, sizeof(uid_validity));
	}

	next_uid = maildir_uidlist_get_next_uid(ibox->uidlist);
	if (next_uid != 0 && hdr->next_uid != next_uid) {
		mail_index_update_header(trans,
			offsetof(struct mail_index_header, next_uid),
			&next_uid, sizeof(next_uid));
	}

	if (ret < 0)
		mail_index_transaction_rollback(trans);
	else {
		uint32_t seq;
		uoff_t offset;

		if (mail_index_transaction_commit(trans, &seq, &offset) < 0)
			ret = -1;
		else if (seq != 0) {
			ibox->commit_log_file_seq = seq;
			ibox->commit_log_file_offset = offset;
		}
	}

	if (mail_index_sync_end(sync_ctx.sync_ctx) < 0)
		ret = -1;

	if (ret == 0) {
		ibox->commit_log_file_seq = 0;
		ibox->commit_log_file_offset = 0;
	} else {
		mail_storage_set_index_error(ibox);
	}

	return ret;
}

static int maildir_sync_context(struct maildir_sync_context *ctx)
{
	int ret, new_changed, cur_changed;

	if (maildir_sync_quick_check(ctx, &new_changed, &cur_changed) < 0)
		return -1;

	if (!new_changed && !cur_changed)
		return 0;

	ctx->partial = !cur_changed;
	ctx->uidlist_sync_ctx =
		maildir_uidlist_sync_init(ctx->ibox->uidlist, ctx->partial);

	if (maildir_scan_dir(ctx, TRUE) < 0)
		return -1;
	if (cur_changed) {
		if (maildir_scan_dir(ctx, FALSE) < 0)
			return -1;
	}

	/* finish uidlist syncing, but keep it still locked */
	if (maildir_uidlist_sync_finish(ctx->uidlist_sync_ctx)) {
		if (maildir_sync_index(ctx) < 0)
			return -1;
	}

	ret = maildir_uidlist_sync_deinit(ctx->uidlist_sync_ctx);
        ctx->uidlist_sync_ctx = NULL;

	return ret;
}

static int maildir_sync_context_readonly(struct maildir_sync_context *ctx)
{
	int ret;

	ctx->uidlist_sync_ctx =
		maildir_uidlist_sync_init(ctx->ibox->uidlist, FALSE);

	if (maildir_scan_dir(ctx, TRUE) < 0)
		return -1;
	if (maildir_scan_dir(ctx, FALSE) < 0)
		return -1;

	ret = maildir_uidlist_sync_deinit(ctx->uidlist_sync_ctx);
        ctx->uidlist_sync_ctx = NULL;

	return ret;
}

int maildir_storage_sync_readonly(struct index_mailbox *ibox)
{
        struct maildir_sync_context *ctx;
	int ret;

	ctx = maildir_sync_context_new(ibox);
	ret = maildir_sync_context_readonly(ctx);
	maildir_sync_deinit(ctx);
	return ret;
}

int maildir_storage_sync(struct mailbox *box, enum mailbox_sync_flags flags)
{
	struct index_mailbox *ibox = (struct index_mailbox *)box;
	struct maildir_sync_context *ctx;
	int ret;

	if ((flags & MAILBOX_SYNC_FLAG_FAST) == 0 ||
	    ibox->sync_last_check + MAILBOX_FULL_SYNC_INTERVAL <= ioloop_time) {
		ibox->sync_last_check = ioloop_time;

		ctx = maildir_sync_context_new(ibox);
		ret = maildir_sync_context(ctx);
		maildir_sync_deinit(ctx);

		if (ret < 0)
			return -1;
	}

	return index_storage_sync(box, flags);
}
