/* Copyright (C) 2004 Timo Sirainen */

/*
   Here's a description of how we handle Maildir synchronization and
   it's problems:

   We want to be as efficient as we can. The most efficient way to
   check if changes have occurred is to stat() the new/ and cur/
   directories and uidlist file - if their mtimes haven't changed,
   there's no changes and we don't need to do anything.

   Problem 1: Multiple changes can happen within a single second -
   nothing guarantees that once we synced it, someone else didn't just
   then make a modification. Such modifications wouldn't get noticed
   until a new modification occurred later.

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
#include "array.h"
#include "buffer.h"
#include "hash.h"
#include "str.h"
#include "nfs-workarounds.h"
#include "maildir-storage.h"
#include "maildir-uidlist.h"
#include "maildir-filename.h"
#include "maildir-sync.h"

#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>

#define MAILDIR_FILENAME_FLAG_FOUND 128

/* When rename()ing many files from new/ to cur/, it's possible that next
   readdir() skips some files. we don't of course wish to lose them, so we
   go and rescan the new/ directory again from beginning until no files are
   left. This value is just an optimization to avoid checking the directory
   twice unneededly. usually only NFS is the problem case. 1 is the safest
   bet here, but I guess 5 will do just fine too. */
#define MAILDIR_RENAME_RESCAN_COUNT 5

/* This is mostly to avoid infinite looping when rename() destination already
   exists as the hard link of the file itself. */
#define MAILDIR_SCAN_DIR_MAX_COUNT 5

#define DUPE_LINKS_DELETE_SECS 30

struct maildir_sync_context {
        struct maildir_mailbox *mbox;
	const char *new_dir, *cur_dir;
	bool partial;

	time_t last_touch, last_notify;

	struct maildir_uidlist_sync_ctx *uidlist_sync_ctx;
        struct maildir_index_sync_context *index_sync_ctx;
};

void maildir_sync_notify(struct maildir_sync_context *ctx)
{
	time_t now;

	if (ctx == NULL) {
		/* we got here from maildir-save.c. it has no
		   maildir_sync_context,  */
		return;
	}

	now = time(NULL);
	if (now - ctx->last_touch > MAILDIR_LOCK_TOUCH_SECS) {
		(void)maildir_uidlist_lock_touch(ctx->mbox->uidlist);
		ctx->last_touch = now;
	}
	if (now - ctx->last_notify > MAIL_STORAGE_STAYALIVE_SECS) {
		struct mailbox *box = &ctx->mbox->ibox.box;

		if (box->storage->callbacks->notify_ok != NULL) {
			box->storage->callbacks->
				notify_ok(box, "Hang in there..",
					  box->storage->callback_context);
		}
		ctx->last_notify = now;
	}
}

static struct maildir_sync_context *
maildir_sync_context_new(struct maildir_mailbox *mbox)
{
        struct maildir_sync_context *ctx;

	ctx = t_new(struct maildir_sync_context, 1);
	ctx->mbox = mbox;
	ctx->new_dir = t_strconcat(mbox->path, "/new", NULL);
	ctx->cur_dir = t_strconcat(mbox->path, "/cur", NULL);
	ctx->last_touch = ioloop_time;
	ctx->last_notify = ioloop_time;
	return ctx;
}

static void maildir_sync_deinit(struct maildir_sync_context *ctx)
{
	if (ctx->uidlist_sync_ctx != NULL)
		(void)maildir_uidlist_sync_deinit(&ctx->uidlist_sync_ctx);
	if (ctx->index_sync_ctx != NULL) {
		(void)maildir_sync_index_finish(&ctx->index_sync_ctx,
						TRUE, FALSE);
	}
}

static int maildir_fix_duplicate(struct maildir_sync_context *ctx,
				 const char *dir, const char *fname2)
{
	const char *fname1, *path1, *path2;
	const char *new_fname, *new_path;
	struct stat st1, st2;
	int ret = 0;

	fname1 = maildir_uidlist_sync_get_full_filename(ctx->uidlist_sync_ctx,
							fname2);
	i_assert(fname1 != NULL);

	t_push();

	path1 = t_strconcat(dir, "/", fname1, NULL);
	path2 = t_strconcat(dir, "/", fname2, NULL);

	if (stat(path1, &st1) < 0 || stat(path2, &st2) < 0) {
		/* most likely the files just don't exist anymore.
		   don't really care about other errors much. */
		t_pop();
		return 0;
	}
	if (st1.st_ino == st2.st_ino &&
	    CMP_DEV_T(st1.st_dev, st2.st_dev)) {
		/* Files are the same. this means either a race condition
		   between stat() calls, or that the files were link()ed. */
		if (st1.st_nlink > 1 && st2.st_nlink == st1.st_nlink &&
		    st1.st_ctime == st2.st_ctime &&
		    st1.st_ctime < ioloop_time - DUPE_LINKS_DELETE_SECS) {
			/* The file has hard links and it hasn't had any
			   changes (such as renames) for a while, so this
			   isn't a race condition.

			   rename()ing one file on top of the other would fix
			   this safely, except POSIX decided that rename()
			   doesn't work that way. So we'll have unlink() one
			   and hope that another process didn't just decide to
			   unlink() the other (uidlist lock prevents this from
			   happening) */
			if (unlink(path2) == 0)
				i_warning("Unlinked a duplicate: %s", path2);
			else {
				mail_storage_set_critical(
					&ctx->mbox->storage->storage,
					"unlink(%s) failed: %m", path2);
			}
		}
		t_pop();
		return 0;
	}

	new_fname = maildir_filename_generate();
	new_path = t_strconcat(ctx->mbox->path, "/new/", new_fname, NULL);

	if (rename(path2, new_path) == 0)
		i_warning("Fixed a duplicate: %s -> %s", path2, new_fname);
	else if (errno != ENOENT) {
		mail_storage_set_critical(&ctx->mbox->storage->storage,
			"Couldn't fix a duplicate: rename(%s, %s) failed: %m",
			path2, new_path);
		ret = -1;
	}
	t_pop();

	return ret;
}

static int
maildir_stat(struct maildir_mailbox *mbox, const char *path, struct stat *st_r)
{
	if (nfs_safe_stat(path, st_r) == 0)
		return 0;
	if (errno == ENOENT) {
		/* if mailbox gets deleted under us, don't log an error */
		mbox->ibox.mailbox_deleted = TRUE;
		return -1;
	}

	mail_storage_set_critical(mbox->ibox.box.storage,
				  "stat(%s) failed: %m", path);
	return -1;
}

static int maildir_scan_dir(struct maildir_sync_context *ctx, bool new_dir)
{
	struct mail_storage *storage = &ctx->mbox->storage->storage;
	const char *path;
	DIR *dirp;
	string_t *src, *dest;
	struct dirent *dp;
	struct stat st;
	enum maildir_uidlist_rec_flag flags;
	unsigned int i = 0, move_count = 0;
	time_t now;
	int ret = 1;
	bool move_new, check_touch, dir_changed = FALSE;

	path = new_dir ? ctx->new_dir : ctx->cur_dir;
	dirp = opendir(path);
	if (dirp == NULL) {
		if (errno == ENOENT) {
			ctx->mbox->ibox.mailbox_deleted = TRUE;
			return -1;
		}
		mail_storage_set_critical(storage,
					  "opendir(%s) failed: %m", path);
		return -1;
	}

#ifdef HAVE_DIRFD
	if (fstat(dirfd(dirp), &st) < 0) {
		mail_storage_set_critical(storage,
			"fstat(%s) failed: %m", path);
		(void)closedir(dirp);
		return -1;
	}
#else
	if (maildir_stat(ctx->mbox, path, &st) < 0) {
		(void)closedir(dirp);
		return -1;
	}
#endif

	now = time(NULL);
	if (new_dir) {
		ctx->mbox->maildir_hdr.new_check_time = now;
		ctx->mbox->maildir_hdr.new_mtime = st.st_mtime;
#ifdef HAVE_STAT_TV_NSEC
		ctx->mbox->maildir_hdr.new_mtime_nsecs = st.st_mtim.tv_nsec;
#else
		ctx->mbox->maildir_hdr.new_mtime_nsecs = 0;
#endif
	} else {
		ctx->mbox->maildir_hdr.cur_check_time = now;
		ctx->mbox->maildir_hdr.cur_mtime = st.st_mtime;
#ifdef HAVE_STAT_TV_NSEC
		ctx->mbox->maildir_hdr.cur_mtime_nsecs = st.st_mtim.tv_nsec;
#else
		ctx->mbox->maildir_hdr.cur_mtime_nsecs = 0;
#endif
	}

	t_push();
	src = t_str_new(1024);
	dest = t_str_new(1024);

	move_new = new_dir && !mailbox_is_readonly(&ctx->mbox->ibox.box) &&
		!ctx->mbox->ibox.keep_recent;

	errno = 0;
	for (; (dp = readdir(dirp)) != NULL; errno = 0) {
		if (dp->d_name[0] == '.')
			continue;

		ret = maildir_uidlist_sync_next_pre(ctx->uidlist_sync_ctx,
						    dp->d_name);
		if (ret == 0) {
			/* new file and we couldn't lock uidlist, check this
			   later in next sync. */
			dir_changed = TRUE;
			continue;
		}
		if (ret < 0)
			break;

		check_touch = FALSE;
		flags = 0;
		if (move_new) {
			str_truncate(src, 0);
			str_truncate(dest, 0);
			str_printfa(src, "%s/%s", ctx->new_dir, dp->d_name);
			str_printfa(dest, "%s/%s", ctx->cur_dir, dp->d_name);
			if (strchr(dp->d_name, MAILDIR_INFO_SEP) == NULL) {
				str_append(dest, MAILDIR_FLAGS_FULL_SEP);
			}
			if (rename(str_c(src), str_c(dest)) == 0) {
				/* we moved it - it's \Recent for us */
				dir_changed = TRUE;
				move_count++;
				flags |= MAILDIR_UIDLIST_REC_FLAG_MOVED |
					MAILDIR_UIDLIST_REC_FLAG_RECENT;
			} else if (ENOTFOUND(errno)) {
				/* someone else moved it already */
				dir_changed = TRUE;
				move_count++;
				flags |= MAILDIR_UIDLIST_REC_FLAG_MOVED |
					MAILDIR_UIDLIST_REC_FLAG_RECENT;
			} else if (ENOSPACE(errno) || errno == EACCES) {
				/* not enough disk space / read-only maildir,
				   leave here */
				flags |= MAILDIR_UIDLIST_REC_FLAG_NEW_DIR;
				move_new = FALSE;
			} else {
				flags |= MAILDIR_UIDLIST_REC_FLAG_NEW_DIR;
				mail_storage_set_critical(storage,
					"rename(%s, %s) failed: %m",
					str_c(src), str_c(dest));
			}
			if ((move_count % MAILDIR_SLOW_MOVE_COUNT) == 0)
				maildir_sync_notify(ctx);
		} else if (new_dir) {
			flags |= MAILDIR_UIDLIST_REC_FLAG_NEW_DIR |
				MAILDIR_UIDLIST_REC_FLAG_RECENT;
		}

		i++;
		if ((i % MAILDIR_SLOW_CHECK_COUNT) == 0)
			maildir_sync_notify(ctx);

		ret = maildir_uidlist_sync_next(ctx->uidlist_sync_ctx,
						dp->d_name, flags);
		if (ret <= 0) {
			if (ret < 0)
				break;

			/* possibly duplicate - try fixing it */
			if (maildir_fix_duplicate(ctx, path, dp->d_name) < 0) {
				ret = -1;
				break;
			}
		}
	}

	if (errno != 0) {
		mail_storage_set_critical(storage,
					  "readdir(%s) failed: %m", path);
		ret = -1;
	}

	if (closedir(dirp) < 0) {
		mail_storage_set_critical(storage,
					  "closedir(%s) failed: %m", path);
		ret = -1;
	}

	if (dir_changed) {
		if (new_dir)
			ctx->mbox->maildir_hdr.new_mtime = now;
		else
			ctx->mbox->maildir_hdr.cur_mtime = now;
	}

	t_pop();
	return ret < 0 ? -1 :
		(move_count <= MAILDIR_RENAME_RESCAN_COUNT ? 0 : 1);
}

static int maildir_header_refresh(struct maildir_mailbox *mbox)
{
	const void *data;
	size_t data_size;

	if (mail_index_refresh(mbox->ibox.index) < 0) {
		mail_storage_set_index_error(&mbox->ibox);
		return -1;
	}

	mail_index_get_header_ext(mbox->ibox.view, mbox->maildir_ext_id,
				  &data, &data_size);
	if (data_size == 0) {
		/* doesn't exist */
		return 0;
	}

	if (data_size != sizeof(mbox->maildir_hdr))
		i_warning("Maildir %s: Invalid header record size", mbox->path);
	else
		memcpy(&mbox->maildir_hdr, data, sizeof(mbox->maildir_hdr));
	return 0;
}

static int maildir_sync_quick_check(struct maildir_mailbox *mbox,
				    const char *new_dir, const char *cur_dir,
				    bool *new_changed_r, bool *cur_changed_r)
{
#ifdef HAVE_STAT_TV_NSEC
#  define DIR_NSECS_CHANGED(st, hdr, name) \
	((unsigned int)(st).st_mtim.tv_nsec != (hdr)->name ## _mtime_nsecs)
#else
#  define DIR_NSECS_CHANGED(st, hdr, name) 0
#endif

#define DIR_DELAYED_REFRESH(hdr, name) \
	((hdr)->name ## _check_time <= \
		(hdr)->name ## _mtime + MAILDIR_SYNC_SECS && \
	 (time_t)(hdr)->name ## _check_time < ioloop_time - MAILDIR_SYNC_SECS)

#define DIR_MTIME_CHANGED(st, hdr, name) \
	((st).st_mtime != (time_t)(hdr)->name ## _mtime || \
	 DIR_NSECS_CHANGED(st, hdr, name))

	struct maildir_index_header *hdr = &mbox->maildir_hdr;
	struct stat new_st, cur_st;
	bool refreshed = FALSE, check_new = FALSE, check_cur = FALSE;

	if (mbox->maildir_hdr.new_mtime == 0) {
		if (maildir_header_refresh(mbox) < 0)
			return -1;
		if (mbox->maildir_hdr.new_mtime == 0) {
			/* first sync */
			*new_changed_r = *cur_changed_r = TRUE;
			return 0;
		}
	}

	*new_changed_r = *cur_changed_r = FALSE;

	/* try to avoid stat()ing by first checking delayed changes */
	if (DIR_DELAYED_REFRESH(hdr, new) ||
	    DIR_DELAYED_REFRESH(hdr, cur)) {
		/* refresh index and try again */
		if (maildir_header_refresh(mbox) < 0)
			return -1;
		refreshed = TRUE;

		if (DIR_DELAYED_REFRESH(hdr, new))
			*new_changed_r = TRUE;
		if (DIR_DELAYED_REFRESH(hdr, cur))
			*cur_changed_r = TRUE;
		if (*new_changed_r && *cur_changed_r)
			return 0;
	}

	if (!*new_changed_r) {
		if (maildir_stat(mbox, new_dir, &new_st) < 0)
			return -1;
		check_new = TRUE;
	}
	if (!*cur_changed_r) {
		if (maildir_stat(mbox, cur_dir, &cur_st) < 0)
			return -1;
		check_cur = TRUE;
	}

	for (;;) {
		if (check_new)
			*new_changed_r = DIR_MTIME_CHANGED(new_st, hdr, new);
		if (check_cur)
			*cur_changed_r = DIR_MTIME_CHANGED(cur_st, hdr, cur);

		if ((!*new_changed_r && !*cur_changed_r) || refreshed)
			break;

		/* refresh index and try again */
		if (maildir_header_refresh(mbox) < 0)
			return -1;
		refreshed = TRUE;
	}

	return 0;
}

static void maildir_sync_update_next_uid(struct maildir_mailbox *mbox)
{
	const struct mail_index_header *hdr;
	uint32_t uid_validity, next_uid;

	hdr = mail_index_get_header(mbox->ibox.view);
	if (hdr->uid_validity == 0)
		return;

	uid_validity = maildir_uidlist_get_uid_validity(mbox->uidlist);
	next_uid = maildir_uidlist_get_next_uid(mbox->uidlist);

	if (uid_validity == hdr->uid_validity || uid_validity == 0) {
		/* make sure uidlist's next_uid is at least as large as
		   index file's. typically this happens only if uidlist gets
		   deleted. */
		maildir_uidlist_set_uid_validity(mbox->uidlist,
						 hdr->uid_validity);
		maildir_uidlist_set_next_uid(mbox->uidlist,
					     hdr->next_uid, FALSE);
	}
}

static bool move_recent_messages(struct maildir_sync_context *ctx)
{
	const struct mail_index_header *hdr;

	if (ctx->mbox->ibox.keep_recent)
		return FALSE;

	(void)maildir_uidlist_refresh(ctx->mbox->uidlist);

	/* if there are files in new/, we'll need to move them. we'll check
	   this by checking if we have any recent messages */
	hdr = mail_index_get_header(ctx->mbox->ibox.view);
	return hdr->first_recent_uid <
		maildir_uidlist_get_next_uid(ctx->mbox->uidlist);
}

static int maildir_sync_context(struct maildir_sync_context *ctx, bool forced,
				bool sync_last_commit)
{
	bool new_changed, cur_changed, full_rescan = FALSE;
	int ret;

	if (sync_last_commit) {
		new_changed = cur_changed = FALSE;
	} else if (!forced) {
		if (maildir_sync_quick_check(ctx->mbox,
					     ctx->new_dir, ctx->cur_dir,
					     &new_changed, &cur_changed) < 0)
			return -1;

		if (!new_changed && !cur_changed) {
			if (!move_recent_messages(ctx))
				return 1;
			new_changed = TRUE;
		}
	} else {
		new_changed = cur_changed = TRUE;
	}

	/*
	   Locking, locking, locking.. Wasn't maildir supposed to be lockless?

	   We can get here either as beginning a real maildir sync, or when
	   committing changes to maildir but a file was lost (maybe renamed).

	   So, we're going to need two locks. One for index and one for
	   uidlist. To avoid deadlocking do the uidlist lock always first.

	   uidlist is needed only for figuring out UIDs for newly seen files,
	   so theoretically we wouldn't need to lock it unless there are new
	   files. It has a few problems though, assuming the index lock didn't
	   already protect it (eg. in-memory indexes):

	   1. Just because you see a new file which doesn't exist in uidlist
	   file, doesn't mean that the file really exists anymore, or that
	   your readdir() lists all new files. Meaning that this is possible:

	     A: opendir(), readdir() -> new file ...
	     -- new files are written to the maildir --
	     B: opendir(), readdir() -> new file, lock uidlist,
		readdir() -> another new file, rewrite uidlist, unlock
	     A: ... lock uidlist, readdir() -> nothing left, rewrite uidlist,
		unlock

	   The second time running A didn't see the two new files. To handle
	   this correctly, it must not remove the new unseen files from
	   uidlist. This is possible to do, but adds extra complexity.

	   2. If another process is rename()ing files while we are
	   readdir()ing, it's possible that readdir() never lists some files,
	   causing Dovecot to assume they were expunged. In next sync they
	   would show up again, but client could have already been notified of
	   that and they would show up under new UIDs, so the damage is
	   already done.

	   Both of the problems can be avoided if we simply lock the uidlist
	   before syncing and keep it until sync is finished. Typically this
	   would happen in any case, as there is the index lock..

	   The second case is still a problem with external changes though,
	   because maildir doesn't require any kind of locking. Luckily this
	   problem rarely happens except under high amount of modifications.
	*/

	ctx->partial = !cur_changed;
	ret = maildir_uidlist_sync_init(ctx->mbox->uidlist, ctx->partial,
					&ctx->uidlist_sync_ctx);
	if (ret <= 0) {
		/* failure / timeout. if forced is TRUE, we could still go
		   forward and check only for renamed files, but is it worth
		   the trouble? .. */
		return ret;
	}

	if (!ctx->mbox->syncing_commit) {
		if (maildir_sync_index_begin(ctx->mbox, ctx,
					     &ctx->index_sync_ctx) < 0)
			return -1;
	}

	if (new_changed || cur_changed) {
		/* if we're going to check cur/ dir our current logic requires
		   that new/ dir is checked as well. it's a good idea anyway. */
		unsigned int count = 0;

		while ((ret = maildir_scan_dir(ctx, TRUE)) > 0) {
			/* rename()d at least some files, which might have
			   caused some other files to be missed. check again
			   (see MAILDIR_RENAME_RESCAN_COUNT). */
			if (++count > MAILDIR_SCAN_DIR_MAX_COUNT)
				break;
		}
		if (ret < 0)
			return -1;

		if (cur_changed) {
			if (maildir_scan_dir(ctx, FALSE) < 0)
				return -1;
		}

		maildir_sync_update_next_uid(ctx->mbox);

		/* finish uidlist syncing, but keep it still locked */
		maildir_uidlist_sync_finish(ctx->uidlist_sync_ctx);
	}

	if (!ctx->mbox->syncing_commit) {
		/* NOTE: index syncing here might cause a re-sync due to
		   files getting lost, so this function might be called
		   re-entrantly. */
		ret = maildir_sync_index(ctx->index_sync_ctx, ctx->partial);
		if (maildir_sync_index_finish(&ctx->index_sync_ctx,
					      ret < 0, FALSE) < 0)
			return -1;

		if (ret < 0)
			return -1;
		if (ret == 0)
			full_rescan = TRUE;

		i_assert(maildir_uidlist_is_locked(ctx->mbox->uidlist));
	}

	ret = maildir_uidlist_sync_deinit(&ctx->uidlist_sync_ctx);
	return ret < 0 ? -1 : (full_rescan ? 0 : 1);
}

int maildir_storage_sync_force(struct maildir_mailbox *mbox)
{
        struct maildir_sync_context *ctx;
	int ret;

	ctx = maildir_sync_context_new(mbox);
	ret = maildir_sync_context(ctx, TRUE, FALSE);
	maildir_sync_deinit(ctx);
	return ret < 0 ? -1 : 0;
}

int maildir_sync_last_commit(struct maildir_mailbox *mbox)
{
        struct maildir_sync_context *ctx;
	int ret = 0;

	if (mbox->ibox.commit_log_file_seq != 0) {
		ctx = maildir_sync_context_new(mbox);
		ret = maildir_sync_context(ctx, FALSE, TRUE);
		maildir_sync_deinit(ctx);
	}

	if (ret == 0) {
		if (maildir_uidlist_update(mbox->uidlist) < 0)
			ret = -1;
	}
	return ret < 0 ? -1 : 0;
}

struct mailbox_sync_context *
maildir_storage_sync_init(struct mailbox *box, enum mailbox_sync_flags flags)
{
	struct maildir_mailbox *mbox = (struct maildir_mailbox *)box;
	struct maildir_sync_context *ctx;
	int ret = 0;

	if (!box->opened)
		index_storage_mailbox_open(&mbox->ibox);

	if ((flags & MAILBOX_SYNC_FLAG_FAST) == 0 ||
	    mbox->ibox.sync_last_check + MAILBOX_FULL_SYNC_INTERVAL <=
	    ioloop_time) {
		mbox->ibox.sync_last_check = ioloop_time;

		ctx = maildir_sync_context_new(mbox);
		ret = maildir_sync_context(ctx, FALSE, FALSE);
		maildir_sync_deinit(ctx);

		i_assert(!maildir_uidlist_is_locked(mbox->uidlist) ||
			 mbox->ibox.keep_locked);

		if (ret == 0) {
			/* lost some files from new/, see if thery're in cur/ */
			ret = maildir_storage_sync_force(mbox);
		}
	}

	return index_mailbox_sync_init(box, flags, ret < 0);
}

int maildir_sync_is_synced(struct maildir_mailbox *mbox)
{
	const char *new_dir, *cur_dir;
	bool new_changed, cur_changed;
	int ret;

	t_push();
	new_dir = t_strconcat(mbox->path, "/new", NULL);
	cur_dir = t_strconcat(mbox->path, "/cur", NULL);

	ret = maildir_sync_quick_check(mbox, new_dir, cur_dir,
				       &new_changed, &cur_changed);
	t_pop();
	return ret < 0 ? -1 : (!new_changed && !cur_changed);
}
