/* Copyright (C) 2002-2003 Timo Sirainen */

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

   We have maildir_cur_dirty variable which is set to cur/ directory's
   mtime when it's >= time() - MAILDIR_SYNC_SECS and we _think_ we have
   synchronized the directory.

   When maildir_cur_dirty is non-zero, we don't synchronize the cur/
   directory until

      a) cur/'s mtime changes
      b) opening a mail fails with ENOENT
      c) time() > maildir_cur_dirty + MAILDIR_SYNC_SECS

   This allows us to modify the maildir multiple times without having
   to sync it at every change. The sync will eventually be done to
   make sure we didn't miss any external changes.

   The maildir_cur_dirty is set when:

      - we change message flags
      - we expunge messages
      - we move mail from new/ to cur/
      - we sync cur/ directory and it's mtime is
        >= time() - MAILDIR_SYNC_SECS

   It's unset when we do the final syncing, ie. when mtime is
   older than time() - MAILDIR_SYNC_SECS.

   new directory
   -------------

   If new/'s mtime is >= time() - MAILDIR_SYNC_SECS, always synchronize
   it. maildir_cur_dirty-like feature might save us a few syncs, but
   that might break a client which saves a mail in one connection and
   tries to fetch it in another one. new/ directory is almost always
   empty, so syncing it should be very fast anyway. Actually this can
   still happen if we sync only new/ dir while another client is also
   moving mails from it to cur/ - it takes us a while to see them.
   That's pretty unlikely to happen however, and only way to fix it
   would be to always synchronize cur/ after new/.

   Normally we move all mails from new/ to cur/ whenever we sync it. If
   it's not possible for some reason, we set maildir_have_new flag on
   which instructs synchronization to check files in new/ directory as
   well. maildir_keep_new flag is also set which instructs syncing to
   not even try to move mails to cur/ anymore.

   If client tries to change a flag for message in new/, we try to
   rename() it into cur/. If it's successful, we clear the
   maildir_keep_new flag so at next sync we'll try to move all of them
   to cur/. When all of them have been moved, maildir_have_new flag is
   cleared as well. Expunges will also clear maildir_keep_new flag.

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
   one's. Use utime() before rename() if needed.

   Only time you have to read this file is when assigning new UIDs for
   messages, to see if they already have UIDs. If file's mtime hasn't
   changed, you don't have to do even that.

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
   Don't move the mail from new/ to cur/ if it's mtime (it's included
   in beginning of file name, so stat() isn't needed) is >= time() -
   MAILDIR_SYNC_SECS. The second delivery's link() call then fails
   because the file is already in new/, and it will then use a
   different filename. There's a few problems with this however:

      - another MUA might still move the mail to cur/
      - if first file's flags are modified by either Dovecot or another
        MUA, it's moved to cur/ (you _could_ just do the dirty-flagging
	but that'd be ugly)

   Because this is useful only for very few people and it requires some
   extra code, I decided not to implement it at least for now.

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

      c) Most other maildir clients use rename(). So if client 1 changes
         mail's flag with link()+unlink() and client 2 using rename()
	 changes it back between 1's link() and unlink(), the mail gets
	 expunged.

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
#include "buffer.h"
#include "istream.h"
#include "hash.h"
#include "ioloop.h"
#include "str.h"
#include "maildir-index.h"
#include "maildir-uidlist.h"
#include "mail-index-util.h"
#include "mail-cache.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <utime.h>
#include <sys/stat.h>

#define MAILDIR_SYNC_SECS 1

enum maildir_file_action {
	MAILDIR_FILE_ACTION_EXPUNGE,
        MAILDIR_FILE_ACTION_UPDATE_FLAGS,
	MAILDIR_FILE_ACTION_NEW,
	MAILDIR_FILE_ACTION_NONE,

	MAILDIR_FILE_FLAG_NEWDIR	= 0x1000,
	MAILDIR_FILE_FLAG_ALLOCED	= 0x2000,
        MAILDIR_FILE_FLAGS		= 0x3000
};

struct maildir_hash_context {
	struct mail_index *index;
	struct mail_index_record *new_mail;

	int failed;
};

struct maildir_hash_rec {
	struct mail_index_record *rec;
	enum maildir_file_action action;
};
#define ACTION(hash) ((hash)->action & ~MAILDIR_FILE_FLAGS)

struct maildir_sync_context {
        struct mail_index *index;
	const char *new_dir, *cur_dir;

	pool_t pool;
	struct hash_table *files;
	unsigned int new_count;

	DIR *new_dirp;
	struct dirent *new_dent;

	struct maildir_uidlist *uidlist;
        struct mail_cache_transaction_ctx *trans_ctx;
	unsigned int readonly_check:1;
	unsigned int flag_updates:1;
	unsigned int uidlist_rewrite:1;
	unsigned int new_mails_new:1;
	unsigned int new_mails_cur:1;
	unsigned int have_uncached_filenames:1;
};

static int maildir_sync_cur_dir(struct maildir_sync_context *ctx);

/* a char* hash function from ASU -- from glib */
static unsigned int maildir_hash(const void *p)
{
        const unsigned char *s = p;
	unsigned int g, h = 0;

	while (*s != ':' && *s != '\0') {
		h = (h << 4) + *s;
		if ((g = h & 0xf0000000UL)) {
			h = h ^ (g >> 24);
			h = h ^ g;
		}
		s++;
	}

	return h;
}

static int maildir_cmp(const void *p1, const void *p2)
{
	const char *s1 = p1, *s2 = p2;

	while (*s1 == *s2 && *s1 != ':' && *s1 != '\0') {
		s1++; s2++;
	}
	if ((*s1 == '\0' || *s1 == ':') &&
	    (*s2 == '\0' || *s2 == ':'))
		return 0;
	return *s1 - *s2;
}

static int maildir_update_flags(struct maildir_sync_context *ctx,
				struct mail_index_record *rec,
				unsigned int seq, const char *new_fname)
{
	enum mail_flags flags;

	if (ctx->index->lock_type != MAIL_LOCK_EXCLUSIVE)
		return TRUE;

	flags = maildir_filename_get_flags(new_fname, rec->msg_flags);
	if (flags != rec->msg_flags) {
		if (!ctx->index->update_flags(ctx->index, rec,
					      seq, MODIFY_REPLACE, flags, TRUE))
			return FALSE;
	}

	return TRUE;
}

static int maildir_sync_open_uidlist(struct maildir_sync_context *ctx)
{
	struct mail_index *index = ctx->index;
	struct stat st;
	const char *path;

	if (ctx->uidlist != NULL)
		return TRUE;

	/* open it only if it's changed since we last synced it,
	   or if we have uncached filenames. */
	path = t_strconcat(index->control_dir, "/" MAILDIR_UIDLIST_NAME, NULL);
	if (stat(path, &st) < 0) {
		if (errno == ENOENT) {
			/* doesn't exist yet, create it */
			switch (maildir_uidlist_try_lock(ctx->index)) {
			case -1:
				return FALSE;
			case 1:
				ctx->uidlist_rewrite = TRUE;
				break;
			}

			return TRUE;
		}
		return index_file_set_syscall_error(index, path, "stat()");
	}

	/* FIXME: last_uidlist_mtime should be in index headers */
	if (st.st_mtime == index->last_uidlist_mtime &&
	    !ctx->have_uncached_filenames)
		return TRUE;

	ctx->uidlist = maildir_uidlist_open(index);
	if (ctx->uidlist == NULL)
		return TRUE;

	if (ctx->uidlist->uid_validity != index->header->uid_validity) {
		/* uidvalidity changed */
		if (!index->rebuilding && index->opened) {
			index_set_corrupted(index,
					    "UIDVALIDITY changed in uidlist");
			return FALSE;
		}

		index->header->uid_validity = ctx->uidlist->uid_validity;
		i_assert(index->header->next_uid == 1);
	}

	if (index->header->next_uid > ctx->uidlist->next_uid) {
		index_set_corrupted(index, "index.next_uid (%u) > "
				    "uidlist.next_uid (%u)",
				    index->header->next_uid,
				    ctx->uidlist->next_uid);
		return FALSE;
	}

	return TRUE;
}

static void uidlist_hash_get_filenames(void *key, void *value, void *context)
{
	buffer_t *buf = context;
	struct maildir_hash_rec *hash_rec = value;

	if (ACTION(hash_rec) == MAILDIR_FILE_ACTION_NEW)
		buffer_append(buf, (const void *) &key, sizeof(const char *));
}

static int maildir_time_cmp(const void *p1, const void *p2)
{
	const char *s1 = *((const char **) p1);
	const char *s2 = *((const char **) p2);
	time_t t1 = 0, t2 = 0;

	/* we have to do numeric comparision, strcmp() will break when
	   there's different amount of digits (mostly the 999999999 ->
	   1000000000 change in Sep 9 2001) */
	while (*s1 >= '0' && *s1 <= '9') {
		t1 = t1*10 + (*s1 - '0');
		s1++;
	}
	while (*s2 >= '0' && *s2 <= '9') {
		t2 = t2*10 + (*s2 - '0');
		s2++;
	}

	return t1 < t2 ? -1 : t1 > t2 ? 1 : 0;
}

static int maildir_full_sync_finish_new_mails(struct maildir_sync_context *ctx)
{
	const char *dir, **new_files;
	buffer_t *buf;
	unsigned int i;
	int new_dir;

	ctx->uidlist_rewrite = TRUE;

	/* then there's the completely new mails. sort them by the filename
	   so we should get them to same order as they were created. */
	buf = buffer_create_static_hard(ctx->pool,
					ctx->new_count * sizeof(const char *));
	hash_foreach(ctx->files, uidlist_hash_get_filenames, buf);
	i_assert(buffer_get_used_size(buf) ==
		 ctx->new_count * sizeof(const char *));

	new_files = buffer_get_modifyable_data(buf, NULL);
	qsort(new_files, ctx->new_count, sizeof(const char *),
	      maildir_time_cmp);

	if (!ctx->index->maildir_keep_new) {
		dir = ctx->cur_dir;
		new_dir = FALSE;
	} else {
		/* this is actually slightly wrong, because we don't really
		   know if some of the new messages are in cur/ already.
		   we could know that by saving it into buffer, but that'd
		   require extra memory. luckily it doesn't really matter if
		   we say it's in new/, but it's actually in cur/. we have
		   to deal with such case anyway since another client might
		   have just moved it. */
		dir = ctx->new_dir;
		new_dir = TRUE;
		ctx->index->maildir_have_new = TRUE;
	}

	for (i = 0; i < ctx->new_count; i++) {
		if (!maildir_index_append_file(&ctx->trans_ctx, ctx->index,
					       new_files[i], new_dir))
			return FALSE;
	}
	ctx->new_count = 0;

	return TRUE;
}

static int maildir_full_sync_finish(struct maildir_sync_context *ctx)
{
	struct mail_index *index = ctx->index;
        struct maildir_uidlist *uidlist;
	struct mail_index_record *rec, *first_rec, *last_rec;
	struct maildir_hash_rec *hash_rec;
	struct maildir_uidlist_rec uid_rec;
        enum maildir_file_action action;
	const char *fname, *dir;
	void *orig_key, *orig_value;
	unsigned int seq, first_seq, last_seq, uid, last_uid, new_flag;
	int new_dir, skip_next;

	if (ctx->new_count > 0) {
		/* new mails, either they're already in uidlist or we have
		   to add them there. If we want to add them, we'll need to
		   sync it locked. */
		if (maildir_uidlist_try_lock(ctx->index) < 0)
			return FALSE;

		if (!maildir_sync_open_uidlist(ctx))
			return FALSE;
	}

        seq = 1;
	rec = index->lookup(index, 1);
	uidlist = ctx->uidlist;

	if (uidlist == NULL)
		memset(&uid_rec, 0, sizeof(uid_rec));
	else {
		if (maildir_uidlist_next(uidlist, &uid_rec) < 0)
			return FALSE;
	}

	first_rec = last_rec = NULL;
	first_seq = last_seq = 0;
	skip_next = FALSE;
	while (rec != NULL) {
		uid = rec->uid;

		/* skip over the expunged records in uidlist */
		while (uid_rec.uid != 0 && uid_rec.uid < uid) {
			if (maildir_uidlist_next(uidlist, &uid_rec) < 0)
				return FALSE;
		}

		fname = maildir_get_location(index, rec, NULL);
		if (fname == NULL) {
			/* filename not cached, it must be in uidlist or
			   it's expunged */
			fname = uid_rec.uid == rec->uid ?
				uid_rec.filename : NULL;
		}

		if (fname == NULL) {
			hash_rec = NULL;
			action = MAILDIR_FILE_ACTION_EXPUNGE;
		} else if (hash_lookup_full(ctx->files, fname,
					    &orig_key, &orig_value)) {
			hash_rec = orig_value;
			action = ACTION(hash_rec);
		} else {
			/* none action */
			hash_rec = NULL;
			action = MAILDIR_FILE_ACTION_NONE;
		}

		if (uid_rec.uid == uid &&
		    maildir_cmp(fname, uid_rec.filename) != 0) {
			index_set_corrupted(index,
				"Filename mismatch for UID %u: %s vs %s",
				uid, fname, uid_rec.filename);
			return FALSE;
		}

		if (uid_rec.uid > uid && hash_rec != NULL &&
		    (action == MAILDIR_FILE_ACTION_UPDATE_FLAGS ||
		     action == MAILDIR_FILE_ACTION_NONE)) {
			/* it's UID has changed. shouldn't happen. */
			index_set_corrupted(index,
					    "UID changed for %s/%s: %u -> %u",
					    index->mailbox_path, fname,
					    uid, uid_rec.uid);
			return FALSE;
		}

		switch (action) {
		case MAILDIR_FILE_ACTION_EXPUNGE:
			if (first_rec == NULL) {
				first_rec = rec;
				first_seq = seq;
			}
			last_rec = rec;
			last_seq = seq;
			break;
		case MAILDIR_FILE_ACTION_NEW:
			/* filename wasn't cached */
			new_flag = hash_rec->action & MAILDIR_FILE_FLAG_NEWDIR;
			hash_rec->action = MAILDIR_FILE_ACTION_NONE | new_flag;
			ctx->new_count--;

			if (!maildir_cache_update_file(&ctx->trans_ctx, index,
						       rec, fname, new_flag))
				return FALSE;
			/* fall through */
		case MAILDIR_FILE_ACTION_UPDATE_FLAGS:
			new_dir = (hash_rec->action &
				   MAILDIR_FILE_FLAG_NEWDIR) != 0;
			maildir_index_update_filename(index, rec->uid,
						      orig_key, new_dir);
			if (!maildir_update_flags(ctx, rec, seq, orig_key))
				return FALSE;
			/* fall through */
		case MAILDIR_FILE_ACTION_NONE:
			if (first_rec != NULL) {
				if (!index->expunge(index, first_rec, last_rec,
						    first_seq, last_seq, TRUE))
					return FALSE;
				first_rec = NULL;

				seq = first_seq;
				rec = index->lookup(index, seq);
				skip_next = TRUE;
			}
			break;
		default:
			i_unreached();
		}

		if (uid_rec.uid == uid) {
			if (maildir_uidlist_next(uidlist, &uid_rec) < 0)
				return FALSE;
		}

		if (skip_next)
			skip_next = FALSE;
		else {
			rec = index->next(index, rec);
			seq++;
		}
	}

	if (first_rec != NULL) {
		if (!index->expunge(index, first_rec, last_rec,
				    first_seq, last_seq, TRUE))
			return FALSE;
		seq = first_seq;
	}

	if (seq-1 != index->header->messages_count) {
		index_set_corrupted(index,
				    "Wrong messages_count in header (%u != %u)",
				    seq, index->header->messages_count);
		return FALSE;
	}

	/* if there's new mails which are already in uidlist, get them */
	last_uid = 0;
	while (uid_rec.uid != 0) {
		if (hash_lookup_full(ctx->files, uid_rec.filename,
				     &orig_key, &orig_value))
			hash_rec = orig_value;
		else
			hash_rec = NULL;

		if (hash_rec != NULL &&
		    ACTION(hash_rec) == MAILDIR_FILE_ACTION_NONE) {
			/* it's a duplicate, shouldn't happen */
			i_error("%s: Found duplicate filename %s, rebuilding",
				ctx->uidlist->fname, uid_rec.filename);
			(void)unlink(ctx->uidlist->fname);

			if (INDEX_IS_UIDLIST_LOCKED(index))
				ctx->uidlist_rewrite = TRUE;
			hash_rec = NULL;
		}

		if (hash_rec != NULL) {
 			i_assert(ACTION(hash_rec) == MAILDIR_FILE_ACTION_NEW);

			/* make sure we set the same UID for it. */
			if (index->header->next_uid > uid_rec.uid) {
				index_set_corrupted(index,
						    "index.next_uid (%u) > "
						    "uid_rec.uid (%u)",
						    index->header->next_uid,
						    uid_rec.uid);
				return FALSE;
			}
			index->header->next_uid = uid_rec.uid;

			new_flag = hash_rec->action & MAILDIR_FILE_FLAG_NEWDIR;
			hash_rec->action = MAILDIR_FILE_ACTION_NONE | new_flag;
			ctx->new_count--;

			if (new_flag != 0)
				ctx->index->maildir_have_new = TRUE;
			dir = new_flag != 0 ? ctx->new_dir : ctx->cur_dir;

			if (!maildir_index_append_file(&ctx->trans_ctx, index,
						       orig_key, new_flag != 0))
				return FALSE;
		}

		if (maildir_uidlist_next(uidlist, &uid_rec) < 0)
			return FALSE;
	}

	if (ctx->uidlist != NULL) {
		/* update our next_uid. it should have been checked for
		   sanity already. */
		struct stat st;

		i_assert(index->header->next_uid <= ctx->uidlist->next_uid);
                index->header->next_uid = ctx->uidlist->next_uid;

		/* uidlist is now synced, remember that. */
		if (fstat(i_stream_get_fd(ctx->uidlist->input), &st) < 0) {
			return index_file_set_syscall_error(index,
							    ctx->uidlist->fname,
							    "fstat()");
		}
		index->last_uidlist_mtime = st.st_mtime;
	}

	if (ctx->new_count > 0 && INDEX_IS_UIDLIST_LOCKED(index))
                maildir_full_sync_finish_new_mails(ctx);

	/* all done (or can't do it since we don't have lock) */
	ctx->index->maildir_synced_once = TRUE;
	if (ctx->trans_ctx != NULL)
		mail_cache_transaction_commit(ctx->trans_ctx);
	return TRUE;
}

static int maildir_full_sync_init(struct maildir_sync_context *ctx,
				  int only_new)
{
	struct mail_index *index = ctx->index;
	struct mail_index_record *rec;
	struct maildir_hash_rec *hash_rec;
	const char *fname;
	size_t size;
	int new_dir, have_new;

	if (index->header->messages_count >= INT_MAX/32) {
		index_set_corrupted(index, "Header says %u messages",
				    index->header->messages_count);
		return FALSE;
	}

	/* we're resyncing everything, so reset the filename hash */
	if (index->new_filenames != NULL) {
		hash_destroy(index->new_filenames);
		index->new_filenames = NULL;
	}

	if (index->new_filename_pool != NULL)
		p_clear(index->new_filename_pool);

	/* reset synced-flag too, just in case something fails and we don't
	   have up-to-date new_filenames */
	ctx->index->maildir_synced_once = FALSE;

	/* read current messages in index into hash */
	size = nearest_power(index->header->messages_count *
			     sizeof(struct maildir_hash_rec) + 1024);
	ctx->pool = pool_alloconly_create("maildir sync", I_MAX(size, 16384));
	ctx->files = hash_create(default_pool, ctx->pool,
				 index->header->messages_count * 2,
				 maildir_hash, maildir_cmp);
	ctx->new_count = 0;

	have_new = FALSE;

	/* Now we'll fill the hash with cached filenames. This is done mostly
	   just to save some memory since we can use pointers to mmaped cache
	   file. Note that all records may not have the filename cached.

	   WARNING: Cache file must not be modified as long as these pointers
	   exist, as modifying might change the mmap base address. The call
	   below makes sure that cache file is initially fully mmaped. */
	if (mail_cache_get_mmaped(index->cache, &size) == NULL)
		return FALSE;

	rec = index->lookup(index, 1);
	while (rec != NULL) {
		fname = maildir_get_location(index, rec, &new_dir);
		if (fname == NULL)
                        ctx->have_uncached_filenames = TRUE;

		if (new_dir)
			have_new = TRUE;

		if ((!only_new || new_dir) && fname != NULL) {
			hash_rec = p_new(ctx->pool, struct maildir_hash_rec, 1);
			hash_rec->rec = rec;
			hash_rec->action = MAILDIR_FILE_ACTION_EXPUNGE;

			if (hash_lookup(ctx->files, fname) != NULL) {
				index_set_corrupted(index,
					"Duplicated message %s", fname);
				return FALSE;
			}

			hash_insert(ctx->files, (void *) fname, hash_rec);
		}

		rec = index->next(index, rec);
	}

	index->maildir_have_new = have_new;
	return TRUE;
}

static int maildir_fix_duplicate(struct mail_index *index,
				 const char *old_fname, int new_dir)
{
	const char *new_fname, *old_path, *new_path;
	int ret = TRUE;

	t_push();

	old_path = t_strconcat(index->mailbox_path, new_dir ? "/new/" : "/cur/",
			       old_fname, NULL);

	new_fname = maildir_generate_tmp_filename(&ioloop_timeval);
	new_path = t_strconcat(index->mailbox_path, "/new/", new_fname, NULL);

	if (rename(old_path, new_path) == 0) {
		i_warning("Fixed duplicate in %s: %s -> %s",
			  index->mailbox_path, old_fname, new_fname);
	} else if (errno != ENOENT) {
		index_set_error(index, "rename(%s, %s) failed: %m",
				old_path, new_path);
		ret = FALSE;
	}
	t_pop();

	return ret;
}

static void maildir_sync_hash_fix_allocs(void *key, void *value, void *context)
{
        struct maildir_sync_context *ctx = context;
	struct maildir_hash_rec *hash_rec = value;

	switch (ACTION(hash_rec)) {
	case MAILDIR_FILE_ACTION_NONE:
		hash_remove(ctx->files, key);
		break;
	case MAILDIR_FILE_ACTION_EXPUNGE:
		if (hash_rec->action & MAILDIR_FILE_FLAG_ALLOCED) {
			/* we're getting here because our recently
			   inserted node is traversed as well */
			break;
		}

		hash_rec->action |= MAILDIR_FILE_FLAG_ALLOCED;
		hash_insert(ctx->files, p_strdup(ctx->pool, key), value);
		break;
	default:
		break;
	}
}

static int maildir_full_sync_dir(struct maildir_sync_context *ctx,
				 int new_dir, DIR *dirp, struct dirent *d)
{
	struct maildir_hash_rec *hash_rec;
	void *orig_key, *orig_value;
	int newflag;

	newflag = new_dir ? MAILDIR_FILE_FLAG_NEWDIR : 0;

	do {
		if (d->d_name[0] == '.')
			continue;

		if (!hash_lookup_full(ctx->files, d->d_name,
				      &orig_key, &orig_value)) {
			hash_rec = p_new(ctx->pool, struct maildir_hash_rec, 1);
		} else {
			hash_rec = orig_value;
			if (ACTION(hash_rec) != MAILDIR_FILE_ACTION_EXPUNGE) {
				if (!maildir_fix_duplicate(ctx->index,
							   d->d_name, new_dir))
					return FALSE;
				continue;
			}
		}

		if (hash_rec->rec == NULL) {
			/* new message */
			if (ctx->readonly_check &&
			    !ctx->have_uncached_filenames)
				continue;

			if (new_dir)
				ctx->new_mails_new = TRUE;
			else
				ctx->new_mails_cur = TRUE;

			ctx->new_count++;
			hash_rec->action = MAILDIR_FILE_ACTION_NEW | newflag;
			hash_insert(ctx->files, p_strdup(ctx->pool, d->d_name),
				    hash_rec);
			continue;
		}

		if (strcmp(orig_key, d->d_name) != 0) {
			hash_rec->action =
				MAILDIR_FILE_ACTION_UPDATE_FLAGS | newflag;

			hash_insert(ctx->files, p_strdup(ctx->pool, d->d_name),
				    hash_rec);
                        ctx->flag_updates = TRUE;
		} else {
			hash_rec->action = MAILDIR_FILE_ACTION_NONE | newflag;
		}
	} while ((d = readdir(dirp)) != NULL);

	/* records that are left to hash must not have any (filename) pointers
	   to cache file. So remove none actions, and p_strdup() expunge
	   actions. */
	hash_foreach(ctx->files, maildir_sync_hash_fix_allocs, ctx);

	return TRUE;
}

static int maildir_new_scan_first_file(struct maildir_sync_context *ctx)
{
	DIR *dirp;
	struct dirent *d;

	dirp = opendir(ctx->new_dir);
	if (dirp == NULL) {
		return index_file_set_syscall_error(ctx->index, ctx->new_dir,
						    "opendir()");
	}

	/* find first file */
	while ((d = readdir(dirp)) != NULL) {
		if (d->d_name[0] != '.')
			break;
	}

	if (d == NULL) {
		if (closedir(dirp) < 0) {
			index_file_set_syscall_error(ctx->index, ctx->new_dir,
						     "closedir()");
		}
	} else {
		ctx->new_dirp = dirp;
		ctx->new_dent = d;
	}

	return TRUE;
}

static int maildir_full_sync_dirs(struct maildir_sync_context *ctx)
{
	DIR *dirp;
	int failed;

	if (ctx->new_dirp == NULL &&
	    (ctx->index->maildir_have_new || ctx->index->maildir_keep_new)) {
		if (!maildir_new_scan_first_file(ctx))
			return FALSE;
	}

	if (ctx->new_dent != NULL) {
		if (!maildir_full_sync_dir(ctx, TRUE, ctx->new_dirp,
					   ctx->new_dent))
			return FALSE;
                ctx->new_dent = NULL;
	}

	dirp = opendir(ctx->cur_dir);
	if (dirp == NULL) {
		return index_file_set_syscall_error(ctx->index, ctx->cur_dir,
						    "opendir()");
	}

	failed = !maildir_full_sync_dir(ctx, FALSE, dirp, readdir(dirp));

	if (closedir(dirp) < 0) {
		return index_file_set_syscall_error(ctx->index, ctx->cur_dir,
						    "closedir()");
	}

	return !failed;
}

static int maildir_sync_new_dir_full(struct maildir_sync_context *ctx)
{
	if (!ctx->index->set_lock(ctx->index, MAIL_LOCK_EXCLUSIVE))
		return FALSE;

	if (!maildir_full_sync_init(ctx, TRUE))
		return FALSE;

	if (!maildir_full_sync_dir(ctx, TRUE, ctx->new_dirp, ctx->new_dent))
		return FALSE;
	ctx->new_dent = NULL;

	if (!maildir_full_sync_finish(ctx))
		return FALSE;

	return TRUE;
}

static int maildir_sync_new_dir(struct maildir_sync_context *ctx,
				int move_to_cur, int append_index)
{
	struct dirent *d;
	string_t *sourcepath, *destpath;
	const char *final_dir;

	if (append_index) {
		if (ctx->index->maildir_have_new) {
			/* some of the mails in new/ are already indexed.
			   we'll have to do a full sync. */
			return maildir_sync_new_dir_full(ctx);
		}

		if (!ctx->index->set_lock(ctx->index, MAIL_LOCK_EXCLUSIVE))
			return FALSE;

		switch (maildir_uidlist_try_lock(ctx->index)) {
		case -1:
			return FALSE;
		case 0:
			/* couldn't get a lock.
			   no point in doing more. */
			return TRUE;
		}

		/* make sure uidlist is up to date.
		   if it's not, do a full sync. */
		if (!maildir_sync_open_uidlist(ctx))
			return FALSE;

		if (ctx->uidlist != NULL)
			return maildir_sync_cur_dir(ctx);

		ctx->uidlist_rewrite = TRUE;
	}

	d = ctx->new_dent;
	ctx->new_dent = NULL;

	sourcepath = t_str_new(PATH_MAX);
	destpath = t_str_new(PATH_MAX);

	final_dir = move_to_cur ? ctx->cur_dir : ctx->new_dir;

	do {
		if (d->d_name[0] == '.')
			continue;

		str_truncate(sourcepath, 0);
		str_printfa(sourcepath, "%s/%s", ctx->new_dir, d->d_name);

		if (move_to_cur) {
			str_truncate(destpath, 0);
			str_printfa(destpath, "%s/%s", ctx->cur_dir, d->d_name);

			if (rename(str_c(sourcepath), str_c(destpath)) < 0 &&
			    errno != ENOENT) {
				if (ENOSPACE(errno))
					ctx->index->nodiskspace = TRUE;
				else if (errno == EACCES)
					ctx->index->mailbox_readonly = TRUE;
				else {
					index_set_error(ctx->index,
						"rename(%s, %s) failed: %m",
						str_c(sourcepath),
						str_c(destpath));
					return FALSE;
				}

				ctx->index->maildir_keep_new = TRUE;
				if (!append_index) {
					ctx->new_dent = d;
					return TRUE;
				}

				/* continue by keeping them in new/ dir */
				final_dir = ctx->new_dir;
				move_to_cur = FALSE;
			}
		}

		if (append_index) {
			if (!move_to_cur)
				ctx->index->maildir_have_new = TRUE;

			t_push();
			if (!maildir_index_append_file(&ctx->trans_ctx,
						       ctx->index, d->d_name,
						       !move_to_cur)) {
				t_pop();
				return FALSE;
			}
			t_pop();
		}
	} while ((d = readdir(ctx->new_dirp)) != NULL);

	return TRUE;
}

static int maildir_sync_cur_dir(struct maildir_sync_context *ctx)
{
	struct mail_index *index = ctx->index;

	if (ctx->new_dent != NULL && !index->maildir_keep_new) {
		/* there's also new mails. move them into cur/ first, if we
		   can lock the uidlist */
		switch (maildir_uidlist_try_lock(index)) {
		case -1:
			return FALSE;
		case 1:
			if (!maildir_sync_new_dir(ctx, TRUE, FALSE))
				return FALSE;
		}
	}

	if (!index->set_lock(index, MAIL_LOCK_EXCLUSIVE))
		return FALSE;

	if (!maildir_full_sync_init(ctx, FALSE) ||
	    !maildir_full_sync_dirs(ctx) ||
	    !maildir_full_sync_finish(ctx))
		return FALSE;

	return TRUE;
}

static int maildir_index_sync_context(struct maildir_sync_context *ctx,
				      int *changes)

{
        struct mail_index *index = ctx->index;
	struct stat st;
	time_t new_mtime, cur_mtime;

	if (!maildir_try_flush_dirty_flags(ctx->index, FALSE))
		return FALSE;

	if (index->fd != -1) {
		/* FIXME: file_sync_stamp should be in index file's headers.
		   it should also contain maildir_cur_dirty. */
		if (fstat(index->fd, &st) < 0)
			return index_set_syscall_error(index, "fstat()");
		index->file_sync_stamp = st.st_mtime;
	}

	if (stat(ctx->new_dir, &st) < 0) {
		index_file_set_syscall_error(index, ctx->new_dir, "stat()");
		return FALSE;
	}
	new_mtime = st.st_mtime;

	if (stat(ctx->cur_dir, &st) < 0) {
		index_file_set_syscall_error(index, ctx->cur_dir, "stat()");
		return FALSE;
	}
	cur_mtime = st.st_mtime;

	if (new_mtime != index->last_new_mtime ||
	    new_mtime >= ioloop_time - MAILDIR_SYNC_SECS) {
		if (!maildir_new_scan_first_file(ctx))
			return FALSE;
	}

	if (cur_mtime != index->file_sync_stamp ||
	    (index->maildir_cur_dirty != 0 &&
	     index->maildir_cur_dirty < ioloop_time - MAILDIR_SYNC_SECS)) {
		/* cur/ changed, or delayed cur/ check */
		if (changes != NULL)
			*changes = TRUE;

		if (!maildir_sync_cur_dir(ctx))
			return FALSE;
	}

	if (ctx->new_dent != NULL) {
		if (changes != NULL)
			*changes = TRUE;

		if (!maildir_sync_new_dir(ctx, !index->maildir_keep_new, TRUE))
			return FALSE;

		/* this will set maildir_cur_dirty. it may actually be
		   different from cur/'s mtime if we're unlucky, but that only
		   causes extra sync and it's not worth the extra stat() */
		if (ctx->new_dent == NULL &&
		    (ctx->new_count == 0 || !ctx->new_mails_new))
			cur_mtime = time(NULL);
	}

	if (ctx->uidlist_rewrite) {
		i_assert(INDEX_IS_UIDLIST_LOCKED(index));

		if (!maildir_uidlist_rewrite(index, &index->last_uidlist_mtime))
			return FALSE;
	}

	if (index->lock_type == MAIL_LOCK_EXCLUSIVE) {
		if (index->maildir_have_new)
			index->header->flags |= MAIL_INDEX_FLAG_MAILDIR_NEW;
		else
			index->header->flags &= ~MAIL_INDEX_FLAG_MAILDIR_NEW;
	}

	if (index->maildir_cur_dirty == 0 ||
	    index->maildir_cur_dirty < ioloop_time - MAILDIR_SYNC_SECS) {
		if (cur_mtime >= ioloop_time - MAILDIR_SYNC_SECS)
			index->maildir_cur_dirty = cur_mtime;
		else if (ctx->new_count == 0 || !ctx->new_mails_cur)
			index->maildir_cur_dirty = 0;
		else {
			/* uidlist is locked, wait for a while before
			   trying again */
			index->maildir_cur_dirty = ioloop_time;
		}
	}

	index->file_sync_stamp = cur_mtime;
	if (ctx->new_dent == NULL &&
	    (ctx->new_count == 0 || !ctx->new_mails_new))
		index->last_new_mtime = new_mtime;

	return TRUE;
}

static int maildir_full_sync_finish_readonly(struct maildir_sync_context *ctx)
{
	struct mail_index *index = ctx->index;
	struct mail_index_record *rec;
	struct maildir_hash_rec *hash_rec;
	struct maildir_uidlist *uidlist;
	struct maildir_uidlist_rec uid_rec;
	void *orig_key, *orig_value;
	const char *fname;
	unsigned int seq;
	int new_dir, tried_uidlist;

	if (!ctx->flag_updates && !ctx->have_uncached_filenames) {
		ctx->index->maildir_synced_once = TRUE;
		return TRUE;
	}

	memset(&uid_rec, 0, sizeof(uid_rec));
	uidlist = ctx->uidlist;
	tried_uidlist = FALSE;

	rec = index->lookup(index, 1); seq = 1;
	for (; rec != NULL; rec = index->next(index, rec), seq++) {
		fname = maildir_get_location(index, rec, NULL);
		if (fname == NULL) {
			/* not cached, get it from uidlist */
			if (uidlist == NULL && !tried_uidlist) {
				ctx->have_uncached_filenames = TRUE;
				if (!maildir_sync_open_uidlist(ctx))
					return FALSE;

				uidlist = ctx->uidlist;
				tried_uidlist = TRUE;

				/* get the initial record */
				if (uidlist != NULL &&
				    maildir_uidlist_next(uidlist, &uid_rec) < 0)
					return FALSE;
			}

			if (uidlist == NULL) {
				/* uidlist doesn't exist? shouldn't happen */
				continue;
			}

			while (uid_rec.uid != 0 && uid_rec.uid < rec->uid) {
				if (maildir_uidlist_next(uidlist, &uid_rec) < 0)
					return FALSE;
			}

			if (uid_rec.uid != rec->uid) {
				/* not in uidlist, it's expunged */
				continue;
			}

			fname = uid_rec.filename;
		}

		if (!hash_lookup_full(ctx->files, fname,
				      &orig_key, &orig_value))
			continue;

		hash_rec = orig_value;
		if (ACTION(hash_rec) != MAILDIR_FILE_ACTION_UPDATE_FLAGS &&
		    ACTION(hash_rec) != MAILDIR_FILE_ACTION_NEW)
			continue;

		new_dir = (hash_rec->action & MAILDIR_FILE_FLAG_NEWDIR) != 0;
		maildir_index_update_filename(index, rec->uid,
					      orig_key, new_dir);

		if (!maildir_update_flags(ctx, rec, seq, orig_key))
			return FALSE;
	}

	ctx->index->maildir_synced_once = TRUE;
	return TRUE;
}

static int maildir_index_sync_context_readonly(struct maildir_sync_context *ctx)
{
	struct mail_index *index = ctx->index;
	struct stat st;
	int cur_changed;

	i_assert(index->lock_type != MAIL_LOCK_UNLOCK);

	if (!index->maildir_synced_once) {
		/* we haven't synced yet in this session. do it */
		cur_changed = TRUE;
	} else {
		if (stat(ctx->cur_dir, &st) < 0) {
			index_file_set_syscall_error(index, ctx->cur_dir,
						     "stat()");
			return FALSE;
		}

		cur_changed = st.st_mtime != index->file_sync_stamp ||
			index->maildir_cur_dirty != 0;
	}

	if (!cur_changed) {
		if (!index->maildir_have_new) {
			/* no changes */
			return TRUE;
		}

		if (stat(ctx->new_dir, &st) < 0) {
			return index_file_set_syscall_error(index, ctx->new_dir,
							    "stat()");
		}
		if (st.st_mtime == index->last_new_mtime &&
		    st.st_mtime < ioloop_time - MAILDIR_SYNC_SECS) {
			/* no changes */
			return TRUE;
		}

		if (!maildir_new_scan_first_file(ctx))
			return FALSE;
	}

	/* ok, something's changed. check only changes in file names. */

	/* if we can get exclusive lock, we can update the index
	   directly. but don't rely on it. */
	(void)index->try_lock(index, MAIL_LOCK_EXCLUSIVE);

	if (!maildir_full_sync_init(ctx, FALSE) ||
	    !maildir_full_sync_dirs(ctx) ||
	    !maildir_full_sync_finish_readonly(ctx))
		return FALSE;

	return TRUE;
}

static void maildir_index_sync_deinit(struct maildir_sync_context *ctx)
{
	// FIXME: remove new flags from cache if needed
	if (ctx->trans_ctx != NULL)
                mail_cache_transaction_end(ctx->trans_ctx);
	if (ctx->uidlist != NULL)
		maildir_uidlist_close(ctx->uidlist);
	if (ctx->files != NULL)
		hash_destroy(ctx->files);
	if (ctx->pool != NULL)
		pool_unref(ctx->pool);

	if (ctx->new_dirp != NULL) {
		if (closedir(ctx->new_dirp) < 0) {
			index_file_set_syscall_error(ctx->index, ctx->new_dir,
						     "closedir()");
		}
	}

	maildir_uidlist_unlock(ctx->index);
}

static struct maildir_sync_context *
maildir_sync_context_new(struct mail_index *index)
{
        struct maildir_sync_context *ctx;

	ctx = t_new(struct maildir_sync_context, 1);
	ctx->index = index;
	ctx->new_dir = t_strconcat(index->mailbox_path, "/new", NULL);
	ctx->cur_dir = t_strconcat(index->mailbox_path, "/cur", NULL);
	return ctx;
}

int maildir_index_sync_readonly(struct mail_index *index,
				const char *fname, int *found)
{
        struct maildir_sync_context *ctx;
	struct maildir_hash_rec *hash_rec;
	int ret;

	ctx = maildir_sync_context_new(index);
	ctx->readonly_check = TRUE;

	ret = maildir_index_sync_context_readonly(ctx);

	if (!ret || ctx->files == NULL || fname == NULL)
		*found = FALSE;
	else {
		hash_rec = hash_lookup(ctx->files, fname);
		*found = hash_rec != NULL &&
			hash_rec->action != MAILDIR_FILE_ACTION_EXPUNGE;
	}
	maildir_index_sync_deinit(ctx);
	return ret;
}

int maildir_index_sync(struct mail_index *index, int minimal_sync,
		       enum mail_lock_type data_lock_type __attr_unused__,
		       int *changes)
{
        struct maildir_sync_context *ctx;
	int ret;

	i_assert(index->lock_type != MAIL_LOCK_SHARED);

	if (changes != NULL)
		*changes = FALSE;

	if (minimal_sync)
		return TRUE;

	ctx = maildir_sync_context_new(index);
	ret = maildir_index_sync_context(ctx, changes);
        maildir_index_sync_deinit(ctx);
	return ret;
}
