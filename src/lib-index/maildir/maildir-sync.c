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
#include "buffer.h"
#include "istream.h"
#include "hash.h"
#include "ioloop.h"
#include "str.h"
#include "maildir-index.h"
#include "maildir-uidlist.h"
#include "mail-index-data.h"
#include "mail-index-util.h"

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
	MAILDIR_FILE_ACTION_UPDATE_CONTENT,
	MAILDIR_FILE_ACTION_NEW,
	MAILDIR_FILE_ACTION_NONE,

	MAILDIR_FILE_FLAG_NEWDIR = 0x1000
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
#define ACTION(hash) ((hash)->action & 0x0f)

struct maildir_sync_context {
        struct mail_index *index;
	const char *new_dir, *cur_dir;

	pool_t pool;
	struct hash_table *files;
	unsigned int new_count;

	DIR *new_dirp;
	struct dirent *new_dent;

	struct maildir_uidlist *uidlist;
	unsigned int readonly_check:1;
	unsigned int flag_updates:1;
};

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
	    (*s2 == '\0' || *s2 == '\0'))
		return 0;
	return *s1 - *s2;
}

static void maildir_update_filename_memory(struct mail_index *index,
					   const char *fname)
{
	char *new_fname;

	if (index->new_filename_pool == NULL) {
		index->new_filename_pool =
			pool_alloconly_create("Maildir fname", 10240);
	}
	if (index->new_filenames == NULL) {
		index->new_filenames =
			hash_create(system_pool, index->new_filename_pool, 0,
				    maildir_hash, maildir_cmp);
	}

	new_fname = p_strdup(index->new_filename_pool, fname);
	hash_insert(index->new_filenames, new_fname, new_fname);
}

static int maildir_update_filename(struct maildir_sync_context *ctx,
				   struct mail_index_record *rec,
				   const char *new_fname)
{
	struct mail_index_update *update;

	if (ctx->index->lock_type != MAIL_LOCK_EXCLUSIVE) {
		maildir_update_filename_memory(ctx->index, new_fname);
		return TRUE;
	}

	update = ctx->index->update_begin(ctx->index, rec);
	ctx->index->update_field(update, DATA_FIELD_LOCATION, new_fname, 0);
	return ctx->index->update_end(update);
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
					      seq, flags, TRUE))
			return FALSE;
	}

	return TRUE;
}

static int is_file_content_changed(struct mail_index *index,
				   struct mail_index_record *rec,
				   const char *dir, const char *fname)
{
#define DATA_HDR_SIZE (DATA_HDR_HEADER_SIZE | DATA_HDR_BODY_SIZE)
	struct mail_index_data_record_header *data_hdr;
	struct stat st;
	const char *path;

	if ((rec->data_fields & DATA_HDR_INTERNAL_DATE) == 0 &&
	    (rec->data_fields & DATA_HDR_SIZE) != DATA_HDR_SIZE) {
		/* nothing in cache, we can't know if it's changed */
		return FALSE;
	}

	t_push();
	path = t_strdup_printf("%s/%s", dir, fname);

	if (stat(path, &st) < 0) {
		if (errno != ENOENT)
			index_file_set_syscall_error(index, path, "stat()");
		t_pop();
		return FALSE;
	}
	t_pop();

	data_hdr = mail_index_data_lookup_header(index->data, rec);
	if (data_hdr == NULL)
		return FALSE;

	if ((rec->data_fields & DATA_HDR_INTERNAL_DATE) != 0 &&
	    st.st_mtime != data_hdr->internal_date)
		return TRUE;

	if ((rec->data_fields & DATA_HDR_SIZE) == DATA_HDR_SIZE &&
	    (uoff_t)st.st_size != data_hdr->body_size + data_hdr->header_size)
		return TRUE;

	return FALSE;
}

static void uidlist_hash_get_filenames(void *key, void *value, void *context)
{
	buffer_t *buf = context;
	struct maildir_hash_rec *hash_rec = value;

	if (ACTION(hash_rec) == MAILDIR_FILE_ACTION_NEW)
		buffer_append(buf, (const void *) &key, sizeof(key));
}

static int maildir_sync_uidlist(struct maildir_sync_context *ctx)
{
	struct mail_index *index = ctx->index;
        struct maildir_uidlist *uidlist = ctx->uidlist;
	struct mail_index_record *rec;
	struct maildir_hash_rec *hash_rec;
        struct maildir_uidlist_rec uid_rec;
	const char *fname, **new_files, *dir;
	void *orig_key, *orig_value;
	unsigned int seq, uid, last_uid, i, new_flag;
	int new_dir;
	buffer_t *buf;

        seq = 0;
	rec = index->lookup(index, 1);

	if (uidlist == NULL)
		memset(&uid_rec, 0, sizeof(uid_rec));
	else {
		if (maildir_uidlist_next(uidlist, &uid_rec) < 0)
			return FALSE;
	}

	while (rec != NULL) {
		seq++; uid = rec->uid;

		/* skip over the expunged records in uidlist */
		while (uid_rec.uid != 0 && uid_rec.uid < uid) {
			uidlist->rewrite = TRUE;
			if (maildir_uidlist_next(uidlist, &uid_rec) < 0)
				return FALSE;
		}

		fname = maildir_get_location(index, rec);
		if (fname == NULL)
			return FALSE;

		hash_rec = hash_lookup(ctx->files, fname);
		if (hash_rec == NULL) {
			index_set_corrupted(index,
				"Unexpectedly lost file %s from hash", fname);
			return FALSE;
		}

		if (uid_rec.uid == uid &&
		    maildir_cmp(fname, uid_rec.filename) != 0) {
			index_set_corrupted(index,
				"Filename mismatch for UID %u: %s vs %s",
				uid, fname, uid_rec.filename);
			return FALSE;
		}

		if (uid_rec.uid > uid &&
		    (ACTION(hash_rec) == MAILDIR_FILE_ACTION_UPDATE_FLAGS ||
		     ACTION(hash_rec) == MAILDIR_FILE_ACTION_NONE)) {
			/* it's UID has changed */
			hash_rec->action = MAILDIR_FILE_ACTION_UPDATE_CONTENT |
				(hash_rec->action & MAILDIR_FILE_FLAG_NEWDIR);

			/* make sure filename is not invalidated by expunge */
			hash_insert(ctx->files, p_strdup(ctx->pool, fname),
				    hash_rec);
		}

		switch (ACTION(hash_rec)) {
		case MAILDIR_FILE_ACTION_EXPUNGE:
			if (!index->expunge(index, rec, seq, TRUE))
				return FALSE;
			seq--;
			break;
		case MAILDIR_FILE_ACTION_UPDATE_FLAGS:
			if (!maildir_update_flags(ctx, rec, seq, fname))
				return FALSE;
			break;
		case MAILDIR_FILE_ACTION_UPDATE_CONTENT:
			if (!index->expunge(index, rec, seq, TRUE))
				return FALSE;
			seq--;
			hash_rec->action = MAILDIR_FILE_ACTION_NEW |
				(hash_rec->action & MAILDIR_FILE_FLAG_NEWDIR);
			ctx->new_count++;
			break;
		case MAILDIR_FILE_ACTION_NONE:
			break;
		default:
			i_unreached();
		}

		if (uid_rec.uid == uid) {
			if (maildir_uidlist_next(uidlist, &uid_rec) < 0)
				return FALSE;
		}
		rec = index->next(index, rec);
	}

	if (seq != index->header->messages_count) {
		index_set_corrupted(index, "Wrong messages_count in header "
				    "(%u != %u)", seq,
				    index->header->messages_count);
		return FALSE;
	}

	/* if there's new mails which are already in uidlist, get them */
	last_uid = 0;
	while (uid_rec.uid != 0) {
		if (!hash_lookup_full(ctx->files, uid_rec.filename,
				      &orig_key, &orig_value)) {
			/* expunged */
			if (uidlist != NULL)
				uidlist->rewrite = TRUE;
		} else {
			hash_rec = orig_value;
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

			if (!maildir_index_append_file(index, dir, orig_key,
						       new_flag != 0))
				return FALSE;
		}

		if (maildir_uidlist_next(uidlist, &uid_rec) < 0)
			return FALSE;
	}

	if (ctx->new_count == 0 || !INDEX_IS_UIDLIST_LOCKED(index)) {
		/* all done (or can't do it since we don't have lock) */
		return TRUE;
	}

	if (uidlist != NULL)
		uidlist->rewrite = TRUE;

	/* then there's the completely new mails. sort them by the filename
	   so we should get them to same order as they were created. */
	buf = buffer_create_static_hard(ctx->pool,
					ctx->new_count * sizeof(const char *));
	hash_foreach(ctx->files, uidlist_hash_get_filenames, buf);
	i_assert(buffer_get_used_size(buf) / sizeof(const char *) <=
		 ctx->new_count);

	new_files = buffer_get_modifyable_data(buf, NULL);
	qsort(new_files, ctx->new_count, sizeof(const char *),
	      (int (*)(const void *, const void *)) strcmp);

	if (!index->maildir_keep_new) {
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
		if (!maildir_index_append_file(index, dir,
					       new_files[i], new_dir))
			return FALSE;
	}

	return TRUE;
}

static int maildir_index_full_sync_init(struct maildir_sync_context *ctx)
{
	struct mail_index *index = ctx->index;
	struct mail_index_record *rec;
	struct maildir_hash_rec *hash_rec;
	const char *fname;
	size_t size;
	int have_new;

	if (index->header->messages_count >= INT_MAX/32) {
		index_set_corrupted(index, "Header says %u messages",
				    index->header->messages_count);
		return FALSE;
	}

	/* read current messages in index into hash */
	size = nearest_power(index->header->messages_count *
			     sizeof(struct maildir_hash_rec) + 1024);
	ctx->pool = pool_alloconly_create("maildir sync", I_MAX(size, 16384));
	ctx->files = hash_create(default_pool, ctx->pool,
				 index->header->messages_count * 2,
				 maildir_hash, maildir_cmp);

	have_new = FALSE;

	rec = index->lookup(index, 1);
	while (rec != NULL) {
		fname = maildir_get_location(index, rec);
		if (fname == NULL)
			return FALSE;

		if ((rec->index_flags & INDEX_MAIL_FLAG_MAILDIR_NEW) != 0)
			have_new = TRUE;

		hash_rec = p_new(ctx->pool, struct maildir_hash_rec, 1);
		hash_rec->rec = rec;
		hash_rec->action = MAILDIR_FILE_ACTION_EXPUNGE;
		hash_insert(ctx->files, (void *) fname, hash_rec);

		rec = index->next(index, rec);
	}

	index->maildir_have_new = have_new;
	return TRUE;
}

static int maildir_index_full_sync_dir(struct maildir_sync_context *ctx,
				       const char *dir, int new_dir,
				       DIR *dirp, struct dirent *d)
{
	struct maildir_hash_rec *hash_rec;
	void *orig_key, *orig_value;
	int check_content_changes, newflag;

	newflag = new_dir ? MAILDIR_FILE_FLAG_NEWDIR : 0;

	/* Do we want to check changes in file contents? This slows down
	   things as we need to do extra stat() for all files. */
	check_content_changes = !ctx->readonly_check &&
		getenv("MAILDIR_CHECK_CONTENT_CHANGES") != NULL;

	do {
		if (d->d_name[0] == '.')
			continue;

		if (!hash_lookup_full(ctx->files, d->d_name,
				      &orig_key, &orig_value)) {
			hash_rec = p_new(ctx->pool, struct maildir_hash_rec, 1);
		} else {
			hash_rec = orig_value;
			if (ACTION(hash_rec) != MAILDIR_FILE_ACTION_EXPUNGE) {
				/* FIXME: duplicate */
				continue;
			}
		}

		if (hash_rec->rec == NULL) {
			/* new message */
			if (ctx->readonly_check)
				continue;

			ctx->new_count++;
			hash_rec->action = MAILDIR_FILE_ACTION_NEW | newflag;
			hash_insert(ctx->files, p_strdup(ctx->pool, d->d_name),
				    hash_rec);
			continue;
		}

		if (!new_dir && (hash_rec->rec->index_flags &
				 INDEX_MAIL_FLAG_MAILDIR_NEW) != 0 &&
		    ctx->index->lock_type == MAIL_LOCK_EXCLUSIVE) {
			/* mail was indexed in new/ but it has been
			   moved to cur/ later */
			hash_rec->rec->index_flags &=
				~INDEX_MAIL_FLAG_MAILDIR_NEW;
		}

		if (check_content_changes &&
		    is_file_content_changed(ctx->index, hash_rec->rec,
					    dir, d->d_name)) {
			/* file content changed, treat it as new message */
			hash_rec->action =
				MAILDIR_FILE_ACTION_UPDATE_CONTENT | newflag;

			/* make sure filename is not invalidated by expunge
			   later. the file name may have changed also. */
			hash_insert(ctx->files, p_strdup(ctx->pool, d->d_name),
				    hash_rec);
		} else if (strcmp(orig_key, d->d_name) != 0) {
			/* update file name now. flags later because we don't
			   know it's sequence number */
			hash_rec->action =
				MAILDIR_FILE_ACTION_UPDATE_FLAGS | newflag;
			if (!maildir_update_filename(ctx, hash_rec->rec,
						     d->d_name))
				return FALSE;
                        ctx->flag_updates = TRUE;
		} else {
			hash_rec->action = MAILDIR_FILE_ACTION_NONE | newflag;
		}
	} while ((d = readdir(dirp)) != NULL);

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

static int maildir_index_full_sync_dirs(struct maildir_sync_context *ctx)
{
	DIR *dirp;
	int failed;

	if (ctx->new_dirp == NULL &&
	    (ctx->index->maildir_have_new || ctx->index->maildir_keep_new)) {
		if (!maildir_new_scan_first_file(ctx))
			return FALSE;
	}

	if (ctx->new_dent != NULL) {
		if (!maildir_index_full_sync_dir(ctx, ctx->new_dir, TRUE,
						 ctx->new_dirp, ctx->new_dent))
			return FALSE;
	}

	dirp = opendir(ctx->cur_dir);
	if (dirp == NULL) {
		return index_file_set_syscall_error(ctx->index, ctx->cur_dir,
						    "opendir()");
	}

	failed = !maildir_index_full_sync_dir(ctx, ctx->cur_dir, FALSE,
					      dirp, readdir(dirp));

	if (closedir(dirp) < 0) {
		return index_file_set_syscall_error(ctx->index, ctx->cur_dir,
						    "closedir()");
	}

	return !failed;
}

static int maildir_sync_new_dir(struct maildir_sync_context *ctx,
				int move_to_cur, int append_index)
{
	struct dirent *d;
	string_t *sourcepath, *destpath;
	const char *final_dir;

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
			if (!maildir_index_append_file(ctx->index, final_dir,
						       d->d_name,
						       !move_to_cur)) {
				t_pop();
				return FALSE;
			}
			t_pop();
		}
	} while ((d = readdir(ctx->new_dirp)) != NULL);

	return TRUE;
}

static int maildir_index_sync_context(struct maildir_sync_context *ctx,
				      int *changes)

{
        struct mail_index *index = ctx->index;
	struct stat st;
	const char *uidlist_path;
	time_t uidlist_mtime, new_mtime, cur_mtime;
	int new_changed, full_sync;

	uidlist_path = t_strconcat(index->control_dir,
				   "/" MAILDIR_UIDLIST_NAME, NULL);

	if (index->fd == -1) {
		/* anon-mmaped */
		index->last_cur_mtime = index->file_sync_stamp;
	} else {
		/* FIXME: we should save it in index's header */
		if (fstat(index->fd, &st) < 0)
			return index_set_syscall_error(index, "fstat()");
		index->last_cur_mtime = st.st_mtime;
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

	if (new_mtime == index->last_new_mtime &&
	    new_mtime < ioloop_time - MAILDIR_SYNC_SECS)
		new_changed = FALSE;
	else {
		if (!maildir_new_scan_first_file(ctx))
			return FALSE;
		new_changed = ctx->new_dent != NULL;
	}

	if (cur_mtime != index->last_cur_mtime ||
	    (index->maildir_cur_dirty != 0 &&
	     index->maildir_cur_dirty < ioloop_time - MAILDIR_SYNC_SECS)) {
		/* cur/ changed, or delayed cur/ check */
		full_sync = TRUE;
	} else if (stat(uidlist_path, &st) < 0) {
		if (errno != ENOENT) {
			return index_file_set_syscall_error(index, uidlist_path,
							    "stat()");
		}

		/* have to create uidlist */
		full_sync = TRUE;
	} else if (st.st_mtime != index->last_uidlist_mtime) {
		/* uidlist changed */
		full_sync = TRUE;
	} else if (!new_changed) {
		/* no changes to anything */
		return TRUE;
	} else {
		full_sync = index->maildir_have_new;
	}

	if (maildir_uidlist_try_lock(index) < 0)
		return FALSE;

	/* we may or may not have succeeded. if we didn't,
	   just continue by syncing with existing uidlist file */

	if (!full_sync && !INDEX_IS_UIDLIST_LOCKED(index)) {
		/* just new mails in new/ dir, we can't sync them
		   if we can't get the lock. */
		return TRUE;
	}

	if (!index->set_lock(index, MAIL_LOCK_EXCLUSIVE))
		return FALSE;

	ctx->uidlist = maildir_uidlist_open(index);
	if (ctx->uidlist != NULL &&
	    ctx->uidlist->uid_validity != index->header->uid_validity) {
		/* uidvalidity changed */
		if (!index->rebuilding && index->opened) {
			index_set_corrupted(index,
					    "UIDVALIDITY changed in uidlist");
			return FALSE;
		}

		if (!index->rebuilding) {
			index->set_flags |= MAIL_INDEX_FLAG_REBUILD;
			return FALSE;
		}

		index->header->uid_validity = ctx->uidlist->uid_validity;
		i_assert(index->header->next_uid == 1);
	}

	if (ctx->uidlist != NULL) {
		/* get uidlist's mtime again now that we have opened the file.
		   it might have changed from out last check. */
		if (fstat(i_stream_get_fd(ctx->uidlist->input), &st) < 0) {
			return index_file_set_syscall_error(index, uidlist_path,
							    "fstat()");
		}
		uidlist_mtime = st.st_mtime;
	}

	if (ctx->uidlist != NULL &&
	    index->header->next_uid > ctx->uidlist->next_uid) {
		index_set_corrupted(index, "index.next_uid (%u) > "
				    "uidlist.next_uid (%u)",
				    index->header->next_uid,
				    ctx->uidlist->next_uid);
		return FALSE;
	}

	if (changes != NULL)
		*changes = TRUE;

	if (new_changed && full_sync &&
	    INDEX_IS_UIDLIST_LOCKED(index) && !index->maildir_keep_new) {
		/* we'll be syncing cur/ anyway, so move the mails from
		   new/ to cur/ first. */
		if (!maildir_sync_new_dir(ctx, TRUE, FALSE))
			return FALSE;

		/* new_dent is non-NULL only if rename() failed because there
		   was no disk space */
		new_changed = ctx->new_dent != NULL;
	}

	if (full_sync) {
		if (!maildir_index_full_sync_init(ctx) ||
		    !maildir_index_full_sync_dirs(ctx) ||
		    !maildir_sync_uidlist(ctx))
			return FALSE;
		new_changed = !INDEX_IS_UIDLIST_LOCKED(index);
	} else if (new_changed) {
		i_assert(INDEX_IS_UIDLIST_LOCKED(index));

		if (!maildir_sync_new_dir(ctx, !index->maildir_keep_new, TRUE))
			return FALSE;
		new_changed = FALSE;

		/* this will set maildir_cur_dirty. it may actually be
		   different from cur/'s mtime if we're unlucky, but that
		   doesn't really matter and it's not worth the extra stat() */
		cur_mtime = time(NULL);
	}

	if (ctx->uidlist != NULL &&
	    ctx->uidlist->next_uid > index->header->next_uid)
		index->header->next_uid = ctx->uidlist->next_uid;

	if (ctx->uidlist == NULL || ctx->uidlist->rewrite) {
		if (!INDEX_IS_UIDLIST_LOCKED(index)) {
			/* there's more new mails, but we need .lock file to
			   be able to sync them. */
			index->last_uidlist_mtime = uidlist_mtime;
			return TRUE;
		}

		if (!maildir_uidlist_rewrite(index, &uidlist_mtime))
			return FALSE;
	}

	if (cur_mtime < ioloop_time - MAILDIR_SYNC_SECS)
		index->maildir_cur_dirty = 0;
	else
		index->maildir_cur_dirty = cur_mtime;

	index->last_uidlist_mtime = uidlist_mtime;
	index->last_cur_mtime = cur_mtime;
	if (!new_changed)
		index->last_new_mtime = new_mtime;

	/* update sync stamp */
	index->file_sync_stamp = cur_mtime;

	return TRUE;
}

static int maildir_index_sync_readonly_flags(struct maildir_sync_context *ctx)
{
	struct mail_index *index = ctx->index;
	struct mail_index_record *rec;
	struct maildir_hash_rec *hash_rec;
	const char *fname;
	unsigned int seq;

	if (index->lock_type != MAIL_LOCK_EXCLUSIVE || !ctx->flag_updates)
		return TRUE;

	rec = index->lookup(index, 1); seq = 1;
	while (rec != NULL) {
		fname = maildir_get_location(index, rec);
		if (fname == NULL)
			return FALSE;

		hash_rec = hash_lookup(ctx->files, fname);
		if (hash_rec == NULL) {
			index_set_corrupted(index,
				"Unexpectedly lost file %s from hash", fname);
			return FALSE;
		}

		if (ACTION(hash_rec) == MAILDIR_FILE_ACTION_UPDATE_FLAGS) {
			if (!maildir_update_flags(ctx, rec, seq, fname))
				return FALSE;
		}

		rec = index->next(index, rec); seq++;
	}

	return TRUE;
}

static int maildir_index_sync_context_readonly(struct maildir_sync_context *ctx)
{
	struct mail_index *index = ctx->index;
	struct stat st;
	int cur_changed;

	i_assert(index->lock_type != MAIL_LOCK_UNLOCK);

	if (stat(ctx->cur_dir, &st) < 0) {
		index_file_set_syscall_error(index, ctx->cur_dir, "stat()");
		return FALSE;
	}

	cur_changed = st.st_mtime != index->last_cur_mtime ||
		index->maildir_cur_dirty != 0;

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

	if (!maildir_index_full_sync_init(ctx) ||
	    !maildir_index_full_sync_dirs(ctx) ||
	    !maildir_index_sync_readonly_flags(ctx))
		return FALSE;

	return TRUE;
}

static void maildir_index_sync_deinit(struct maildir_sync_context *ctx)
{
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

	if (index->new_filenames != NULL) {
		hash_destroy(index->new_filenames);
		index->new_filenames = NULL;
	}

	if (index->new_filename_pool != NULL)
		p_clear(index->new_filename_pool);

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

	if (!ret)
		*found = FALSE;
	else {
		hash_rec = hash_lookup(ctx->files, fname);
		*found = hash_rec != NULL &&
			hash_rec->action != MAILDIR_FILE_ACTION_EXPUNGE;
	}
	maildir_index_sync_deinit(ctx);
	return ret;
}

int maildir_index_sync(struct mail_index *index,
		       enum mail_lock_type data_lock_type __attr_unused__,
		       int *changes)
{
        struct maildir_sync_context *ctx;
	int ret;

	i_assert(index->lock_type != MAIL_LOCK_SHARED);

	if (changes != NULL)
		*changes = FALSE;

	ctx = maildir_sync_context_new(index);
	ret = maildir_index_sync_context(ctx, changes);
        maildir_index_sync_deinit(ctx);
	return ret;
}
