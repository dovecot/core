/* Copyright (C) 2002-2003 Timo Sirainen */

#include "lib.h"
#include "buffer.h"
#include "hash.h"
#include "ioloop.h"
#include "maildir-index.h"
#include "maildir-uidlist.h"
#include "mail-index-data.h"
#include "mail-index-util.h"

#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <utime.h>
#include <sys/stat.h>

enum maildir_file_action {
	MAILDIR_FILE_ACTION_EXPUNGE,
	MAILDIR_FILE_ACTION_UPDATE_FLAGS,
	MAILDIR_FILE_ACTION_UPDATE_CONTENT,
	MAILDIR_FILE_ACTION_NEW,
	MAILDIR_FILE_ACTION_NONE
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

static int maildir_update_filename(struct mail_index *index,
				   struct mail_index_record *rec,
				   const char *new_fname)
{
	struct mail_index_update *update;

	update = index->update_begin(index, rec);
	index->update_field(update, DATA_FIELD_LOCATION, new_fname, 0);
	return index->update_end(update);
}

static int maildir_update_flags(struct mail_index *index,
				struct mail_index_record *rec,
				unsigned int seq, const char *new_fname)
{
	enum mail_flags flags;

	flags = maildir_filename_get_flags(new_fname, rec->msg_flags);
	if (flags != rec->msg_flags) {
		if (!index->update_flags(index, rec, seq, flags, TRUE))
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

static void uidlist_hash_get_filenames(void *key, void *value, void *context)
{
	buffer_t *buf = context;
	struct maildir_hash_rec *hash_rec = value;

	if (hash_rec->action == MAILDIR_FILE_ACTION_NEW)
		buffer_append(buf, (const void *) &key, sizeof(key));
}

static int maildir_sync_uidlist(struct mail_index *index, const char *dir,
				struct maildir_uidlist *uidlist,
				struct hash_table *files, pool_t pool,
				unsigned int new_count)
{
	struct mail_index_record *rec;
	struct maildir_hash_rec *hash_rec;
        struct maildir_uidlist_rec uid_rec;
	const char *fname, **new_files;
	void *orig_key, *orig_value;
	unsigned int seq, uid, last_uid, i;
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
			if (!maildir_uidlist_next(uidlist, &uid_rec))
				return FALSE;
		}

		fname = maildir_get_location(index, rec);
		if (fname == NULL) {
			hash_destroy(files);
			return FALSE;
		}

		hash_rec = hash_lookup(files, fname);
		if (hash_rec == NULL) {
			index_set_corrupted(index, "Unexpectedly lost file "
					    "%s from hash", fname);
			return FALSE;
		}

		if (uid_rec.uid == uid &&
		    maildir_cmp(fname, uid_rec.filename) != 0) {
			index_set_corrupted(index, "Filename mismatch for UID "
					    "%u: %s vs %s", uid, fname,
					    uid_rec.filename);
			return FALSE;
		}

		switch (hash_rec->action) {
		case MAILDIR_FILE_ACTION_EXPUNGE:
			if (!index->expunge(index, rec, seq, TRUE))
				return FALSE;
			seq--;
			break;
		case MAILDIR_FILE_ACTION_UPDATE_FLAGS:
			if (!maildir_update_flags(index, rec, seq, fname))
				return FALSE;
			break;
		case MAILDIR_FILE_ACTION_UPDATE_CONTENT:
			if (!index->expunge(index, rec, seq, TRUE))
				return FALSE;
			seq--;
			hash_rec->action = MAILDIR_FILE_ACTION_NEW;
			new_count++;
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

	/* if there's mails with UIDs in uidlist, write them */
	last_uid = 0;
	while (uid_rec.uid != 0) {
		if (!hash_lookup_full(files, uid_rec.filename,
				      &orig_key, &orig_value)) {
			/* expunged */
			if (uidlist != NULL)
				uidlist->rewrite = TRUE;
		} else {
			hash_rec = orig_value;
			i_assert(hash_rec->action == MAILDIR_FILE_ACTION_NEW);

			/* make sure we set the same UID for it. */
			i_assert(index->header->next_uid <= uid_rec.uid);
			index->header->next_uid = uid_rec.uid;

                        hash_rec->action = MAILDIR_FILE_ACTION_NONE;
			new_count--;

			if (!maildir_index_append_file(index, dir, orig_key))
				return FALSE;
		}

		if (maildir_uidlist_next(uidlist, &uid_rec) < 0)
			return FALSE;
	}

	if (new_count == 0 || !INDEX_IS_UIDLIST_LOCKED(index)) {
		/* all done (or can't do it since we don't have lock) */
		return TRUE;
	}

	if (uidlist != NULL)
		uidlist->rewrite = TRUE;

	/* then there's the completely new mails. sort them by the filename
	   so we should get them to same order as they were created. */
	buf = buffer_create_static_hard(pool, new_count * sizeof(const char *));
	hash_foreach(files, uidlist_hash_get_filenames, buf);
	i_assert(buffer_get_used_size(buf) / sizeof(const char *) <= new_count);

	new_files = buffer_get_modifyable_data(buf, NULL);
	qsort(new_files, new_count, sizeof(const char *),
	      (int (*)(const void *, const void *)) strcmp);

	/* and finally write */
	for (i = 0; i < new_count; i++) {
		if (!maildir_index_append_file(index, dir, new_files[i]))
			return FALSE;
	}

	return TRUE;
}

static int maildir_index_sync_dir(struct mail_index *index, const char *dir,
				  struct maildir_uidlist *uidlist)
{
	pool_t pool;
	struct hash_table *files;
	struct mail_index_record *rec;
	struct maildir_hash_rec *hash_rec;
	DIR *dirp;
	struct dirent *d;
	const char *fname;
	void *orig_key, *orig_value;
	unsigned int new_count;
	size_t size;
	int failed, check_content_changes;

	i_assert(dir != NULL);
	i_assert(index->lock_type == MAIL_LOCK_EXCLUSIVE);

	if (index->header->messages_count >= INT_MAX/32) {
		index_set_corrupted(index, "Header says %u messages",
				    index->header->messages_count);
		return FALSE;
	}

	/* read current messages in index into hash */
	size = nearest_power(index->header->messages_count *
			     sizeof(struct maildir_hash_rec) + 1024);
	pool = pool_alloconly_create("maildir sync", I_MAX(size, 16384));
	files = hash_create(default_pool, pool, index->header->messages_count*2,
			    maildir_hash, maildir_cmp);

	rec = index->lookup(index, 1);
	while (rec != NULL) {
		fname = maildir_get_location(index, rec);
		if (fname == NULL) {
			hash_destroy(files);
			return FALSE;
		}
		hash_rec = p_new(pool, struct maildir_hash_rec, 1);
		hash_rec->rec = rec;
		hash_rec->action = MAILDIR_FILE_ACTION_EXPUNGE;
		hash_insert(files, (void *) fname, hash_rec);

		rec = index->next(index, rec);
	}

	/* Do we want to check changes in file contents? This slows down
	   things as we need to do extra stat() for all files. */
	check_content_changes = getenv("MAILDIR_CHECK_CONTENT_CHANGES") != NULL;

	dirp = opendir(dir);
	if (dirp == NULL)
		return index_file_set_syscall_error(index, dir, "opendir()");

	new_count = 0; failed = FALSE;
	while ((d = readdir(dirp)) != NULL) {
		if (d->d_name[0] == '.')
			continue;

		if (!hash_lookup_full(files, d->d_name,
				      &orig_key, &orig_value)) {
			hash_rec = p_new(pool, struct maildir_hash_rec, 1);
		} else {
			hash_rec = orig_value;
			if (hash_rec->action != MAILDIR_FILE_ACTION_EXPUNGE) {
				/* FIXME: duplicate */
				continue;
			}
		}

		if (hash_rec->rec == NULL) {
			/* new message */
			new_count++;
			hash_rec->action = MAILDIR_FILE_ACTION_NEW;
			hash_insert(files, p_strdup(pool, d->d_name), hash_rec);
		} else if (check_content_changes &&
			   is_file_content_changed(index, rec,
						   dir, d->d_name)) {
			/* file content changed, treat it as new message */
			hash_rec->action = MAILDIR_FILE_ACTION_UPDATE_CONTENT;

			/* make sure filename is not invalidated by expunge
			   later. the file name may have changed also. */
			hash_insert(files, p_strdup(pool, d->d_name), hash_rec);
		} else if (strcmp(orig_key, d->d_name) != 0) {
			/* update filename now, flags later */
			hash_rec->action =  MAILDIR_FILE_ACTION_UPDATE_FLAGS;
			if (!maildir_update_filename(index, hash_rec->rec,
						     d->d_name)) {
				failed = TRUE;
				break;
			}
		} else {
			hash_rec->action =  MAILDIR_FILE_ACTION_NONE;
		}
	}

	if (closedir(dirp) < 0)
		index_file_set_syscall_error(index, dir, "closedir()");

	if (!failed) {
		failed = !maildir_sync_uidlist(index, dir, uidlist,
					       files, pool, new_count);
	}
	hash_destroy(files);
	pool_unref(pool);
	return !failed;
}

static int maildir_new_scan_first_file(struct mail_index *index,
				       const char *dir, DIR **dirp,
				       struct dirent **d)
{
	*dirp = opendir(dir);
	if (*dirp == NULL)
		return index_file_set_syscall_error(index, dir, "opendir()");

	/* find first file */
	while ((*d = readdir(*dirp)) != NULL) {
		if ((*d)->d_name[0] != '.')
			break;
	}

	if (*d == NULL) {
		if (closedir(*dirp) < 0)
			index_file_set_syscall_error(index, dir, "closedir()");
		*dirp = NULL;
	}

	return TRUE;
}

static int maildir_index_lock_and_sync(struct mail_index *index, int *changes,
				       DIR *new_dirp, struct dirent *new_dent,
				       struct maildir_uidlist **uidlist_r)
{
	struct stat st, std;
	struct utimbuf ut;
	struct maildir_uidlist *uidlist;
	const char *uidlist_path, *cur_dir, *new_dir;
	time_t index_mtime;
	int cur_changed;

	*uidlist_r = uidlist = NULL;

	if (index->fd == -1) {
		/* anon-mmaped */
		index_mtime = index->file_sync_stamp;
	} else {
		if (fstat(index->fd, &st) < 0)
			return index_set_syscall_error(index, "fstat()");
		index_mtime = st.st_mtime;
	}

        cur_dir = t_strconcat(index->mailbox_path, "/cur", NULL);
	if (stat(cur_dir, &std) < 0)
		return index_file_set_syscall_error(index, cur_dir, "stat()");

	uidlist_path = t_strconcat(index->mailbox_path,
				   "/" MAILDIR_UIDLIST_NAME, NULL);
	if (stat(uidlist_path, &st) < 0) {
		if (errno != ENOENT) {
			return index_file_set_syscall_error(index, uidlist_path,
							    "stat()");
		}

		memset(&st, 0, sizeof(st));
		cur_changed = TRUE;
	} else {
		/* FIXME: save device and inode into index header, so we don't
		   have to read it every time mailbox is opened */
		cur_changed = index_mtime != std.st_mtime ||
			st.st_ino != index->uidlist_ino ||
			!CMP_DEV_T(st.st_dev, index->uidlist_dev);
	}

	if (new_dirp != NULL || cur_changed) {
		if (maildir_uidlist_try_lock(index) < 0)
			return FALSE;

		/* we may or may not have succeeded. if we didn't,
		   just continue by syncing with existing uidlist file */

		if (!cur_changed && !INDEX_IS_UIDLIST_LOCKED(index)) {
			/* just new mails in new/ dir, we can't sync them
			   if we can't get the lock. */
			return TRUE;
		}

		if (!index->set_lock(index, MAIL_LOCK_EXCLUSIVE))
			return FALSE;

		*uidlist_r = uidlist = maildir_uidlist_open(index);
		if (uidlist != NULL &&
		    uidlist->uid_validity != index->header->uid_validity) {
			/* uidvalidity changed */
			if (!index->rebuilding) {
				index_set_corrupted(index,
					"UIDVALIDITY changed in uidlist");
				return FALSE;
			}

			index->header->uid_validity = uidlist->uid_validity;
		}

		if (uidlist != NULL &&
		    index->header->next_uid > uidlist->next_uid) {
			index_set_corrupted(index, "index.next_uid (%u) > "
					    "uidlist.next_uid (%u)",
					    index->header->next_uid,
					    uidlist->next_uid);
			return FALSE;
		}

		if (changes != NULL)
			*changes = TRUE;
	}

	/* move mail from new/ to cur/ */
	if (new_dirp != NULL && INDEX_IS_UIDLIST_LOCKED(index)) {
		new_dir = t_strconcat(index->mailbox_path, "/new", NULL);
		if (!maildir_index_build_dir(index, new_dir, cur_dir,
					     new_dirp, new_dent))
			return FALSE;

		if (uidlist != NULL)
			uidlist->rewrite = TRUE;

		/* set cur/ directory's timestamp into past to make sure we
		   notice if new mail is moved there */
		ut.actime = ut.modtime = ioloop_time-60;
		if (utime(cur_dir, &ut) < 0) {
			index_file_set_syscall_error(index, cur_dir, "utime()");
			return FALSE;
		}

		/* We have to always scan the cur/ directory to make
		   sure we don't miss any mails some other non-Dovecot
		   client may have moved there. FIXME: make it
		   optional, it's unnecessary with Dovecot-only setup */
		cur_changed = TRUE;

		/* set the cur/ directory's timestamp */
		std.st_mtime = ut.modtime;
	}

	if (cur_changed) {
		if (!maildir_index_sync_dir(index, cur_dir, uidlist))
			return FALSE;
	}

	if (uidlist != NULL && uidlist->next_uid > index->header->next_uid)
		index->header->next_uid = uidlist->next_uid;

	if ((new_dirp != NULL || cur_changed) &&
	    (uidlist == NULL || uidlist->rewrite)) {
		if (!INDEX_IS_UIDLIST_LOCKED(index)) {
			/* there's more new mails, but we need .lock file to
			   be able to sync them. */
			return TRUE;
		}

		if (fstat(index->maildir_lock_fd, &st) < 0) {
			return index_file_set_syscall_error(index, uidlist_path,
							    "fstat()");
		}

		if (!maildir_uidlist_rewrite(index))
			return FALSE;
	}

	/* uidlist file synced */
	index->uidlist_ino = st.st_ino;
	index->uidlist_dev = st.st_dev;

	/* update sync stamp */
	index->file_sync_stamp = std.st_mtime;

	if (index->lock_type == MAIL_LOCK_UNLOCK && !index->anon_mmap) {
		/* no changes to index, we need to update it's timestamp
		   ourself to get it changed */
		ut.actime = ioloop_time;
		ut.modtime = index->file_sync_stamp;
		if (utime(index->filepath, &ut) < 0)
			return index_set_syscall_error(index, "utime()");
	}

	return TRUE;
}

int maildir_index_sync(struct mail_index *index,
		       enum mail_lock_type data_lock_type __attr_unused__,
		       int *changes)
{
        struct maildir_uidlist *uidlist;
	DIR *new_dirp;
	struct dirent *new_dent;
	const char *new_dir;
	int ret;

	i_assert(index->lock_type != MAIL_LOCK_SHARED);

	if (changes != NULL)
		*changes = FALSE;

	new_dir = t_strconcat(index->mailbox_path, "/new", NULL);
	if (!maildir_new_scan_first_file(index, new_dir, &new_dirp, &new_dent))
		return FALSE;

	ret = maildir_index_lock_and_sync(index, changes, new_dirp, new_dent,
					  &uidlist);

	if (uidlist != NULL)
		maildir_uidlist_close(uidlist);

	if (new_dirp != NULL) {
		if (closedir(new_dirp) < 0) {
			index_file_set_syscall_error(index, new_dir,
						     "closedir()");
		}
	}

	maildir_uidlist_unlock(index);
	return ret;
}
