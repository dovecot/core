/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "ioloop.h"
#include "hash.h"
#include "maildir-index.h"
#include "mail-index-data.h"
#include "mail-index-util.h"

#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <utime.h>
#include <sys/stat.h>

static int maildir_index_sync_file(MailIndex *index, MailIndexRecord *rec,
				   unsigned int seq, const char *fname,
				   const char *path,
				   int fname_changed, int file_changed)
{
	MailIndexUpdate *update;
	MailFlags flags;
	int fd, failed;

	i_assert(fname != NULL);
	i_assert(path != NULL);

	if (!index->set_lock(index, MAIL_LOCK_EXCLUSIVE))
		return FALSE;

	failed = FALSE;
	update = index->update_begin(index, rec);

	if (fname_changed)
		index->update_field(update, DATA_FIELD_LOCATION, fname, 0);
	if (file_changed) {
		/* file itself changed - reload the header */
		fd = open(path, O_RDONLY);
		if (fd == -1) {
			index_file_set_syscall_error(index, path, "open()");
			failed = TRUE;
		} else {
			if (!maildir_record_update(index, update, fd))
				failed = TRUE;
			if (close(fd) < 0) {
				index_file_set_syscall_error(index, path,
							     "close()");
			}
		}
	}

	if (!index->update_end(update))
		failed = TRUE;

	/* update flags after filename has been updated, so it can be
	   compared correctly */
	flags = maildir_filename_get_flags(fname, rec->msg_flags);
	if (!failed && flags != rec->msg_flags) {
		if (!index->update_flags(index, rec, seq, flags, TRUE))
			failed = TRUE;
	}

	return !failed;
}

static int maildir_index_sync_files(MailIndex *index, const char *dir,
				    HashTable *files, int check_content_changes)
{
	MailIndexRecord *rec;
	MailIndexDataRecordHeader *data_hdr;
	struct stat st;
	const char *fname, *value;
	char str[1024], *p;
	unsigned int seq;
	int fname_changed, file_changed;

	i_assert(dir != NULL);

	rec = index->lookup(index, 1);
	for (seq = 1; rec != NULL; rec = index->next(index, rec)) {
		fname = index->lookup_field(index, rec, DATA_FIELD_LOCATION);
		if (fname == NULL) {
			index_data_set_corrupted(index->data,
				"Missing location field for record %u",
				rec->uid);
			return FALSE;
		}

		/* get the filename without the ":flags" part */
		strncpy(str, fname, sizeof(str)-1); str[sizeof(str)-1] = '\0';
		p = strchr(str, ':');
		if (p != NULL) *p = '\0';

		value = hash_lookup(files, str);
		hash_remove(files, str);

		if (value == NULL) {
			/* mail is expunged */
			if (!index->set_lock(index, MAIL_LOCK_EXCLUSIVE))
				return FALSE;

			if (!index->expunge(index, rec, seq, TRUE))
				return FALSE;
			continue;
		}

		/* file still exists */
		i_snprintf(str, sizeof(str), "%s/%s", dir, value);

		if (!check_content_changes)
			file_changed = FALSE;
		else {
			if (stat(str, &st) < 0) {
				index_file_set_syscall_error(index, str,
							     "stat()");
				return FALSE;
			}

			data_hdr = mail_index_data_lookup_header(index->data,
								 rec);
			file_changed = data_hdr != NULL &&
				(uoff_t)st.st_size !=
				data_hdr->body_size + data_hdr->header_size;
		}

		/* changed - update */
		fname_changed = strcmp(value, fname) != 0;
		if (fname_changed || file_changed) {
			if (!maildir_index_sync_file(index, rec, seq, value,
						     str, fname_changed,
						     file_changed))
				return FALSE;
		}

		seq++;
	}

	if (seq-1 != index->header->messages_count) {
		index_set_corrupted(index, "Wrong messages_count in header "
				    "(%u != %u)", seq-1,
				    index->header->messages_count);
	}

	return TRUE;
}

typedef struct {
	MailIndex *index;
	const char *dir;
	int failed;
} HashAppendContext;

static void maildir_index_hash_append_file(void *key __attr_unused__,
					   void *value, void *context)
{
	HashAppendContext *ctx = context;

	if (!maildir_index_append_file(ctx->index, ctx->dir, value)) {
		ctx->failed = TRUE;
                hash_foreach_stop();
	}
}

static int maildir_index_append_files(MailIndex *index, const char *dir,
				      HashTable *files)
{
	HashAppendContext ctx;

	ctx.failed = FALSE;
	ctx.index = index;
	ctx.dir = dir;
	hash_foreach(files, maildir_index_hash_append_file, &ctx);

	return !ctx.failed;
}

static int maildir_index_sync_dir(MailIndex *index, const char *dir)
{
	Pool pool;
	HashTable *files;
	DIR *dirp;
	struct dirent *d;
	const char *key, *value, *p;
	unsigned int count;
	int failed, check_content_changes;

	i_assert(dir != NULL);

	/* get exclusive lock always, this way the index file's timestamp
	   is updated even if there's no changes, which is useful to make
	   sure the cur/ directory isn't scanned all the time when it's
	   timestamp has changed but hasn't had any other changes. */
	if (!index->set_lock(index, MAIL_LOCK_EXCLUSIVE))
		return FALSE;

	if (index->header->messages_count >= INT_MAX/32) {
		index_set_corrupted(index, "Header says %u messages",
				    index->header->messages_count);
		return FALSE;
	}

	/* we need to find out the new and the deleted files. do this by
	   first building a hash of what files really exist, then go through
	   the index and after updated/removed the index, remove the file
	   from hash, so finally the hash should contain only the new
	   files which will be added then. */
	dirp = opendir(dir);
	if (dirp == NULL)
		return index_file_set_syscall_error(index, dir, "opendir()");

	count = index->header->messages_count + 16;
	pool = pool_create("Maildir sync", nearest_power(count*30), FALSE);
	files = hash_create(pool, index->header->messages_count*2, str_hash,
			    (HashCompareFunc) strcmp);

	while ((d = readdir(dirp)) != NULL) {
		if (d->d_name[0] == '.')
			continue;

		/* hash key is the file name without the ":flags" part */
		p = strrchr(d->d_name, ':');
		if (p == d->d_name)
			continue;

		value = p_strdup(pool, d->d_name);
		key = p == NULL ? value : p_strdup_until(pool, d->d_name, p);
		hash_insert(files, key, value);
	}

	if (closedir(dirp) < 0)
		index_file_set_syscall_error(index, dir, "closedir()");

	/* Do we want to check changes in file contents? This slows down
	   things as we need to do extra stat() for all files. */
	check_content_changes = getenv("MAILDIR_CHECK_CONTENT_CHANGES") != NULL;

	/* now walk through the index syncing and expunging existing mails */
	failed = !maildir_index_sync_files(index, dir, files,
					   check_content_changes);

	if (!failed) {
		/* then add the new mails */
		failed = !maildir_index_append_files(index, dir, files);
	}

	hash_destroy(files);
	pool_unref(pool);
	return !failed;
}

int maildir_index_sync(MailIndex *index, MailLockType lock_type, int *changes)
{
	struct stat sti, std;
	struct utimbuf ut;
	const char *cur_dir, *new_dir;
	time_t index_mtime;

	i_assert(index->lock_type != MAIL_LOCK_SHARED);

	if (changes != NULL)
		*changes = FALSE;

	if (index->fd == -1) {
		/* anon-mmaped */
		index_mtime = index->file_sync_stamp;
	} else {
		if (fstat(index->fd, &sti) < 0)
			return index_set_syscall_error(index, "fstat()");
		index_mtime = sti.st_mtime;
	}

	/* cur/ and new/ directories can have new mail - sync the cur/ first
	   so it'll be a bit bit faster since we haven't yet added the new
	   mail. */
        cur_dir = t_strconcat(index->dir, "/cur", NULL);
	if (stat(cur_dir, &std) < 0)
		return index_file_set_syscall_error(index, cur_dir, "stat()");

	if (std.st_mtime != index_mtime) {
		if (changes != NULL) *changes = TRUE;
		if (!maildir_index_sync_dir(index, cur_dir))
			return FALSE;
	}

	/* move mail from new/ to cur/ */
	new_dir = t_strconcat(index->dir, "/new", NULL);
	if (stat(new_dir, &std) < 0)
		return index_file_set_syscall_error(index, new_dir, "stat()");

	if (std.st_mtime != index_mtime) {
		if (changes != NULL) *changes = TRUE;

		if (!maildir_index_build_dir(index, new_dir, cur_dir))
			return FALSE;

		/* set cur/ and new/ directory's timestamp into past to
		   make sure if someone adds new mail it the new/ dir's
		   timestamp isn't set to same as cur/ directory's. */
		ut.actime = ut.modtime = ioloop_time-60;
		if (utime(cur_dir, &ut) < 0) {
			return index_file_set_syscall_error(index, cur_dir,
							    "utime()");
		}
		if (utime(new_dir, &ut) < 0) {
			return index_file_set_syscall_error(index, new_dir,
							    "utime()");
		}

		/* it's possible that new mail came in just after we
		   scanned the directory. scan the directory again, this will
		   update the directory's timestamps so at next sync we'll
		   always check the new/ dir once more, but at least we can be
		   sure that no mail got lost. */
		if (!maildir_index_build_dir(index, new_dir, cur_dir))
			return FALSE;
	}

	/* update sync stamp */
	if (stat(cur_dir, &std) < 0)
		return index_file_set_syscall_error(index, cur_dir, "stat()");
	index->file_sync_stamp = std.st_mtime;

	if (index->fd != -1 && index->lock_type == MAIL_LOCK_UNLOCK) {
		/* no changes, we need to update index's timestamp
		   ourself to get it changed */
		ut.actime = ioloop_time;
		ut.modtime = index->file_sync_stamp;
		if (utime(index->filepath, &ut) < 0)
			return index_set_syscall_error(index, "utime()");
	}

	return index->set_lock(index, lock_type);
}
