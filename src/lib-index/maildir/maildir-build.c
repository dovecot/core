/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "istream.h"
#include "maildir-index.h"
#include "mail-index-util.h"

#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

static int maildir_record_update(struct mail_index *index,
				 struct mail_index_update *update, int fd)
{
	struct istream *input;
        enum mail_data_field cache_fields;

	if (index->mail_read_mmaped) {
		input = i_stream_create_mmap(fd, system_pool,
					     MAIL_MMAP_BLOCK_SIZE, 0, 0, FALSE);
	} else {
		input = i_stream_create_file(fd, system_pool,
					     MAIL_READ_BLOCK_SIZE, FALSE);
	}

	cache_fields = index->header->cache_fields & ~DATA_FIELD_LOCATION;
	mail_index_update_headers(update, input, cache_fields, NULL, NULL);

	i_stream_unref(input);
	return TRUE;
}

static int maildir_index_append_fd(struct mail_index *index,
				   int fd, const char *fname, int new_dir)
{
	struct mail_index_record *rec;
	struct mail_index_update *update;
	struct stat st;
	uoff_t virtual_size;
	const char *p;
	int failed;

	i_assert(fname != NULL);

	if (!index->set_lock(index, MAIL_LOCK_EXCLUSIVE))
		return FALSE;

	rec = index->append_begin(index);
	if (rec == NULL)
		return FALSE;

	/* set message flags from file name */
	rec->msg_flags = maildir_filename_get_flags(fname, 0);
	mail_index_mark_flag_changes(index, rec, 0, rec->msg_flags);

	update = index->update_begin(index, rec);

	/* set virtual size if found from file name */
	p = strstr(fname, ",W=");
	if (p != NULL) {
		p += 3;
		virtual_size = 0;
		while (*p >= '0' && *p <= '9') {
			virtual_size = virtual_size * 10 + (*p - '0');
			p++;
		}

		if (*p == ':' || *p == ',' || *p == '\0') {
			index->update_field_raw(update, DATA_HDR_VIRTUAL_SIZE,
						&virtual_size,
						sizeof(virtual_size));
		}
	}

	/* set internal date */
	if (fd != -1 && fstat(fd, &st) == 0) {
		index->update_field_raw(update, DATA_HDR_INTERNAL_DATE,
					&st.st_mtime, sizeof(st.st_mtime));
	}

	/* set the location */
	if (new_dir)
		rec->index_flags |= INDEX_MAIL_FLAG_MAILDIR_NEW;
	index->update_field(update, DATA_FIELD_LOCATION, fname,
			    MAILDIR_LOCATION_EXTRA_SPACE);

	/* parse the header and update record's fields */
	failed = fd == -1 ? FALSE : !maildir_record_update(index, update, fd);

	if (!index->update_end(update) || failed) {
		index->append_abort(index, rec);
		return FALSE;
	}

	return index->append_end(index, rec);
}

int maildir_index_append_file(struct mail_index *index, const char *dir,
			      const char *fname, int new_dir)
{
	const char *path;
	int fd, ret;

	i_assert(index->lock_type != MAIL_LOCK_SHARED);

	if ((index->header->cache_fields & ~DATA_FIELD_LOCATION) == 0) {
		/* nothing cached, don't bother opening the file */
		return maildir_index_append_fd(index, -1, fname, new_dir);
	}

	path = t_strconcat(dir, "/", fname, NULL);
	fd = open(path, O_RDONLY);
	if (fd == -1) {
		if (errno == ENOENT) {
			/* it's not found because it's deleted or renamed.
			   don't try to handle any error cases here, just
			   save the thing and let the syncing handle it
			   later */
			return maildir_index_append_fd(index, -1,
						       fname, new_dir);
		}

		return index_file_set_syscall_error(index, path, "open()");
	}

	ret = maildir_index_append_fd(index, fd, fname, new_dir);
	if (close(fd) < 0)
		return index_file_set_syscall_error(index, path, "close()");
	return ret;
}
