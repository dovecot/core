/* Copyright (c) 2007-2007 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "dbox-storage.h"
#include "../maildir/maildir-storage.h"
#include "../maildir/maildir-filename.h"
#include "dbox-file.h"
#include "dbox-file-maildir.h"

static const char *
dbox_file_maildir_get_flags(struct dbox_file *file, enum dbox_metadata_key key)
{
	ARRAY_TYPE(keyword_indexes) keyword_indexes;
	struct mail_keywords *keywords;
	enum mail_flags flags;
	string_t *str;
	const char *fname;

	if (file->mbox->maildir_sync_keywords == NULL)
		return NULL;

	fname = strrchr(file->path, '/');
	i_assert(fname != NULL);
	fname++;

	t_array_init(&keyword_indexes, 32);
	maildir_filename_get_flags(file->mbox->maildir_sync_keywords,
				   fname, &flags, &keyword_indexes);
	str = t_str_new(64);
	if (key == DBOX_METADATA_FLAGS)
		dbox_mail_metadata_flags_append(str, flags);
	else {
		keywords = mail_index_keywords_create_from_indexes(
			file->mbox->ibox.index, &keyword_indexes);
		dbox_mail_metadata_keywords_append(file->mbox, str, keywords);
		mail_index_keywords_free(&keywords);
	}
	return str_c(str);
}

const char *dbox_file_maildir_metadata_get(struct dbox_file *file,
					   enum dbox_metadata_key key)
{
	const char *fname;
	struct stat st;
	uoff_t size;

	switch (key) {
	case DBOX_METADATA_FLAGS:
	case DBOX_METADATA_KEYWORDS:
		return dbox_file_maildir_get_flags(file, key);
	case DBOX_METADATA_RECEIVED_TIME:
	case DBOX_METADATA_SAVE_TIME:
		if (file->fd != -1) {
			if (fstat(file->fd, &st) < 0) {
				dbox_file_set_syscall_error(file, "fstat");
				return NULL;
			}
		} else {
			if (stat(file->path, &st) < 0) {
				if (errno == ENOENT)
					return NULL;
				dbox_file_set_syscall_error(file, "stat");
				return NULL;
			}
		}
		if (key == DBOX_METADATA_RECEIVED_TIME)
			return dec2str(st.st_mtime);
		else
			return dec2str(st.st_ctime);
	case DBOX_METADATA_VIRTUAL_SIZE:
		fname = strrchr(file->path, '/');
		i_assert(fname != NULL);
		maildir_filename_get_size(fname + 1, MAILDIR_EXTRA_VIRTUAL_SIZE,
					  &size);
		return dec2str(size);
	case DBOX_METADATA_EXPUNGED:
	case DBOX_METADATA_EXT_REF:
	case DBOX_METADATA_SPACE:
		break;
	}
	return NULL;
}
