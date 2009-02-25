/* Copyright (c) 2007-2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "maildir/maildir-storage.h"
#include "maildir/maildir-uidlist.h"
#include "maildir/maildir-filename.h"
#include "dbox-storage.h"
#include "dbox-file.h"
#include "dbox-file-maildir.h"

#include <stdlib.h>

const char *dbox_file_maildir_metadata_get(struct dbox_file *file,
					   enum dbox_metadata_key key)
{
	struct stat st;
	uoff_t size;
	const char *p, *value = NULL;

	switch (key) {
	case DBOX_METADATA_GUID:
		p = strchr(file->fname, MAILDIR_INFO_SEP);
		value = p == NULL ? file->fname :
			t_strdup_until(file->fname, p);
		break;
	case DBOX_METADATA_RECEIVED_TIME:
	case DBOX_METADATA_SAVE_TIME:
		if (file->fd != -1) {
			if (fstat(file->fd, &st) < 0) {
				dbox_file_set_syscall_error(file, "fstat()");
				return NULL;
			}
		} else {
			if (stat(file->current_path, &st) < 0) {
				if (errno == ENOENT)
					return NULL;
				dbox_file_set_syscall_error(file, "stat()");
				return NULL;
			}
		}
		value = t_strdup_printf("%lx", (unsigned long)
					(key == DBOX_METADATA_RECEIVED_TIME ?
					 st.st_mtime : st.st_ctime));
		break;
	case DBOX_METADATA_VIRTUAL_SIZE:
		if (!maildir_filename_get_size(file->fname,
					       MAILDIR_EXTRA_VIRTUAL_SIZE,
					       &size)) {
			value = maildir_uidlist_lookup_ext(
				file->single_mbox->maildir_uidlist,
				file->uid, MAILDIR_UIDLIST_REC_EXT_VSIZE);
			if (value == NULL)
				break;
			size = strtoull(value, NULL, 10);
		}
		value = t_strdup_printf("%llx", (unsigned long long)size);
		break;
	case DBOX_METADATA_POP3_UIDL:
		value = maildir_uidlist_lookup_ext(
				file->single_mbox->maildir_uidlist,
				file->uid, MAILDIR_UIDLIST_REC_EXT_POP3_UIDL);
		if (value != NULL && *value == '\0') {
			/* special case: use base filename */
			p = strchr(file->fname, MAILDIR_INFO_SEP);
			if (p == NULL)
				value = file->fname;
			else
				value = t_strdup_until(file->fname, p);
		}
		break;
	case DBOX_METADATA_OLDV1_EXPUNGED:
	case DBOX_METADATA_OLDV1_FLAGS:
	case DBOX_METADATA_OLDV1_KEYWORDS:
	case DBOX_METADATA_OLDV1_SPACE:
	case DBOX_METADATA_EXT_REF:
		break;
	}
	return value;
}

bool dbox_maildir_uid_get_fname(struct dbox_mailbox *mbox, uint32_t uid,
				const char **fname_r)
{
	enum maildir_uidlist_rec_flag flags;

	*fname_r = maildir_uidlist_lookup(mbox->maildir_uidlist, uid, &flags);
	return *fname_r != NULL;
}
