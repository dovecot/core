/* Copyright (C) 2002-2003 Timo Sirainen */

#include "lib.h"
#include "maildir-index.h"
#include "mail-cache.h"

int maildir_index_append_file(struct mail_cache_transaction_ctx **trans_ctx,
			      struct mail_index *index, const char *fname,
			      int new_dir)
{
	struct mail_index_record *rec;
        enum mail_index_record_flag index_flags;
	uoff_t virtual_size;
	const char *p;

	i_assert(index->lock_type == MAIL_LOCK_EXCLUSIVE);

	if (*trans_ctx == NULL) {
		if (mail_cache_transaction_begin(index->cache,
						 TRUE, trans_ctx) <= 0)
			return FALSE;
	}

	rec = index->append(index);
	if (rec == NULL)
		return FALSE;

	/* set message flags from file name */
	rec->msg_flags = maildir_filename_get_flags(fname, 0);
	mail_index_mark_flag_changes(index, rec, 0, rec->msg_flags);

	/* always set index flags */
	index_flags = new_dir ? MAIL_INDEX_FLAG_MAILDIR_NEW : 0;
	if (!mail_cache_add(*trans_ctx, rec, MAIL_CACHE_INDEX_FLAGS,
			    &index_flags, sizeof(index_flags)))
		return FALSE;

	/* set virtual size if found from file name */
	p = strstr(fname, ",W=");
	if (p != NULL) {
		p += 3;
		virtual_size = 0;
		while (*p >= '0' && *p <= '9') {
			virtual_size = virtual_size * 10 + (*p - '0');
			p++;
		}

		if (*p == ':' || *p == ',' || *p != '\0') {
			if (!mail_cache_add(*trans_ctx, rec,
					    MAIL_CACHE_VIRTUAL_FULL_SIZE,
					    &virtual_size,
					    sizeof(virtual_size)))
				return FALSE;
		}
	}

	/* always set location */
	if (!mail_cache_add(*trans_ctx, rec, MAIL_CACHE_LOCATION,
			    fname, strlen(fname)+1))
		return FALSE;

	return TRUE;
}
