/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "mbox-index.h"
#include "mail-index-util.h"

static MailIndex mbox_index;

MailFlags mbox_header_get_flags(const char *name, unsigned int name_len,
				const char *value, unsigned int value_len)
{
	MailFlags flags;
	unsigned int i;

	flags = 0;
	if ((name_len == 6 && strncasecmp(name, "Status", 6) == 0) ||
	    (name_len == 8 && strncasecmp(name, "X-Status", 8) == 0)) {
		    for (i = 0; i < value_len; i++) {
			    switch (value[i]) {
			    case 'A':
				    flags |= MAIL_ANSWERED;
				    break;
			    case 'F':
				    flags |= MAIL_FLAGGED;
				    break;
			    case 'R':
				    flags |= MAIL_SEEN;
				    break;
			    case 'D':
				    flags |= MAIL_DELETED;
				    break;
			    }
		    }
	}

	return flags;
}

MailIndex *mbox_index_alloc(const char *dir, const char *mbox_path)
{
	MailIndex *index;
	int len;

	i_assert(dir != NULL);

	index = i_new(MailIndex, 1);
	memcpy(index, &mbox_index, sizeof(MailIndex));

	index->fd = -1;
	index->dir = i_strdup(dir);

	len = strlen(index->dir);
	if (index->dir[len-1] == '/')
		index->dir[len-1] = '\0';

	index->mbox_path = i_strdup(mbox_path);
	return (MailIndex *) index;
}

static void mbox_index_free(MailIndex *index)
{
	mail_index_close(index);
	i_free(index->dir);
	i_free(index);
}

static MailIndex mbox_index = {
	mail_index_open,
	mail_index_open_or_create,
	mbox_index_free,
	mail_index_set_lock,
	mail_index_try_lock,
	mbox_index_rebuild,
	mbox_index_fsck,
	mbox_index_sync,
	mail_index_get_header,
	mail_index_lookup,
	mail_index_next,
        mail_index_lookup_uid_range,
	mail_index_lookup_field,
	mail_index_get_sequence,
	mbox_open_mail,
	mail_index_expunge,
	mail_index_update_flags,
	mail_index_append,
	mail_index_update_begin,
	mail_index_update_end,
	mail_index_update_field,
	mail_index_get_last_error,
	mail_index_is_inconsistency_error,

	MAIL_INDEX_PRIVATE_FILL
};
