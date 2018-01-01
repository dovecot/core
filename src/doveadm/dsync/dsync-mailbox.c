/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "istream.h"
#include "mail-storage-private.h"
#include "dsync-brain-private.h"
#include "dsync-mailbox.h"

void dsync_mailbox_attribute_dup(pool_t pool,
				 const struct dsync_mailbox_attribute *src,
				 struct dsync_mailbox_attribute *dest_r)
{
	dest_r->type = src->type;
	dest_r->key = p_strdup(pool, src->key);
	dest_r->value = p_strdup(pool, src->value);
	if (src->value_stream != NULL) {
		dest_r->value_stream = src->value_stream;
		i_stream_ref(dest_r->value_stream);
	}

	dest_r->deleted = src->deleted;
	dest_r->last_change = src->last_change;
	dest_r->modseq = src->modseq;
}

int dsync_mailbox_lock(struct dsync_brain *brain, struct mailbox *box,
		       struct file_lock **lock_r)
{
	const char *path, *error;
	int ret;

	/* Make sure the mailbox is open - locking requires it */
	if (mailbox_open(box) < 0) {
		i_error("Can't open mailbox %s: %s", mailbox_get_vname(box),
			mailbox_get_last_internal_error(box, &brain->mail_error));
		return -1;
	}

	ret = mailbox_get_path_to(box, MAILBOX_LIST_PATH_TYPE_INDEX, &path);
	if (ret < 0) {
		i_error("Can't get mailbox %s path: %s", mailbox_get_vname(box),
			mailbox_get_last_internal_error(box, &brain->mail_error));
		return -1;
	}
	if (ret == 0) {
		/* No index files - don't do any locking. In theory we still
		   could, but this lock is mainly meant to prevent replication
		   problems, and replication wouldn't work without indexes. */
		*lock_r = NULL;
		return 0;
	}

	if (mailbox_lock_file_create(box, DSYNC_MAILBOX_LOCK_FILENAME,
				     brain->mailbox_lock_timeout_secs,
				     lock_r, &error) <= 0) {
		i_error("Failed to lock mailbox %s for dsyncing: %s",
			box->vname, error);
		return -1;
	}
	return 0;
}
