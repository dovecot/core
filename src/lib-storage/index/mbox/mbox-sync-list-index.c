/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "mbox-storage.h"
#include "mbox-sync-private.h"

static unsigned int
mbox_list_get_ext_id(struct mbox_mailbox *mbox,
		     struct mail_index_view *view)
{
	if (mbox->mbox_list_index_ext_id == (uint32_t)-1) {
		mbox->mbox_list_index_ext_id =
			mail_index_ext_register(mail_index_view_get_index(view),
				"mbox", 0,
				sizeof(struct mbox_list_index_record),
				sizeof(uint32_t));
	}
	return mbox->mbox_list_index_ext_id;
}

int mbox_list_index_has_changed(struct mailbox *box,
				struct mail_index_view *list_view,
				uint32_t seq, bool quick, const char **reason_r)
{
	struct mbox_mailbox *mbox = MBOX_MAILBOX(box);
	const struct mbox_list_index_record *rec;
	const void *data;
	const char *path;
	struct stat st;
	uint32_t ext_id;
	bool expunged;
	int ret;

	ret = index_storage_list_index_has_changed(box, list_view, seq,
						   quick, reason_r);
	if (ret != 0 || box->storage->set->mailbox_list_index_very_dirty_syncs)
		return ret;

	ext_id = mbox_list_get_ext_id(mbox, list_view);
	mail_index_lookup_ext(list_view, seq, ext_id, &data, &expunged);
	rec = data;

	if (rec == NULL) {
		*reason_r = "mbox record is missing";
		return 1;
	} else if (expunged) {
		*reason_r = "mbox record is expunged";
		return 1;
	} else if (rec->mtime == 0) {
		/* not synced */
		*reason_r = "mbox record mtime=0";
		return 1;
	}

	ret = mailbox_get_path_to(box, MAILBOX_LIST_PATH_TYPE_MAILBOX, &path);
	if (ret < 0)
		return ret;
	i_assert(ret > 0);

	if (stat(path, &st) < 0) {
		mailbox_set_critical(box, "stat(%s) failed: %m", path);
		return -1;
	}
	if ((time_t)rec->mtime != st.st_mtime) {
		*reason_r = t_strdup_printf(
			"mbox record mtime changed %u != %"PRIdTIME_T,
			rec->mtime, st.st_mtime);
		return 1;
	}
	uint32_t new_size = (uint32_t)(st.st_size & 0xffffffffU);
	if (rec->size != new_size) {
		*reason_r = t_strdup_printf("mbox record size changed %u != %u",
					    rec->size, new_size);
		return 1;
	}
	return 0;
}

void mbox_list_index_update_sync(struct mailbox *box,
				 struct mail_index_transaction *trans,
				 uint32_t seq)
{
	struct mbox_mailbox *mbox = MBOX_MAILBOX(box);
	struct mail_index_view *list_view;
	const struct mbox_index_header *mhdr = &mbox->mbox_hdr;
	const struct mbox_list_index_record *old_rec;
	struct mbox_list_index_record new_rec;
	const void *data;
	uint32_t ext_id;
	bool expunged;

	index_storage_list_index_update_sync(box, trans, seq);

	/* get the current record */
	list_view = mail_index_transaction_get_view(trans);
	ext_id = mbox_list_get_ext_id(mbox, list_view);
	mail_index_lookup_ext(list_view, seq, ext_id, &data, &expunged);
	if (expunged)
		return;
	old_rec = data;

	i_zero(&new_rec);
	new_rec.mtime = mhdr->sync_mtime;
	new_rec.size = mhdr->sync_size & 0xffffffffU;

	if (old_rec == NULL ||
	    memcmp(old_rec, &new_rec, sizeof(*old_rec)) != 0)
		mail_index_update_ext(trans, seq, ext_id, &new_rec, NULL);
}
