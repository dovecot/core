/* Copyright (c) 2007-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "istream.h"
#include "str.h"
#include "index-mail.h"
#include "dbox-mail.h"
#include "mdbox-storage.h"
#include "mdbox-sync.h"
#include "mdbox-map.h"
#include "mdbox-file.h"

#include <stdlib.h>
#include <sys/stat.h>

int mdbox_mail_lookup(struct mdbox_mailbox *mbox, struct mail_index_view *view,
		      uint32_t seq, uint32_t *map_uid_r)
{
	const struct mdbox_mail_index_record *dbox_rec;
	struct mdbox_index_header hdr;
	const void *data;
	uint32_t uid, cur_map_uid_validity;
	bool expunged;

	mail_index_lookup_ext(view, seq, mbox->ext_id, &data, &expunged);
	dbox_rec = data;
	if (dbox_rec == NULL || dbox_rec->map_uid == 0) {
		mail_index_lookup_uid(view, seq, &uid);
		mail_storage_set_critical(&mbox->storage->storage.storage,
			"mdbox %s: map uid lost for uid %u",
			mbox->box.path, uid);
		mdbox_storage_set_corrupted(mbox->storage);
		return -1;
	}

	if (mbox->map_uid_validity == 0) {
		if (mdbox_read_header(mbox, &hdr) < 0)
			return -1;
		mbox->map_uid_validity = hdr.map_uid_validity;
	}
	if (mdbox_map_open_or_create(mbox->storage->map) < 0)
		return -1;

	cur_map_uid_validity = mdbox_map_get_uid_validity(mbox->storage->map);
	if (cur_map_uid_validity != mbox->map_uid_validity) {
		mail_storage_set_critical(&mbox->storage->storage.storage,
			"mdbox %s: map uidvalidity mismatch (%u vs %u)",
			mbox->box.path, mbox->map_uid_validity,
			cur_map_uid_validity);
		mdbox_storage_set_corrupted(mbox->storage);
		return -1;
	}
	*map_uid_r = dbox_rec->map_uid;
	return 0;
}

static void dbox_mail_set_expunged(struct dbox_mail *mail, uint32_t map_uid)
{
	struct mail *_mail = &mail->imail.mail.mail;
	struct mdbox_mailbox *mbox = (struct mdbox_mailbox *)_mail->box;

	(void)mail_index_refresh(_mail->box->index);
	if (mail_index_is_expunged(_mail->transaction->view, _mail->seq)) {
		mail_set_expunged(_mail);
		return;
	}

	mdbox_map_set_corrupted(mbox->storage->map,
				"Unexpectedly lost %s uid=%u map_uid=%u",
				mailbox_get_vname(_mail->box),
				_mail->uid, map_uid);
}

static int dbox_mail_open_init(struct dbox_mail *mail, uint32_t map_uid)
{
	struct mdbox_mailbox *mbox =
		(struct mdbox_mailbox *)mail->imail.mail.mail.box;
	uint32_t file_id;
	int ret;

	if ((ret = mdbox_map_lookup(mbox->storage->map, map_uid,
				    &file_id, &mail->offset)) <= 0) {
		if (ret < 0)
			return -1;

		/* map_uid doesn't exist anymore. either it
		   got just expunged or the map index is
		   corrupted. */
		dbox_mail_set_expunged(mail, map_uid);
		return -1;
	} else {
		mail->open_file = mdbox_file_init(mbox->storage, file_id);
	}
	return 0;
}

int mdbox_mail_open(struct dbox_mail *mail, uoff_t *offset_r,
		    struct dbox_file **file_r)
{
	struct mail *_mail = &mail->imail.mail.mail;
	struct mdbox_mailbox *mbox = (struct mdbox_mailbox *)_mail->box;
	uint32_t prev_file_id = 0, map_uid = 0;
	bool deleted;

	if (_mail->lookup_abort != MAIL_LOOKUP_ABORT_NEVER) {
		mail_set_aborted(_mail);
		return -1;
	}

	do {
		if (mail->open_file != NULL) {
			/* already open */
		} else if (!_mail->saving) {
			if (mdbox_mail_lookup(mbox, _mail->transaction->view,
					      _mail->seq, &map_uid) < 0)
				return -1;
			if (dbox_mail_open_init(mail, map_uid) < 0)
				return -1;
		} else {
			/* mail is being saved in this transaction */
			mail->open_file =
				mdbox_save_file_get_file(_mail->transaction,
							 _mail->seq,
							 &mail->offset);
		}

		if (!dbox_file_is_open(mail->open_file))
			mail->imail.mail.stats_open_lookup_count++;
		if (dbox_file_open(mail->open_file, &deleted) <= 0)
			return -1;
		if (deleted) {
			/* either it's expunged now or moved to another file. */
			struct mdbox_file *mfile =
				(struct mdbox_file *)mail->open_file;

			if (mfile->file_id == prev_file_id) {
				dbox_mail_set_expunged(mail, map_uid);
				return -1;
			}
			prev_file_id = mfile->file_id;
			if (mdbox_map_refresh(mbox->storage->map) < 0)
				return -1;
			dbox_file_unref(&mail->open_file);
		}
	} while (mail->open_file == NULL);

	*file_r = mail->open_file;
	*offset_r = mail->offset;
	return 0;
}

static int mdbox_mail_get_save_date(struct mail *mail, time_t *date_r)
{
	struct mdbox_mailbox *mbox =
		(struct mdbox_mailbox *)mail->transaction->box;
	const struct mdbox_mail_index_record *dbox_rec;
	const void *data;
	bool expunged;

	mail_index_lookup_ext(mail->transaction->view, mail->seq,
			      mbox->ext_id, &data, &expunged);
	dbox_rec = data;
	if (dbox_rec == NULL || dbox_rec->map_uid == 0) {
		/* lost for some reason, use fallback */
		return dbox_mail_get_save_date(mail, date_r);
	}

	*date_r = dbox_rec->save_date;
	return 0;
}

static void
mdbox_mail_update_flags(struct mail *mail, enum modify_type modify_type,
			enum mail_flags flags)
{
	if ((flags & DBOX_INDEX_FLAG_ALT) != 0) {
		mdbox_purge_alt_flag_change(mail, modify_type != MODIFY_REMOVE);
		flags &= ~DBOX_INDEX_FLAG_ALT;
		if (flags == 0 && modify_type != MODIFY_REPLACE)
			return;
	}

	index_mail_update_flags(mail, modify_type, flags);
}

struct mail_vfuncs mdbox_mail_vfuncs = {
	dbox_mail_close,
	index_mail_free,
	index_mail_set_seq,
	index_mail_set_uid,
	index_mail_set_uid_cache_updates,

	index_mail_get_flags,
	index_mail_get_keywords,
	index_mail_get_keyword_indexes,
	index_mail_get_modseq,
	index_mail_get_parts,
	index_mail_get_date,
	dbox_mail_get_received_date,
	mdbox_mail_get_save_date,
	dbox_mail_get_virtual_size,
	dbox_mail_get_physical_size,
	index_mail_get_first_header,
	index_mail_get_headers,
	index_mail_get_header_stream,
	dbox_mail_get_stream,
	dbox_mail_get_special,
	index_mail_get_real_mail,
	mdbox_mail_update_flags,
	index_mail_update_keywords,
	index_mail_update_modseq,
	NULL,
	index_mail_expunge,
	index_mail_parse,
	index_mail_set_cache_corrupted,
	index_mail_opened
};
