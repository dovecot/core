/* Copyright (c) 2007-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "istream.h"
#include "str.h"
#include "index-mail.h"
#include "dbox-mail.h"
#include "sdbox-storage.h"
#include "sdbox-file.h"

#include <sys/stat.h>

static void sdbox_mail_set_expunged(struct dbox_mail *mail)
{
	struct mail *_mail = &mail->imail.mail.mail;

	mail_index_refresh(_mail->box->index);
	if (mail_index_is_expunged(_mail->transaction->view, _mail->seq)) {
		mail_set_expunged(_mail);
		return;
	}

	mail_set_critical(_mail, "dbox: Unexpectedly lost uid");
	sdbox_set_mailbox_corrupted(_mail->box);
}

static int sdbox_mail_file_set(struct dbox_mail *mail)
{
	struct mail *_mail = &mail->imail.mail.mail;
	struct sdbox_mailbox *mbox = SDBOX_MAILBOX(_mail->box);
	bool deleted;
	int ret;

	if (mail->open_file != NULL) {
		/* already set */
		return 0;
	} else if (!_mail->saving) {
		mail->open_file = sdbox_file_init(mbox, _mail->uid);
		return 0;
	} else {
		/* mail is being saved in this transaction */
		mail->open_file =
			sdbox_save_file_get_file(_mail->transaction,
						 _mail->seq);
		mail->open_file->refcount++;

		/* it doesn't have input stream yet */
		ret = dbox_file_open(mail->open_file, &deleted);
		if (ret <= 0) {
			mail_set_critical(_mail,
				"dbox: Unexpectedly lost mail being saved");
			sdbox_set_mailbox_corrupted(_mail->box);
			return -1;
		}
		return 1;
	}
}

static int
sdbox_mail_get_special(struct mail *_mail, enum mail_fetch_field field,
		       const char **value_r)
{
	struct sdbox_mailbox *mbox = SDBOX_MAILBOX(_mail->box);
	struct dbox_mail *mail = DBOX_MAIL(_mail);
	struct stat st;

	switch (field) {
	case MAIL_FETCH_REFCOUNT:
		if (sdbox_mail_file_set(mail) < 0)
			return -1;

		_mail->transaction->stats.fstat_lookup_count++;
		if (dbox_file_stat(mail->open_file, &st) < 0) {
			if (errno == ENOENT)
				mail_set_expunged(_mail);
			return -1;
		}
		*value_r = p_strdup_printf(mail->imail.mail.data_pool, "%lu",
					   (unsigned long)st.st_nlink);
		return 0;
	case MAIL_FETCH_REFCOUNT_ID:
		if (sdbox_mail_file_set(mail) < 0)
			return -1;

		_mail->transaction->stats.fstat_lookup_count++;
		if (dbox_file_stat(mail->open_file, &st) < 0) {
			if (errno == ENOENT)
				mail_set_expunged(_mail);
			return -1;
		}
		*value_r = p_strdup_printf(mail->imail.mail.data_pool, "%llu",
					   (unsigned long long)st.st_ino);
		return 0;
	case MAIL_FETCH_UIDL_BACKEND:
		if (!dbox_header_have_flag(&mbox->box, mbox->hdr_ext_id,
				offsetof(struct sdbox_index_header, flags),
				DBOX_INDEX_HEADER_FLAG_HAVE_POP3_UIDLS)) {
			*value_r = "";
			return 0;
		}
		break;
	case MAIL_FETCH_POP3_ORDER:
		if (!dbox_header_have_flag(&mbox->box, mbox->hdr_ext_id,
				offsetof(struct sdbox_index_header, flags),
				DBOX_INDEX_HEADER_FLAG_HAVE_POP3_ORDERS)) {
			*value_r = "";
			return 0;
		}
		break;
	default:
		break;
	}
	return dbox_mail_get_special(_mail, field, value_r);
}

int sdbox_mail_open(struct dbox_mail *mail, uoff_t *offset_r,
		    struct dbox_file **file_r)
{
	struct mail *_mail = &mail->imail.mail.mail;
	bool deleted;
	int ret;

	if (_mail->lookup_abort != MAIL_LOOKUP_ABORT_NEVER) {
		mail_set_aborted(_mail);
		return -1;
	}
	_mail->mail_stream_opened = TRUE;

	ret = sdbox_mail_file_set(mail);
	if (ret < 0)
		return -1;
	if (ret == 0) {
		if (!dbox_file_is_open(mail->open_file))
			_mail->transaction->stats.open_lookup_count++;
		if (dbox_file_open(mail->open_file, &deleted) <= 0)
			return -1;
		if (deleted) {
			sdbox_mail_set_expunged(mail);
			return -1;
		}
	}

	*file_r = mail->open_file;
	*offset_r = 0;
	return 0;
}

struct mail_vfuncs sdbox_mail_vfuncs = {
	dbox_mail_close,
	index_mail_free,
	index_mail_set_seq,
	index_mail_set_uid,
	index_mail_set_uid_cache_updates,
	index_mail_prefetch,
	index_mail_precache,
	index_mail_add_temp_wanted_fields,

	index_mail_get_flags,
	index_mail_get_keywords,
	index_mail_get_keyword_indexes,
	index_mail_get_modseq,
	index_mail_get_pvt_modseq,
	index_mail_get_parts,
	index_mail_get_date,
	dbox_mail_get_received_date,
	dbox_mail_get_save_date,
	dbox_mail_get_virtual_size,
	dbox_mail_get_physical_size,
	index_mail_get_first_header,
	index_mail_get_headers,
	index_mail_get_header_stream,
	dbox_mail_get_stream,
	index_mail_get_binary_stream,
	sdbox_mail_get_special,
	index_mail_get_backend_mail,
	index_mail_update_flags,
	index_mail_update_keywords,
	index_mail_update_modseq,
	index_mail_update_pvt_modseq,
	NULL,
	index_mail_expunge,
	index_mail_set_cache_corrupted,
	index_mail_opened,
};
