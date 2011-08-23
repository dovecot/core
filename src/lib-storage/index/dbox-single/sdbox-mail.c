/* Copyright (c) 2007-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "istream.h"
#include "str.h"
#include "index-mail.h"
#include "dbox-mail.h"
#include "sdbox-storage.h"
#include "sdbox-file.h"

#include <stdlib.h>
#include <sys/stat.h>

static void sdbox_mail_set_expunged(struct dbox_mail *mail)
{
	struct mail *_mail = &mail->imail.mail.mail;

	(void)mail_index_refresh(_mail->box->index);
	if (mail_index_is_expunged(_mail->transaction->view, _mail->seq)) {
		mail_set_expunged(_mail);
		return;
	}

	mail_storage_set_critical(_mail->box->storage,
				  "dbox %s: Unexpectedly lost uid=%u",
				  _mail->box->path, _mail->uid);
	sdbox_set_mailbox_corrupted(_mail->box);
}

static int sdbox_mail_file_set(struct dbox_mail *mail)
{
	struct mail *_mail = &mail->imail.mail.mail;
	struct sdbox_mailbox *mbox = (struct sdbox_mailbox *)_mail->box;
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
			mail_storage_set_critical(_mail->box->storage,
				"dbox %s: Unexpectedly lost mail being saved",
				  _mail->box->path);
			sdbox_set_mailbox_corrupted(_mail->box);
			return -1;
		}
		return 1;
	}
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

	ret = sdbox_mail_file_set(mail);
	if (ret < 0)
		return -1;
	if (ret == 0) {
		if (!dbox_file_is_open(mail->open_file))
			mail->imail.mail.stats_open_lookup_count++;
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

	index_mail_get_flags,
	index_mail_get_keywords,
	index_mail_get_keyword_indexes,
	index_mail_get_modseq,
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
	dbox_mail_get_special,
	index_mail_get_real_mail,
	index_mail_update_flags,
	index_mail_update_keywords,
	index_mail_update_modseq,
	NULL,
	index_mail_expunge,
	index_mail_parse,
	index_mail_set_cache_corrupted,
	index_mail_opened
};
