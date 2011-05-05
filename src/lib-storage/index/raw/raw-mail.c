/* Copyright (c) 2007-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "istream.h"
#include "index-mail.h"
#include "raw-storage.h"

#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

static int raw_mail_stat(struct mail *mail)
{
	struct raw_mailbox *mbox = (struct raw_mailbox *)mail->box;
	struct mail_private *p = (struct mail_private *)mail;
	const struct stat *st;

	if (mail->lookup_abort == MAIL_LOOKUP_ABORT_NOT_IN_CACHE)
		return mail_set_aborted(mail);

	p->stats_fstat_lookup_count++;
	st = i_stream_stat(mail->box->input, TRUE);
	if (st == NULL) {
		mail_storage_set_critical(mail->box->storage,
			"stat(%s) failed: %m", mail->box->path);
		return -1;
	}

	if (mbox->mtime != (time_t)-1)
		mbox->mtime = st->st_mtime;
	if (mbox->ctime != (time_t)-1)
		mbox->ctime = st->st_ctime;
	mbox->size = st->st_size;
	return 0;
}

static int raw_mail_get_received_date(struct mail *_mail, time_t *date_r)
{
	struct index_mail *mail = (struct index_mail *)_mail;
	struct raw_mailbox *mbox = (struct raw_mailbox *)_mail->box;

	if (mbox->mtime == (time_t)-1) {
		if (raw_mail_stat(_mail) < 0)
			return -1;
	}

	*date_r = mail->data.received_date = mbox->mtime;
	return 0;
}

static int raw_mail_get_save_date(struct mail *_mail, time_t *date_r)
{
	struct index_mail *mail = (struct index_mail *)_mail;
	struct raw_mailbox *mbox = (struct raw_mailbox *)_mail->box;

	if (mbox->ctime == (time_t)-1) {
		if (raw_mail_stat(_mail) < 0)
			return -1;
	}

	*date_r = mail->data.save_date = mbox->ctime;
	return 0;
}

static int raw_mail_get_physical_size(struct mail *_mail, uoff_t *size_r)
{
	struct index_mail *mail = (struct index_mail *)_mail;
	struct raw_mailbox *mbox = (struct raw_mailbox *)_mail->box;

	if (mbox->size == (uoff_t)-1) {
		if (raw_mail_stat(_mail) < 0)
			return -1;
	}

	*size_r = mail->data.physical_size = mbox->size;
	return 0;
}

static int
raw_mail_get_stream(struct mail *_mail, struct message_size *hdr_size,
		    struct message_size *body_size, struct istream **stream_r)
{
	struct index_mail *mail = (struct index_mail *)_mail;

	if (mail->data.stream == NULL) {
		/* we can't just reference mbox->input, because
		   index_mail_close() expects to be able to free the stream */
		mail->data.stream =
			i_stream_create_limit(_mail->box->input, (uoff_t)-1);
	}

	return index_mail_init_stream(mail, hdr_size, body_size, stream_r);
}

static int
raw_mail_get_special(struct mail *_mail, enum mail_fetch_field field,
		     const char **value_r)
{
	struct raw_mailbox *mbox = (struct raw_mailbox *)_mail->box;

	switch (field) {
	case MAIL_FETCH_FROM_ENVELOPE:
		*value_r = mbox->envelope_sender;
		return 0;
	case MAIL_FETCH_UIDL_FILE_NAME:
		*value_r = mbox->have_filename ? _mail->box->path : "";
		return 0;
	default:
		return index_mail_get_special(_mail, field, value_r);
	}
}

struct mail_vfuncs raw_mail_vfuncs = {
	index_mail_close,
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
	raw_mail_get_received_date,
	raw_mail_get_save_date,
	index_mail_get_virtual_size,
	raw_mail_get_physical_size,
	index_mail_get_first_header,
	index_mail_get_headers,
	index_mail_get_header_stream,
	raw_mail_get_stream,
	raw_mail_get_special,
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
