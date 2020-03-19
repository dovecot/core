/* Copyright (c) 2007-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "istream.h"
#include "index-mail.h"
#include "raw-storage.h"

#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

static int raw_mail_stat(struct mail *mail)
{
	struct raw_mailbox *mbox = RAW_MAILBOX(mail->box);
	const struct stat *st;

	if (mail->lookup_abort >= MAIL_LOOKUP_ABORT_NOT_IN_CACHE) {
		mail_set_aborted(mail);
		return -1;
	}
	mail->mail_metadata_accessed = TRUE;

	mail->transaction->stats.fstat_lookup_count++;
	if (i_stream_stat(mail->box->input, TRUE, &st) < 0) {
		mail_set_critical(mail, "stat(%s) failed: %m",
				  i_stream_get_name(mail->box->input));
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
	struct index_mail *mail = INDEX_MAIL(_mail);
	struct raw_mailbox *mbox = RAW_MAILBOX(_mail->box);

	if (mbox->mtime == (time_t)-1) {
		if (raw_mail_stat(_mail) < 0)
			return -1;
	}

	*date_r = mail->data.received_date = mbox->mtime;
	return 0;
}

static int raw_mail_get_save_date(struct mail *_mail, time_t *date_r)
{
	struct index_mail *mail = INDEX_MAIL(_mail);
	struct raw_mailbox *mbox = RAW_MAILBOX(_mail->box);

	if (mbox->ctime == (time_t)-1) {
		if (raw_mail_stat(_mail) < 0)
			return -1;
	}

	*date_r = mail->data.save_date = mbox->ctime;
	return 1;
}

static int raw_mail_get_physical_size(struct mail *_mail, uoff_t *size_r)
{
	struct index_mail *mail = INDEX_MAIL(_mail);
	struct raw_mailbox *mbox = RAW_MAILBOX(_mail->box);

	if (mbox->size == (uoff_t)-1) {
		if (raw_mail_stat(_mail) < 0)
			return -1;
	}

	*size_r = mail->data.physical_size = mbox->size;
	return 0;
}

static int
raw_mail_get_stream(struct mail *_mail, bool get_body ATTR_UNUSED,
		    struct message_size *hdr_size,
		    struct message_size *body_size, struct istream **stream_r)
{
	struct index_mail *mail = INDEX_MAIL(_mail);

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
	struct raw_mailbox *mbox = RAW_MAILBOX(_mail->box);

	switch (field) {
	case MAIL_FETCH_FROM_ENVELOPE:
		*value_r = mbox->envelope_sender != NULL ?
			mbox->envelope_sender : "";
		return 0;
	case MAIL_FETCH_STORAGE_ID:
		*value_r = mbox->have_filename ?
			mailbox_get_path(_mail->box) : "";
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
	raw_mail_get_received_date,
	raw_mail_get_save_date,
	index_mail_get_virtual_size,
	raw_mail_get_physical_size,
	index_mail_get_first_header,
	index_mail_get_headers,
	index_mail_get_header_stream,
	raw_mail_get_stream,
	index_mail_get_binary_stream,
	raw_mail_get_special,
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
