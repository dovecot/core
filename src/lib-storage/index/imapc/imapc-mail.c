/* Copyright (c) 2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "istream.h"
#include "imapc-mail.h"
#include "imapc-client.h"
#include "imapc-storage.h"

struct mail *
imapc_mail_alloc(struct mailbox_transaction_context *t,
		 enum mail_fetch_field wanted_fields,
		 struct mailbox_header_lookup_ctx *wanted_headers)
{
	struct imapc_mail *mail;
	pool_t pool;

	pool = pool_alloconly_create("mail", 2048);
	mail = p_new(pool, struct imapc_mail, 1);
	mail->imail.mail.pool = pool;

	index_mail_init(&mail->imail, t, wanted_fields, wanted_headers);
	return &mail->imail.mail.mail;
}

static void imapc_mail_free(struct mail *_mail)
{
	struct imapc_mail *mail = (struct imapc_mail *)_mail;

	if (mail->body != NULL)
		buffer_free(&mail->body);
	index_mail_free(_mail);
}

static int imapc_mail_get_received_date(struct mail *_mail, time_t *date_r)
{
	struct index_mail *mail = (struct index_mail *)_mail;
	struct index_mail_data *data = &mail->data;

	if (data->received_date == (time_t)-1) {
		if (imapc_mail_fetch(_mail, MAIL_FETCH_RECEIVED_DATE) < 0)
			return -1;
		if (data->received_date == (time_t)-1) {
			mail_storage_set_critical(_mail->box->storage,
				"imapc: Remote server didn't send INTERNALDATE");
			return -1;
		}
	}
	*date_r = data->received_date;
	return 0;
}

static int imapc_mail_get_save_date(struct mail *_mail, time_t *date_r)
{
	struct index_mail *mail = (struct index_mail *)_mail;
	struct index_mail_data *data = &mail->data;

	if (data->save_date == (time_t)-1) {
		/* FIXME */
		return -1;
	}
	*date_r = data->save_date;
	return 0;
}

static int imapc_mail_get_sizes(struct index_mail *mail)
{
	struct message_size hdr_size, body_size;
	struct istream *input;
	uoff_t old_offset;

	/* fallback to reading the file */
	old_offset = mail->data.stream == NULL ? 0 :
		mail->data.stream->v_offset;
	if (mail_get_stream(&mail->mail.mail,
			    &hdr_size, &body_size, &input) < 0)
		return -1;
	i_stream_seek(mail->data.stream, old_offset);
	return 0;
}

static int imapc_mail_get_virtual_size(struct mail *_mail, uoff_t *size_r)
{
	struct index_mail *mail = (struct index_mail *)_mail;
	struct index_mail_data *data = &mail->data;

	if (data->virtual_size == (uoff_t)-1) {
		if (imapc_mail_get_sizes(mail) < 0)
			return -1;
	}
	*size_r = data->virtual_size;
	return 0;
}

static int imapc_mail_get_physical_size(struct mail *_mail, uoff_t *size_r)
{
	struct index_mail *mail = (struct index_mail *)_mail;
	struct index_mail_data *data = &mail->data;

	if (data->physical_size == (uoff_t)-1) {
		if (imapc_mail_get_sizes(mail) < 0)
			return -1;
	}
	*size_r = data->physical_size;
	return 0;
}

static int
imapc_mail_get_stream(struct mail *_mail, struct message_size *hdr_size,
		      struct message_size *body_size, struct istream **stream_r)
{
	struct index_mail *mail = (struct index_mail *)_mail;
	struct index_mail_data *data = &mail->data;
	enum mail_fetch_field fetch_field;

	if (data->stream == NULL) {
		if (!mail->data.initialized) {
			/* coming here from mail_set_seq() */
			return -1;
		}
		fetch_field = body_size != NULL ||
			(mail->wanted_fields & MAIL_FETCH_STREAM_BODY) != 0 ?
			MAIL_FETCH_STREAM_BODY : MAIL_FETCH_STREAM_HEADER;
		if (imapc_mail_fetch(_mail, fetch_field) < 0)
			return -1;

		if (data->stream == NULL) {
			mail_storage_set_critical(_mail->box->storage,
				"imapc: Remote server didn't send BODY[]");
			return -1;
		}
	}

	return index_mail_init_stream(mail, hdr_size, body_size, stream_r);
}

struct mail_vfuncs imapc_mail_vfuncs = {
	index_mail_close,
	imapc_mail_free,
	index_mail_set_seq,
	index_mail_set_uid,
	index_mail_set_uid_cache_updates,

	index_mail_get_flags,
	index_mail_get_keywords,
	index_mail_get_keyword_indexes,
	index_mail_get_modseq,
	index_mail_get_parts,
	index_mail_get_date,
	imapc_mail_get_received_date,
	imapc_mail_get_save_date,
	imapc_mail_get_virtual_size,
	imapc_mail_get_physical_size,
	index_mail_get_first_header,
	index_mail_get_headers,
	index_mail_get_header_stream,
	imapc_mail_get_stream,
	index_mail_get_special,
	index_mail_get_real_mail,
	index_mail_update_flags,
	index_mail_update_keywords,
	index_mail_update_modseq,
	NULL,
	index_mail_expunge,
	index_mail_set_cache_corrupted,
	index_mail_opened
};
