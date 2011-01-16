/* Copyright (c) 2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "istream.h"
#include "index-mail.h"
#include "imapc-storage.h"

static int imapc_mail_get_received_date(struct mail *_mail, time_t *date_r)
{
	struct index_mail *mail = (struct index_mail *)_mail;
	struct index_mail_data *data = &mail->data;

	if (data->received_date == (time_t)-1)
		return -1;
	*date_r = data->received_date;
	return 0;
}

static int imapc_mail_get_save_date(struct mail *_mail, time_t *date_r)
{
	struct index_mail *mail = (struct index_mail *)_mail;
	struct index_mail_data *data = &mail->data;

	if (data->save_date == (time_t)-1)
		return -1;
	*date_r = data->save_date;
	return 0;
}

static int imapc_mail_get_physical_size(struct mail *_mail, uoff_t *size_r)
{
	struct index_mail *mail = (struct index_mail *)_mail;
	struct index_mail_data *data = &mail->data;

	if (data->physical_size == (uoff_t)-1)
		return -1;
	*size_r = data->physical_size;
	return 0;
}

static int
imapc_mail_get_stream(struct mail *_mail, struct message_size *hdr_size,
		      struct message_size *body_size, struct istream **stream_r)
{
	struct index_mail *mail = (struct index_mail *)_mail;
	struct index_mail_data *data = &mail->data;

	if (data->stream == NULL)
		return -1;

	return index_mail_init_stream(mail, hdr_size, body_size, stream_r);
}

struct mail_vfuncs imapc_mail_vfuncs = {
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
	imapc_mail_get_received_date,
	imapc_mail_get_save_date,
	imapc_mail_get_physical_size, /* physical = virtual in our case */
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
