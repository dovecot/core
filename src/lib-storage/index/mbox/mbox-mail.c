/* Copyright (C) 2003 Timo Sirainen */

#include "lib.h"
#include "istream.h"
#include "index-mail.h"
#include "mbox-storage.h"
#include "mbox-file.h"
#include "istream-raw-mbox.h"

#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

static int mbox_mail_seek(struct index_mail *mail)
{
	struct index_mailbox *ibox = mail->ibox;
	const void *data;

	if (mail_index_lookup_extra(ibox->view, mail->mail.seq,
				    ibox->mbox_extra_idx, &data) < 0) {
		mail_storage_set_index_error(ibox);
		return -1;
	}

	// FIXME: lock the file. sync if needed.

	if (mbox_file_open_stream(ibox) < 0)
		return -1;

	istream_raw_mbox_seek(ibox->mbox_stream, *((const uint64_t *)data));
	return 0;
}

static const struct mail_full_flags *mbox_mail_get_flags(struct mail *_mail)
{
	return index_mail_get_flags(_mail);
	/*FIXME:struct index_mail *mail = (struct index_mail *)_mail;
	struct index_mail_data *data = &mail->data;

	i_assert(_mail->seq <= mail->ibox->mbox_data_count);

	(void)index_mail_get_flags(_mail);
	if ((mail->ibox->mbox_data[_mail->seq-1] & 1) != 0)
		data->flags.flags |= MAIL_RECENT;

	return &data->flags;*/
}

static time_t mbox_mail_get_received_date(struct mail *_mail)
{
	struct index_mail *mail = (struct index_mail *)_mail;
	struct index_mail_data *data = &mail->data;

	(void)index_mail_get_received_date(_mail);
	if (data->received_date != (time_t)-1)
		return data->received_date;

	if (mbox_mail_seek(mail) < 0)
		return (time_t)-1;
	data->received_date =
		istream_raw_mbox_get_received_time(mail->ibox->mbox_stream);

	if (data->received_date != (time_t)-1) {
		index_mail_cache_add(mail, MAIL_CACHE_RECEIVED_DATE,
				     &data->received_date,
				     sizeof(data->received_date));
	}
	return data->received_date;
}

static const char *
mbox_mail_get_special(struct mail *_mail, enum mail_fetch_field field)
{
	struct index_mail *mail = (struct index_mail *)_mail;

	if (field == MAIL_FETCH_FROM_ENVELOPE) {
		if (mbox_mail_seek(mail) < 0)
			return NULL;

		return istream_raw_mbox_get_sender(mail->ibox->mbox_stream);

	}

	return index_mail_get_special(_mail, field);
}

static struct istream *mbox_mail_get_stream(struct mail *_mail,
					    struct message_size *hdr_size,
					    struct message_size *body_size)
{
	struct index_mail *mail = (struct index_mail *)_mail;
	struct index_mail_data *data = &mail->data;
	struct istream *raw_stream;
	uoff_t offset;

	if (data->stream == NULL) {
		if (mbox_mail_seek(mail) < 0)
			return NULL;

		// FIXME: need to hide the headers
		raw_stream = mail->ibox->mbox_stream;
		offset = istream_raw_mbox_get_header_offset(raw_stream);
		data->stream = i_stream_create_limit(default_pool, raw_stream,
						     offset, (uoff_t)-1);
	}

	return index_mail_init_stream(mail, hdr_size, body_size);
}

struct mail mbox_mail = {
	0, 0, 0, 0, 0, 0,

	mbox_mail_get_flags,
	index_mail_get_parts,
	mbox_mail_get_received_date,
	index_mail_get_date,
	index_mail_get_size,
	index_mail_get_header,
	index_mail_get_headers,
	mbox_mail_get_stream,
	mbox_mail_get_special,
	index_mail_update_flags,
	index_mail_expunge
};
