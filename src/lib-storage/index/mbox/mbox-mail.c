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
	i_assert(mail->mail.seq <= mail->ibox->mbox_data_count);

	// FIXME: lock the file

	if (mbox_file_open_stream(mail->ibox) < 0)
		return -1;

	i_stream_seek(mail->ibox->mbox_stream,
		      mail->ibox->mbox_data[mail->mail.seq-1] >> 1);
	return 0;
}

static const struct mail_full_flags *mbox_mail_get_flags(struct mail *_mail)
{
	struct index_mail *mail = (struct index_mail *)_mail;
	struct index_mail_data *data = &mail->data;

	i_assert(_mail->seq <= mail->ibox->mbox_data_count);

	(void)index_mail_get_flags(_mail);
	if ((mail->ibox->mbox_data[_mail->seq-1] & 1) != 0)
		data->flags.flags |= MAIL_RECENT;

	return &data->flags;
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

	if (data->stream == NULL) {
		if (mbox_mail_seek(mail) < 0)
			return NULL;

		data->stream = mail->ibox->mbox_stream;
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
