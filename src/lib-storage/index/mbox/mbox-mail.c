/* Copyright (C) 2003 Timo Sirainen */

#include "lib.h"
#include "istream.h"
#include "index-mail.h"
#include "mbox-storage.h"
#include "mbox-file.h"
#include "mbox-sync-private.h"
#include "istream-raw-mbox.h"
#include "istream-header-filter.h"

#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

static int mbox_mail_seek(struct index_mail *mail)
{
	struct index_mailbox *ibox = mail->ibox;
	const void *data;
	uint64_t offset;
	int ret;

	if (ibox->mbox_lock_type == F_UNLCK) {
		if (mbox_sync(ibox, FALSE, FALSE, TRUE) < 0)
			return -1;

		i_assert(ibox->mbox_lock_type != F_UNLCK);
                mail->ibox->mbox_mail_lock_id = ibox->mbox_lock_id;
	}

	if (mbox_file_open_stream(ibox) < 0)
		return -1;

	ret = mail_index_lookup_extra(mail->trans->trans_view, mail->mail.seq,
				      ibox->mbox_extra_idx, &data);
	if (ret <= 0) {
		if (ret < 0)
			mail_storage_set_index_error(ibox);
		return -1;
	}

	offset = *((const uint64_t *)data);
	if (istream_raw_mbox_seek(ibox->mbox_stream, offset) < 0) {
		mail_storage_set_critical(ibox->box.storage,
			"Cached message offset %s is invalid for mbox file %s",
			dec2str(offset), ibox->path);
		mail_index_mark_corrupted(ibox->index);
		return -1;
	}
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
	if (data->received_date == (time_t)-1) {
		/* it's broken and conflicts with our "not found"
		   return value. change it. */
		data->received_date = 0;
	}

	index_mail_cache_add(mail, MAIL_CACHE_RECEIVED_DATE,
			     &data->received_date,
			     sizeof(data->received_date));
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
		raw_stream = i_stream_create_limit(default_pool, raw_stream,
						   offset, (uoff_t)-1);
		data->stream =
			i_stream_create_header_filter(default_pool,
						      raw_stream,
						      mbox_hide_headers,
						      mbox_hide_headers_count);
		i_stream_unref(raw_stream);
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
