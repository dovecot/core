/* Copyright (C) 2003 Timo Sirainen */

#include "lib.h"
#include "istream.h"
#include "index-mail.h"
#include "mbox-storage.h"
#include "mbox-file.h"
#include "mbox-lock.h"
#include "mbox-sync-private.h"
#include "istream-raw-mbox.h"
#include "istream-header-filter.h"

#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

static int mbox_mail_seek(struct index_mail *mail)
{
	struct mbox_transaction_context *t =
		(struct mbox_transaction_context *)mail->trans;
	struct index_mailbox *ibox = mail->ibox;
	enum mbox_sync_flags sync_flags = 0;
	int ret, deleted;

	if (mail->mail.mail.expunged)
		return 0;

__again:
	if (ibox->mbox_lock_type == F_UNLCK) {
		sync_flags |= MBOX_SYNC_LOCK_READING;
		if (mbox_sync(ibox, sync_flags) < 0)
			return -1;

		/* refresh index file after mbox has been locked to make
		   sure we get only up-to-date mbox offsets. */
		if (mail_index_refresh(ibox->index) < 0) {
			mail_storage_set_index_error(ibox);
			return -1;
		}

		i_assert(ibox->mbox_lock_type != F_UNLCK);
		t->mbox_lock_id = ibox->mbox_lock_id;
	}

	if (mbox_file_open_stream(ibox) < 0)
		return -1;

	ret = mbox_file_seek(ibox, mail->trans->trans_view,
			     mail->mail.mail.seq, &deleted);
	if (ret < 0) {
		if (deleted) {
			mail->mail.mail.expunged = TRUE;
			return 0;
		}
		return -1;
	}

	if (ret == 0) {
		/* we'll need to re-sync it completely */
		if (ibox->mbox_lock_type == F_RDLCK) {
			if (ibox->mbox_lock_id == t->mbox_lock_id)
				t->mbox_lock_id = 0;
			(void)mbox_unlock(mail->ibox, ibox->mbox_lock_id);
			ibox->mbox_lock_id = 0;
			i_assert(ibox->mbox_lock_type == F_UNLCK);
		}

		sync_flags |= MBOX_SYNC_UNDIRTY;
		goto __again;
	}

	return 1;
}

static time_t mbox_mail_get_received_date(struct mail *_mail)
{
	struct index_mail *mail = (struct index_mail *)_mail;
	struct index_mail_data *data = &mail->data;

	(void)index_mail_get_received_date(_mail);
	if (data->received_date != (time_t)-1)
		return data->received_date;

	if (mbox_mail_seek(mail) <= 0)
		return (time_t)-1;
	data->received_date =
		istream_raw_mbox_get_received_time(mail->ibox->mbox_stream);
	if (data->received_date == (time_t)-1) {
		/* it's broken and conflicts with our "not found"
		   return value. change it. */
		data->received_date = 0;
	}

	mail_cache_add(mail->trans->cache_trans, mail->data.seq,
		       MAIL_CACHE_RECEIVED_DATE,
		       &data->received_date, sizeof(data->received_date));
	return data->received_date;
}

static const char *
mbox_mail_get_special(struct mail *_mail, enum mail_fetch_field field)
{
	struct index_mail *mail = (struct index_mail *)_mail;

	if (field == MAIL_FETCH_FROM_ENVELOPE) {
		if (mbox_mail_seek(mail) <= 0)
			return NULL;

		return istream_raw_mbox_get_sender(mail->ibox->mbox_stream);

	}

	return index_mail_get_special(_mail, field);
}

static uoff_t mbox_mail_get_physical_size(struct mail *_mail)
{
	struct index_mail *mail = (struct index_mail *)_mail;
	struct index_mail_data *data = &mail->data;
	struct istream *stream;
	uoff_t hdr_offset, body_offset, body_size;

	if (mbox_mail_seek(mail) <= 0)
		return (uoff_t)-1;

	/* our header size varies, so don't do any caching */
	stream = mail->ibox->mbox_stream;
	hdr_offset = istream_raw_mbox_get_header_offset(stream);
	body_offset = istream_raw_mbox_get_body_offset(stream);
	body_size = istream_raw_mbox_get_body_size(stream, (uoff_t)-1);

	data->physical_size = (body_offset - hdr_offset) + body_size;
	return data->physical_size;

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
		if (mbox_mail_seek(mail) <= 0)
			return NULL;

		raw_stream = mail->ibox->mbox_stream;
		offset = istream_raw_mbox_get_header_offset(raw_stream);
		raw_stream = i_stream_create_limit(default_pool, raw_stream,
						   offset, (uoff_t)-1);
		data->stream =
			i_stream_create_header_filter(raw_stream,
						      HEADER_FILTER_EXCLUDE,
						      mbox_hide_headers,
						      mbox_hide_headers_count,
						      NULL, NULL);
		i_stream_unref(raw_stream);
	}

	return index_mail_init_stream(mail, hdr_size, body_size);
}

struct mail_vfuncs mbox_mail_vfuncs = {
	index_mail_free,
	index_mail_set_seq,

	index_mail_get_flags,
	index_mail_get_keywords,
	index_mail_get_parts,
	mbox_mail_get_received_date,
	index_mail_get_date,
	index_mail_get_virtual_size,
	mbox_mail_get_physical_size,
	index_mail_get_header,
	index_mail_get_headers,
	mbox_mail_get_stream,
	mbox_mail_get_special,
	index_mail_update_flags,
	index_mail_update_keywords,
	index_mail_expunge
};
