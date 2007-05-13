/* Copyright (C) 2005 Timo Sirainen */

#include "lib.h"
#include "ioloop.h"
#include "hex-dec.h"
#include "read-full.h"
#include "istream.h"
#include "index-mail.h"
#include "dbox-file.h"
#include "dbox-sync.h"
#include "dbox-storage.h"

#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

static int dbox_mail_parse_mail_header(struct index_mail *mail,
				       struct dbox_file *file)
{
	struct dbox_mailbox *mbox =
		(struct dbox_mailbox *)mail->mail.mail.box;
	const struct dbox_mail_header *hdr = &file->seeked_mail_header;
	uint32_t hdr_uid = hex2dec(hdr->uid_hex, sizeof(hdr->uid_hex));

	if (hdr_uid != mail->mail.mail.uid) {
		mail_storage_set_critical(&mbox->storage->storage,
			"dbox %s: Cached file offset broken",
			mbox->file->path);

		/* make sure we get it fixed */
		(void)dbox_sync(mbox, TRUE);
		return -1;
	}

	/* Note that the mail may already have an expunge flag, but we don't
	   care since we can still read it */
	mail->data.physical_size = mail->data.virtual_size =
		hex2dec(hdr->mail_size_hex, sizeof(hdr->mail_size_hex));
	mail->data.received_date =
		hex2dec(hdr->received_time_hex, sizeof(hdr->received_time_hex));
	return 1;
}

int dbox_mail_lookup_offset(struct index_transaction_context *trans,
			    uint32_t seq, uint32_t *file_seq_r,
			    uoff_t *offset_r)
{
	struct dbox_mailbox *mbox =
		(struct dbox_mailbox *)trans->ibox;
	uint32_t uid;
	bool synced = FALSE;
	int ret;

	for (;;) {
		ret = dbox_file_lookup_offset(mbox, trans->trans_view, seq,
					      file_seq_r, offset_r);
		if (ret <= 0)
			return ret;
		if (*file_seq_r != 0)
			return 1;

		/* lost file sequence/offset */
		if (synced)
			return -1;

		if (mail_index_lookup_uid(trans->trans_view, seq, &uid) < 0) {
			mail_storage_set_index_error(&mbox->ibox);
			return -1;
		}

		mail_storage_set_critical(&mbox->storage->storage,
			"Cached message offset lost for uid %u in "
			"dbox %s", uid, mbox->path);

		/* resync and try again */
		if (dbox_sync(mbox, TRUE) < 0)
			return -1;
		synced = TRUE;
	}
}

static bool dbox_mail_try_open(struct index_mail *mail,
			       uint32_t *file_seq_r, uoff_t *offset_r,
			       int *ret_r)
{
	struct dbox_mailbox *mbox = (struct dbox_mailbox *)mail->ibox;
	struct dbox_transaction_context *t =
		(struct dbox_transaction_context *)mail->trans;
	uint32_t seq = mail->mail.mail.seq;

	*ret_r = dbox_mail_lookup_offset(mail->trans, seq,
					 file_seq_r, offset_r);
	if (*ret_r <= 0) {
		if (*ret_r == 0)
			mail_set_expunged(&mail->mail.mail);
		return TRUE;
	}

	if ((*ret_r = dbox_file_seek(mbox, *file_seq_r, *offset_r,
				     seq >= t->first_saved_mail_seq)) < 0)
		return TRUE;
	if (*ret_r > 0) {
		/* ok */
		*ret_r = dbox_mail_parse_mail_header(mail, mbox->file);
		return TRUE;
	}
	return FALSE;
}

static int dbox_mail_open(struct index_mail *mail, uoff_t *offset_r)
{
	struct dbox_mailbox *mbox = (struct dbox_mailbox *)mail->ibox;
	uint32_t file_seq, prev_file_seq = 0;
	uoff_t prev_offset = 0;
	int i, ret;

	if (mail->mail.mail.expunged || mbox->syncing)
		return 0;

	for (i = 0; i < 3; i++) {
		if (dbox_mail_try_open(mail, &file_seq, offset_r, &ret))
			return ret;

		if (prev_file_seq == file_seq && prev_offset == *offset_r) {
			/* broken offset */
			break;
		} else {
			/* mail was moved. resync dbox to find out the new
			   offset and try again. */
			if (dbox_sync(mbox, FALSE) < 0)
				return -1;
		}

		prev_file_seq = file_seq;
		prev_offset = *offset_r;
	}

	mail_storage_set_critical(&mbox->storage->storage,
				  "Cached message offset (%u, %"PRIuUOFF_T") "
				  "broken for uid %u in dbox %s",
				  file_seq, *offset_r, mail->mail.mail.uid,
				  mbox->path);

	if (dbox_sync(mbox, TRUE) < 0)
		return -1;
	if (dbox_mail_try_open(mail, &file_seq, offset_r, &ret))
		return ret;
	return -1;
}

static time_t dbox_mail_get_received_date(struct mail *_mail)
{
	struct index_mail *mail = (struct index_mail *)_mail;
	struct index_mail_data *data = &mail->data;
	uoff_t offset;
	uint32_t t;

	(void)index_mail_get_received_date(_mail);
	if (data->received_date != (time_t)-1)
		return data->received_date;

	if (dbox_mail_open(mail, &offset) <= 0)
		return (time_t)-1;
	if (data->received_date == (time_t)-1) {
		/* it's broken and conflicts with our "not found"
		   return value. change it. */
		data->received_date = 0;
	}

	t = data->received_date;
	index_mail_cache_add(mail, MAIL_CACHE_RECEIVED_DATE, &t, sizeof(t));
	return data->received_date;
}

static time_t dbox_mail_get_save_date(struct mail *_mail)
{
	struct index_mail *mail = (struct index_mail *)_mail;
	struct index_mail_data *data = &mail->data;
	uoff_t offset;

	(void)index_mail_get_save_date(_mail);
	if (data->save_date != (time_t)-1)
		return data->save_date;

	if (dbox_mail_open(mail, &offset) <= 0)
		return (time_t)-1;
	if (data->save_date == (time_t)-1) {
		/* it's broken and conflicts with our "not found"
		   return value. change it. */
		data->save_date = ioloop_time;
	}

	index_mail_cache_add(mail, MAIL_CACHE_SAVE_DATE,
			     &data->save_date, sizeof(data->save_date));
	return data->save_date;
}

static uoff_t dbox_mail_get_physical_size(struct mail *_mail)
{
	struct index_mail *mail = (struct index_mail *)_mail;
	struct index_mail_data *data = &mail->data;
	uoff_t offset;

	(void)index_mail_get_physical_size(_mail);
	if (data->physical_size != (uoff_t)-1)
		return data->physical_size;

	if (dbox_mail_open(mail, &offset) <= 0)
		return (uoff_t)-1;

	index_mail_cache_add(mail, MAIL_CACHE_PHYSICAL_FULL_SIZE,
			     &data->physical_size, sizeof(data->physical_size));
	return data->physical_size;

}

static struct istream *
dbox_mail_get_stream(struct mail *_mail,
		     struct message_size *hdr_size,
		     struct message_size *body_size)
{
	struct index_mail *mail = (struct index_mail *)_mail;
	struct dbox_mailbox *mbox = (struct dbox_mailbox *)mail->ibox;
	uoff_t offset;

	if (mail->data.stream == NULL) {
		if (dbox_mail_open(mail, &offset) <= 0)
			return NULL;

		offset += mbox->file->mail_header_size;
		mail->data.stream =
			i_stream_create_limit(default_pool, mbox->file->input,
					      offset,
					      mbox->file->seeked_mail_size);
	}

	return index_mail_init_stream(mail, hdr_size, body_size);
}

struct mail_vfuncs dbox_mail_vfuncs = {
	index_mail_free,
	index_mail_set_seq,
	index_mail_set_uid,

	index_mail_get_flags,
	index_mail_get_keywords,
	index_mail_get_parts,
	index_mail_get_date,
	dbox_mail_get_received_date,
	dbox_mail_get_save_date,
	dbox_mail_get_physical_size, /* physical = virtual in our case */
	dbox_mail_get_physical_size,
	index_mail_get_first_header,
	index_mail_get_headers,
	index_mail_get_header_stream,
	dbox_mail_get_stream,
	index_mail_get_special,
	index_mail_update_flags,
	index_mail_update_keywords,
	index_mail_expunge
};
