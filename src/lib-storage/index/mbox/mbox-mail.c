/* Copyright (c) 2003-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "istream.h"
#include "hex-binary.h"
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

static void mbox_prepare_resync(struct mail *mail)
{
	struct mbox_transaction_context *t =
		(struct mbox_transaction_context *)mail->transaction;
	struct mbox_mailbox *mbox = (struct mbox_mailbox *)mail->box;

	if (mbox->mbox_lock_type == F_RDLCK) {
		if (mbox->mbox_lock_id == t->mbox_lock_id)
			t->mbox_lock_id = 0;
		(void)mbox_unlock(mbox, mbox->mbox_lock_id);
		i_assert(mbox->mbox_lock_type == F_UNLCK);
	}
}

static int mbox_mail_seek(struct index_mail *mail)
{
	struct mbox_transaction_context *t =
		(struct mbox_transaction_context *)mail->trans;
	struct mail *_mail = &mail->mail.mail;
	struct mbox_mailbox *mbox = (struct mbox_mailbox *)_mail->box;
	enum mbox_sync_flags sync_flags = 0;
	int ret, try;
	bool deleted;

	if (_mail->expunged || mbox->syncing)
		return -1;

	if (_mail->lookup_abort != MAIL_LOOKUP_ABORT_NEVER)
		return mail_set_aborted(_mail);

	if (mbox->mbox_stream != NULL &&
	    istream_raw_mbox_is_corrupted(mbox->mbox_stream)) {
		/* clear the corruption by forcing a full resync */
		sync_flags |= MBOX_SYNC_UNDIRTY | MBOX_SYNC_FORCE_SYNC;
	}

	for (try = 0; try < 2; try++) {
		if ((sync_flags & MBOX_SYNC_FORCE_SYNC) != 0) {
			/* dirty offsets are broken. make sure we can sync. */
			mbox_prepare_resync(_mail);
		}
		if (mbox->mbox_lock_type == F_UNLCK) {
			sync_flags |= MBOX_SYNC_LOCK_READING;
			if (mbox_sync(mbox, sync_flags) < 0)
				return -1;
			t->mbox_lock_id = mbox->mbox_lock_id;
			i_assert(t->mbox_lock_id != 0);

			/* refresh index file after mbox has been locked to
			   make sure we get only up-to-date mbox offsets. */
			if (mail_index_refresh(mbox->box.index) < 0) {
				mail_storage_set_index_error(&mbox->box);
				return -1;
			}

			i_assert(mbox->mbox_lock_type != F_UNLCK);
		} else if (t->mbox_lock_id == 0) {
			/* file is already locked by another transaction, but
			   we must keep it locked for the entire transaction,
			   so increase the lock counter. */
			if (mbox_lock(mbox, mbox->mbox_lock_type,
				      &t->mbox_lock_id) < 0)
				i_unreached();
		}

		if (mbox_file_open_stream(mbox) < 0)
			return -1;

		ret = mbox_file_seek(mbox, _mail->transaction->view,
				     _mail->seq, &deleted);
		if (ret > 0) {
			/* success */
			break;
		}
		if (ret < 0) {
			if (deleted)
				mail_set_expunged(_mail);
			return -1;
		}

		/* we'll need to re-sync it completely */
		sync_flags |= MBOX_SYNC_UNDIRTY | MBOX_SYNC_FORCE_SYNC;
	}
	if (ret == 0) {
		mail_storage_set_critical(&mbox->storage->storage,
			"Losing sync for mail uid=%u in mbox file %s",
			_mail->uid, mbox->box.path);
	}
	return 0;
}

static int mbox_mail_get_received_date(struct mail *_mail, time_t *date_r)
{
	struct index_mail *mail = (struct index_mail *)_mail;
	struct index_mail_data *data = &mail->data;
	struct mbox_mailbox *mbox = (struct mbox_mailbox *)_mail->box;

	if (index_mail_get_received_date(_mail, date_r) == 0)
		return 0;

	if (mbox_mail_seek(mail) < 0)
		return -1;
	data->received_date =
		istream_raw_mbox_get_received_time(mbox->mbox_stream);
	if (data->received_date == (time_t)-1) {
		/* it's broken and conflicts with our "not found"
		   return value. change it. */
		data->received_date = 0;
	}

	*date_r = data->received_date;
	return 0;
}

static int mbox_mail_get_save_date(struct mail *_mail, time_t *date_r)
{
	struct index_mail *mail = (struct index_mail *)_mail;
	struct index_mail_data *data = &mail->data;

	if (index_mail_get_save_date(_mail, date_r) == 0)
		return 0;

	/* no way to know this. save the current time into cache and use
	   that from now on. this works only as long as the index files
	   are permanent */
	data->save_date = ioloop_time;
	*date_r = data->save_date;
	return 0;
}

static bool
mbox_mail_get_md5_header(struct index_mail *mail, const char **value_r)
{
	static uint8_t empty_md5[16] =
		{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
	struct mbox_mailbox *mbox = (struct mbox_mailbox *)mail->mail.mail.box;
	const void *ext_data;

	if (mail->data.guid != NULL) {
		*value_r = mail->data.guid;
		return TRUE;
	}

	mail_index_lookup_ext(mail->mail.mail.transaction->view,
			      mail->mail.mail.seq, mbox->md5hdr_ext_idx,
			      &ext_data, NULL);
	if (ext_data != NULL && memcmp(ext_data, empty_md5, 16) != 0) {
		mail->data.guid = p_strdup(mail->data_pool,
					   binary_to_hex(ext_data, 16));
		*value_r = mail->data.guid;
		return TRUE;
	} else {
		return FALSE;
	}
}

static int
mbox_mail_get_special(struct mail *_mail, enum mail_fetch_field field,
		      const char **value_r)
{
	struct index_mail *mail = (struct index_mail *)_mail;
	struct mbox_mailbox *mbox = (struct mbox_mailbox *)_mail->box;
	uoff_t offset;

	switch (field) {
	case MAIL_FETCH_FROM_ENVELOPE:
		if (mbox_mail_seek(mail) < 0)
			return -1;

		*value_r = istream_raw_mbox_get_sender(mbox->mbox_stream);
		return 0;
	case MAIL_FETCH_GUID:
	case MAIL_FETCH_HEADER_MD5:
		if (mbox_mail_get_md5_header(mail, value_r))
			return 0;

		/* i guess in theory the empty_md5 is valid and can happen,
		   but it's almost guaranteed that it means the MD5 sum is
		   missing. recalculate it. */
		offset = mbox->mbox_lock_type == F_UNLCK ? 0 :
			istream_raw_mbox_get_start_offset(mbox->mbox_stream);
		mbox->mbox_save_md5 = TRUE;
		if (mbox_sync(mbox, MBOX_SYNC_FORCE_SYNC |
			      MBOX_SYNC_READONLY) < 0)
			return -1;
		if (mbox->mbox_lock_type != F_UNLCK) {
			if (istream_raw_mbox_seek(mbox->mbox_stream,
						  offset) < 0) {
				i_error("mbox %s sync lost during MD5 syncing",
					_mail->box->name);
				return -1;
			}
		}

		if (!mbox_mail_get_md5_header(mail, value_r)) {
			i_error("mbox %s resyncing didn't save header MD5 values",
				_mail->box->name);
			return -1;
		}
		return 0;
	default:
		break;
	}

	return index_mail_get_special(_mail, field, value_r);
}

static bool
mbox_mail_get_next_offset(struct index_mail *mail, uoff_t *next_offset_r)
{
	struct mbox_mailbox *mbox = (struct mbox_mailbox *)mail->mail.mail.box;
	struct mail_index_view *view;
	const struct mail_index_header *hdr;
	uint32_t seq;
	int trailer_size;
	int ret = 1;

	hdr = mail_index_get_header(mail->mail.mail.transaction->view);
	if (mail->mail.mail.seq > hdr->messages_count) {
		/* we're appending a new message */
		return 0;
	}

	/* We can't really trust trans_view. The next message may already be
	   expunged from it. Also hdr.messages_count may be incorrect there.
	   So refresh the index to get the latest changes and get the next
	   message's offset using a new view. */
	i_assert(mbox->mbox_lock_type != F_UNLCK);
	if (mbox_sync_header_refresh(mbox) < 0)
		return -1;

	view = mail_index_view_open(mail->mail.mail.box->index);
	hdr = mail_index_get_header(view);
	if (!mail_index_lookup_seq(view, mail->mail.mail.uid, &seq))
		i_panic("Message unexpectedly expunged from index");

	if (seq == hdr->messages_count) {
		/* last message, use the synced mbox size */
		trailer_size =
			mbox->storage->storage.set->mail_save_crlf ? 2 : 1;
		*next_offset_r = mbox->mbox_hdr.sync_size - trailer_size;
	} else {
		if (mbox_file_lookup_offset(mbox, view, seq + 1,
					    next_offset_r) <= 0)
			ret = -1;
	}
	mail_index_view_close(&view);
	return ret;
}

static int mbox_mail_get_physical_size(struct mail *_mail, uoff_t *size_r)
{
	struct index_mail *mail = (struct index_mail *)_mail;
	struct index_mail_data *data = &mail->data;
	struct mbox_mailbox *mbox = (struct mbox_mailbox *)_mail->box;
	struct istream *input;
	struct message_size hdr_size;
	uoff_t old_offset, body_offset, body_size, next_offset;

	if (index_mail_get_physical_size(_mail, size_r) == 0)
		return 0;

	/* we want to return the header size as seen by mail_get_stream(). */
	old_offset = data->stream == NULL ? 0 : data->stream->v_offset;
	if (mail_get_stream(_mail, &hdr_size, NULL, &input) < 0)
		return -1;

	/* our header size varies, so don't do any caching */
	body_offset = istream_raw_mbox_get_body_offset(mbox->mbox_stream);
	if (body_offset == (uoff_t)-1) {
		mail_storage_set_critical(_mail->box->storage,
					  "Couldn't get mbox size");
		return -1;
	}

	/* use the next message's offset to avoid reading through the entire
	   message body to find out its size */
	if (mbox_mail_get_next_offset(mail, &next_offset) > 0)
		body_size = next_offset - body_offset;
	else
		body_size = (uoff_t)-1;

	/* verify that the calculated body size is correct */
	body_size = istream_raw_mbox_get_body_size(mbox->mbox_stream,
						   body_size);

	data->physical_size = hdr_size.physical_size + body_size;
	*size_r = data->physical_size;

	i_stream_seek(input, old_offset);
	return 0;
}

static int mbox_mail_init_stream(struct index_mail *mail)
{
	struct mbox_mailbox *mbox = (struct mbox_mailbox *)mail->mail.mail.box;
	struct istream *raw_stream;
	uoff_t hdr_offset, next_offset;
	int ret;

	if (mbox_mail_seek(mail) < 0)
		return -1;

	ret = mbox_mail_get_next_offset(mail, &next_offset);
	if (ret < 0) {
		if (mbox_mail_seek(mail) < 0)
			return -1;
		ret = mbox_mail_get_next_offset(mail, &next_offset);
		if (ret < 0) {
			i_warning("mbox %s: Can't find next message offset "
				  "for uid=%u",
				  mbox->box.path, mail->mail.mail.uid);
		}
	}
	if (ret <= 0)
		next_offset = (uoff_t)-1;

	raw_stream = mbox->mbox_stream;
	hdr_offset = istream_raw_mbox_get_header_offset(raw_stream);
	i_stream_seek(raw_stream, hdr_offset);

	if (next_offset != (uoff_t)-1)
		istream_raw_mbox_set_next_offset(raw_stream, next_offset);

	raw_stream = i_stream_create_limit(raw_stream, (uoff_t)-1);
	mail->data.stream =
		i_stream_create_header_filter(raw_stream,
				HEADER_FILTER_EXCLUDE | HEADER_FILTER_NO_CR,
				mbox_hide_headers, mbox_hide_headers_count,
				null_header_filter_callback, NULL);
	i_stream_unref(&raw_stream);
	return 0;
}

static int mbox_mail_get_stream(struct mail *_mail,
				struct message_size *hdr_size,
				struct message_size *body_size,
				struct istream **stream_r)
{
	struct index_mail *mail = (struct index_mail *)_mail;

	if (mail->data.stream == NULL) {
		if (mbox_mail_init_stream(mail) < 0)
			return -1;
	}

	return index_mail_init_stream(mail, hdr_size, body_size, stream_r);
}

static void mbox_mail_set_seq(struct mail *_mail, uint32_t seq)
{
	struct index_mail *mail = (struct index_mail *)_mail;

	index_mail_set_seq(_mail, seq);
	mail->data.dont_cache_fetch_fields |= MAIL_FETCH_PHYSICAL_SIZE;
}

static bool mbox_mail_set_uid(struct mail *_mail, uint32_t uid)
{
	struct index_mail *mail = (struct index_mail *)_mail;
	bool ret;

	ret = index_mail_set_uid(_mail, uid);
	mail->data.dont_cache_fetch_fields |= MAIL_FETCH_PHYSICAL_SIZE;
	return ret;
}

struct mail_vfuncs mbox_mail_vfuncs = {
	index_mail_close,
	index_mail_free,
	mbox_mail_set_seq,
	mbox_mail_set_uid,
	index_mail_set_uid_cache_updates,

	index_mail_get_flags,
	index_mail_get_keywords,
	index_mail_get_keyword_indexes,
	index_mail_get_modseq,
	index_mail_get_parts,
	index_mail_get_date,
	mbox_mail_get_received_date,
	mbox_mail_get_save_date,
	index_mail_get_virtual_size,
	mbox_mail_get_physical_size,
	index_mail_get_first_header,
	index_mail_get_headers,
	index_mail_get_header_stream,
	mbox_mail_get_stream,
	mbox_mail_get_special,
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
