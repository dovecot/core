/* Copyright (C) 2007 Timo Sirainen */

#include "lib.h"
#include "istream.h"
#include "index-mail.h"
#include "dbox-storage.h"
#include "dbox-file.h"

#include <stdlib.h>

struct dbox_mail {
	struct index_mail imail;

	struct dbox_file *open_file;
	uoff_t offset;
};

struct mail *
dbox_mail_alloc(struct mailbox_transaction_context *t,
		enum mail_fetch_field wanted_fields,
		struct mailbox_header_lookup_ctx *wanted_headers)
{
	struct dbox_mail *mail;
	pool_t pool;

	pool = pool_alloconly_create("mail", 1024);
	mail = p_new(pool, struct dbox_mail, 1);
	mail->imail.mail.pool = pool;

	index_mail_init(&mail->imail, t, wanted_fields, wanted_headers);
	return &mail->imail.mail.mail;
}

static void dbox_mail_close(struct mail *_mail)
{
	struct dbox_mail *mail = (struct dbox_mail *)_mail;

	if (mail->open_file != NULL)
		dbox_file_unref(&mail->open_file);
	index_mail_close(_mail);
}

static int dbox_mail_lookup(struct dbox_mail *mail,
			    uoff_t *offset_r, struct dbox_file **file_r)
{
	struct dbox_mailbox *mbox = (struct dbox_mailbox *)mail->imail.ibox;
	unsigned int file_id;

	if (mail->open_file == NULL) {
		if (!dbox_file_lookup(mbox, mbox->ibox.view,
				      mail->imail.mail.mail.seq,
				      &file_id, &mail->offset)) {
			mail_set_expunged(&mail->imail.mail.mail);
			return -1;
		}
		mail->open_file = dbox_file_init(mbox, file_id);
	}

	*file_r = mail->open_file;
	*offset_r = mail->offset;
	return 0;
}

static int
dbox_mail_metadata_seek(struct dbox_mail *mail, struct dbox_file **file_r)
{
	struct mail *_mail = &mail->imail.mail.mail;
	uoff_t offset, metadata_offset, physical_size;
	bool expunged;
	int ret;

	if (dbox_mail_lookup(mail, &offset, file_r) < 0)
		return -1;

	if (mail_get_physical_size(_mail, &physical_size) < 0)
		return -1;

	metadata_offset =
		dbox_file_get_metadata_offset(*file_r, offset, physical_size);
	ret = dbox_file_metadata_seek(*file_r, metadata_offset, &expunged);
	if (ret <= 0) {
		if (ret < 0)
			return -1;
		/* FIXME */
		return -1;
	}
	if (expunged) {
		mail_set_expunged(&mail->imail.mail.mail);
		return -1;
	}
	return 0;
}

static int dbox_mail_get_received_date(struct mail *_mail, time_t *date_r)
{
	struct dbox_mail *mail = (struct dbox_mail *)_mail;
	struct index_mail_data *data = &mail->imail.data;
	struct dbox_file *file;
	const char *value;
	uint32_t t;

	(void)index_mail_get_received_date(_mail, date_r);
	if (*date_r != (time_t)-1)
		return 0;

	if (dbox_mail_metadata_seek(mail, &file) < 0)
		return -1;

	value = dbox_file_metadata_get(file, DBOX_METADATA_RECEIVED_TIME);
	data->received_date = t = value == NULL ? 0 : strtoul(value, NULL, 16);
	index_mail_cache_add(&mail->imail, MAIL_CACHE_RECEIVED_DATE,
			     &t, sizeof(t));
	*date_r = data->received_date;
	return 0;
}

static int dbox_mail_get_save_date(struct mail *_mail, time_t *date_r)
{
	struct dbox_mail *mail = (struct dbox_mail *)_mail;
	struct index_mail_data *data = &mail->imail.data;
	struct dbox_file *file;
	const char *value;
	uint32_t t;

	(void)index_mail_get_save_date(_mail, date_r);
	if (*date_r != (time_t)-1)
		return 0;

	if (dbox_mail_metadata_seek(mail, &file) < 0)
		return -1;

	value = dbox_file_metadata_get(file, DBOX_METADATA_SAVE_TIME);
	data->save_date = t = value == NULL ? 0 : strtoul(value, NULL, 16);
	index_mail_cache_add(&mail->imail, MAIL_CACHE_SAVE_DATE, &t, sizeof(t));
	*date_r = data->save_date;
	return 0;
}

static int dbox_mail_get_virtual_size(struct mail *_mail, uoff_t *size_r)
{
	struct dbox_mail *mail = (struct dbox_mail *)_mail;
	struct index_mail_data *data = &mail->imail.data;
	struct dbox_file *file;
	const char *value;

	if (index_mail_get_cached_virtual_size(&mail->imail, size_r))
		return 0;

	if (dbox_mail_metadata_seek(mail, &file) < 0)
		return -1;

	value = dbox_file_metadata_get(file, DBOX_METADATA_VIRTUAL_SIZE);
	if (value == NULL)
		return index_mail_get_virtual_size(_mail, size_r);

	data->virtual_size = strtoul(value, NULL, 16);
	index_mail_cache_add(&mail->imail, MAIL_CACHE_VIRTUAL_FULL_SIZE,
			     &data->virtual_size, sizeof(data->virtual_size));
	*size_r = data->virtual_size;
	return 0;
}

static int dbox_mail_get_physical_size(struct mail *_mail, uoff_t *size_r)
{
	struct index_mail *mail = (struct index_mail *)_mail;
	struct index_mail_data *data = &mail->data;
	struct istream *input;

	(void)index_mail_get_physical_size(_mail, size_r);
	if (*size_r != (uoff_t)-1)
		return 0;

	if (mail_get_stream(_mail, NULL, NULL, &input) < 0)
		return -1;

	i_assert(data->physical_size != (uoff_t)-1);
	index_mail_cache_add(mail, MAIL_CACHE_PHYSICAL_FULL_SIZE,
			     &data->physical_size, sizeof(data->physical_size));
	*size_r = data->physical_size;
	return 0;
}

static int
dbox_mail_get_stream(struct mail *_mail, struct message_size *hdr_size,
		     struct message_size *body_size, struct istream **stream_r)
{
	struct dbox_mail *mail = (struct dbox_mail *)_mail;
	struct index_mail_data *data = &mail->imail.data;
	struct istream *input;
	uoff_t offset;
	uint32_t uid;
	bool expunged;
	int ret;

	if (data->stream == NULL) {
		if (dbox_mail_lookup(mail, &offset, &mail->open_file) < 0)
			return -1;

		ret = dbox_file_get_mail_stream(mail->open_file, offset, &uid,
						&data->physical_size, &input,
						&expunged);
		if (ret < 0)
			return -1;
		if (ret > 0 && expunged) {
			mail_set_expunged(_mail);
			return -1;
		}
		if (ret == 0 || uid != _mail->uid) {
			/* FIXME: broken file/offset */
			if (ret > 0)
				i_stream_unref(&input);
			return -1;
		}
		data->stream = input;
	}

	return index_mail_init_stream(&mail->imail, hdr_size, body_size,
				      stream_r);
}

struct mail_vfuncs dbox_mail_vfuncs = {
	dbox_mail_close,
	index_mail_free,
	index_mail_set_seq,
	index_mail_set_uid,

	index_mail_get_flags,
	index_mail_get_keywords,
	index_mail_get_parts,
	index_mail_get_date,
	dbox_mail_get_received_date,
	dbox_mail_get_save_date,
	dbox_mail_get_virtual_size,
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
