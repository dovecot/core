/* Copyright (c) 2007-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "istream.h"
#include "str.h"
#include "index-storage.h"
#include "index-mail.h"
#include "index-pop3-uidl.h"
#include "dbox-attachment.h"
#include "dbox-storage.h"
#include "dbox-file.h"
#include "dbox-mail.h"


struct mail *
dbox_mail_alloc(struct mailbox_transaction_context *t,
		enum mail_fetch_field wanted_fields,
		struct mailbox_header_lookup_ctx *wanted_headers)
{
	struct dbox_mail *mail;
	pool_t pool;

	pool = pool_alloconly_create("mail", 2048);
	mail = p_new(pool, struct dbox_mail, 1);
	mail->imail.mail.pool = pool;

	index_mail_init(&mail->imail, t, wanted_fields, wanted_headers);
	return &mail->imail.mail.mail;
}

void dbox_mail_close(struct mail *_mail)
{
	struct dbox_mail *mail = DBOX_MAIL(_mail);

	index_mail_close(_mail);
	/* close the dbox file only after index is closed, since it may still
	   try to read from it. */
	if (mail->open_file != NULL)
		dbox_file_unref(&mail->open_file);
}

int dbox_mail_metadata_read(struct dbox_mail *mail, struct dbox_file **file_r)
{
	struct dbox_storage *storage =
		DBOX_STORAGE(mail->imail.mail.mail.box->storage);
	uoff_t offset;

	if (storage->v.mail_open(mail, &offset, file_r) < 0)
		return -1;

	if (dbox_file_seek(*file_r, offset) <= 0)
		return -1;
	if (dbox_file_metadata_read(*file_r) <= 0)
		return -1;

	if (mail->imail.data.stream != NULL) {
		/* we just messed up mail's input stream by reading metadata */
		i_stream_seek((*file_r)->input, offset);
		i_stream_sync(mail->imail.data.stream);
	}
	return 0;
}

static int
dbox_mail_metadata_get(struct dbox_mail *mail, enum dbox_metadata_key key,
		       const char **value_r)
{
	struct dbox_file *file;

	if (dbox_mail_metadata_read(mail, &file) < 0)
		return -1;

	*value_r = dbox_file_metadata_get(file, key);
	return 0;
}

int dbox_mail_get_physical_size(struct mail *_mail, uoff_t *size_r)
{
	struct dbox_mail *mail = DBOX_MAIL(_mail);
	struct index_mail_data *data = &mail->imail.data;
	struct dbox_file *file;

	if (index_mail_get_physical_size(_mail, size_r) == 0)
		return 0;

	if (dbox_mail_metadata_read(mail, &file) < 0)
		return -1;

	data->physical_size = dbox_file_get_plaintext_size(file);
	*size_r = data->physical_size;
	return 0;
}

int dbox_mail_get_virtual_size(struct mail *_mail, uoff_t *size_r)
{
	struct dbox_mail *mail = DBOX_MAIL(_mail);
	struct index_mail_data *data = &mail->imail.data;
	const char *value;
	uintmax_t size;

	if (index_mail_get_cached_virtual_size(&mail->imail, size_r))
		return 0;

	if (dbox_mail_metadata_get(mail, DBOX_METADATA_VIRTUAL_SIZE,
				   &value) < 0)
		return -1;
	if (value == NULL)
		return index_mail_get_virtual_size(_mail, size_r);

	if (str_to_uintmax_hex(value, &size) < 0 || size > (uoff_t)-1)
		return -1;
	data->virtual_size = (uoff_t)size;
	*size_r = data->virtual_size;
	return 0;
}

int dbox_mail_get_received_date(struct mail *_mail, time_t *date_r)
{
	struct dbox_mail *mail = DBOX_MAIL(_mail);
	struct index_mail_data *data = &mail->imail.data;
	const char *value;
	uintmax_t time;

	if (index_mail_get_received_date(_mail, date_r) == 0)
		return 0;

	if (dbox_mail_metadata_get(mail, DBOX_METADATA_RECEIVED_TIME,
				   &value) < 0)
		return -1;

	time = 0;
	if (value != NULL && str_to_uintmax_hex(value, &time) < 0)
		return -1;

	data->received_date = (time_t)time;
	*date_r = data->received_date;
	return 0;
}

int dbox_mail_get_save_date(struct mail *_mail, time_t *date_r)
{
	struct dbox_storage *storage = DBOX_STORAGE(_mail->box->storage);
	struct dbox_mail *mail = DBOX_MAIL(_mail);
	struct index_mail_data *data = &mail->imail.data;
	struct dbox_file *file;
	struct stat st;
	uoff_t offset;

 	if (index_mail_get_save_date(_mail, date_r) == 0)
		return 0;

	if (storage->v.mail_open(mail, &offset, &file) < 0)
		return -1;

	_mail->transaction->stats.fstat_lookup_count++;
	if (dbox_file_stat(file, &st) < 0) {
		if (errno == ENOENT)
			mail_set_expunged(_mail);
		return -1;
	}
	*date_r = data->save_date = st.st_ctime;
	return 0;
}

static int
dbox_get_cached_metadata(struct dbox_mail *mail, enum dbox_metadata_key key,
			 enum index_cache_field cache_field,
			 const char **value_r)
{
	struct index_mail *imail = &mail->imail;
	struct index_mailbox_context *ibox =
		INDEX_STORAGE_CONTEXT(imail->mail.mail.box);
	const char *value;
	string_t *str;
	uint32_t order;

	str = str_new(imail->mail.data_pool, 64);
	if (mail_cache_lookup_field(imail->mail.mail.transaction->cache_view,
				    str, imail->mail.mail.seq,
				    ibox->cache_fields[cache_field].idx) > 0) {
		if (cache_field == MAIL_CACHE_POP3_ORDER) {
			i_assert(str_len(str) == sizeof(order));
			memcpy(&order, str_data(str), sizeof(order));
			str_truncate(str, 0);
			if (order != 0)
				str_printfa(str, "%u", order);
			else {
				/* order=0 means it doesn't exist. we don't
				   want to return "0" though, because then the
				   mails get ordered to beginning, while
				   nonexistent are supposed to be ordered at
				   the end. */
			}
		}
		*value_r = str_c(str);
		return 0;
	}

	if (dbox_mail_metadata_get(mail, key, &value) < 0)
		return -1;

	if (value == NULL)
		value = "";
	if (cache_field != MAIL_CACHE_POP3_ORDER) {
		index_mail_cache_add_idx(imail, ibox->cache_fields[cache_field].idx,
					 value, strlen(value));
	} else {
		if (str_to_uint(value, &order) < 0)
			order = 0;
		index_mail_cache_add_idx(imail, ibox->cache_fields[cache_field].idx,
					 &order, sizeof(order));
	}

	/* don't return pointer to dbox metadata directly, since it may
	   change unexpectedly */
	str_truncate(str, 0);
	str_append(str, value);
	*value_r = str_c(str);
	return 0;
}

int dbox_mail_get_special(struct mail *_mail, enum mail_fetch_field field,
			  const char **value_r)
{
	struct dbox_mail *mail = DBOX_MAIL(_mail);
	int ret;

	/* keep the UIDL in cache file, otherwise POP3 would open all
	   mail files and read the metadata. same for GUIDs if they're
	   used. */
	switch (field) {
	case MAIL_FETCH_UIDL_BACKEND:
		if (!index_pop3_uidl_can_exist(_mail)) {
			*value_r = "";
			return 0;
		}
		ret = dbox_get_cached_metadata(mail, DBOX_METADATA_POP3_UIDL,
					       MAIL_CACHE_POP3_UIDL, value_r);
		if (ret == 0) {
			index_pop3_uidl_update_exists(&mail->imail.mail.mail,
						      (*value_r)[0] != '\0');
		}
		return ret;
	case MAIL_FETCH_POP3_ORDER:
		if (!index_pop3_uidl_can_exist(_mail)) {
			/* we're assuming that if there's a POP3 order, there's
			   also a UIDL */
			*value_r = "";
			return 0;
		}
		return dbox_get_cached_metadata(mail, DBOX_METADATA_POP3_ORDER,
						MAIL_CACHE_POP3_ORDER, value_r);
	case MAIL_FETCH_GUID:
		return dbox_get_cached_metadata(mail, DBOX_METADATA_GUID,
						MAIL_CACHE_GUID, value_r);
	default:
		break;
	}

	return index_mail_get_special(_mail, field, value_r);
}

static int
get_mail_stream(struct dbox_mail *mail, uoff_t offset,
		struct istream **stream_r)
{
	struct mail_private *pmail = &mail->imail.mail;
	struct dbox_file *file = mail->open_file;
	int ret;

	if ((ret = dbox_file_seek(file, offset)) <= 0) {
		*stream_r = NULL;
		return ret;
	}

	*stream_r = i_stream_create_limit(file->input, file->cur_physical_size);
	if (pmail->v.istream_opened != NULL) {
		if (pmail->v.istream_opened(&pmail->mail, stream_r) < 0)
			return -1;
	}
	if (file->storage->attachment_dir == NULL)
		return 1;
	else
		return dbox_attachment_file_get_stream(file, stream_r);
}

int dbox_mail_get_stream(struct mail *_mail, bool get_body ATTR_UNUSED,
			 struct message_size *hdr_size,
			 struct message_size *body_size,
			 struct istream **stream_r)
{
	struct dbox_storage *storage = DBOX_STORAGE(_mail->box->storage);
	struct dbox_mail *mail = DBOX_MAIL(_mail);
	struct index_mail_data *data = &mail->imail.data;
	struct istream *input;
	uoff_t offset;
	int ret;

	if (data->stream == NULL) {
		if (storage->v.mail_open(mail, &offset, &mail->open_file) < 0)
			return -1;

		ret = get_mail_stream(mail, offset, &input);
		if (ret <= 0) {
			if (ret < 0)
				return -1;
			dbox_file_set_corrupted(mail->open_file,
				"uid=%u points to broken data at offset="
				"%"PRIuUOFF_T, _mail->uid, offset);
			i_stream_unref(&input);
			return -1;
		}
		data->stream = input;
		index_mail_set_read_buffer_size(_mail, input);
	}

	return index_mail_init_stream(&mail->imail, hdr_size, body_size,
				      stream_r);
}
