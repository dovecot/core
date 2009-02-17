/* Copyright (c) 2007-2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "istream.h"
#include "str.h"
#include "index-mail.h"
#include "dbox-storage.h"
#include "dbox-map.h"
#include "dbox-file.h"

#include <stdlib.h>
#include <sys/stat.h>

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

uint32_t dbox_mail_lookup(struct dbox_mailbox *mbox,
			  struct mail_index_view *view, uint32_t seq)
{
	const struct dbox_mail_index_record *dbox_rec;
	const void *data;
	bool expunged;

	mail_index_lookup_ext(view, seq, mbox->dbox_ext_id, &data, &expunged);
	dbox_rec = data;
	return dbox_rec == NULL ? 0 : dbox_rec->map_uid;
}

static int dbox_mail_open(struct dbox_mail *mail,
			  uoff_t *offset_r, struct dbox_file **file_r)
{
	struct dbox_mailbox *mbox = (struct dbox_mailbox *)mail->imail.ibox;
	struct mail *_mail = &mail->imail.mail.mail;
	uint32_t map_uid, file_id;

	if (mail->open_file == NULL) {
		map_uid = dbox_mail_lookup(mbox, mbox->ibox.view, _mail->seq);
		if (map_uid == 0) {
			mail->open_file =
				dbox_file_init_single(mbox, _mail->uid);
		} else if (!dbox_map_lookup(mbox->storage->map_index, map_uid,
					    &file_id, &mail->offset)) {
			mail_set_expunged(_mail);
			return -1;
		} else {
			mail->open_file =
				dbox_file_init_multi(mbox->storage, file_id);
		}
	}

	*file_r = mail->open_file;
	*offset_r = mail->offset;
	return 0;
}

static int
dbox_mail_metadata_seek(struct dbox_mail *mail, struct dbox_file **file_r)
{
	uoff_t offset;
	bool expunged;
	int ret;

	if (dbox_mail_open(mail, &offset, file_r) < 0)
		return -1;

	ret = dbox_file_metadata_seek_mail_offset(*file_r, offset, &expunged);
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

	if (index_mail_get_received_date(_mail, date_r) == 0)
		return 0;

	if (dbox_mail_metadata_seek(mail, &file) < 0)
		return -1;

	value = dbox_file_metadata_get(file, DBOX_METADATA_RECEIVED_TIME);
	data->received_date = value == NULL ? 0 : strtoul(value, NULL, 16);
	*date_r = data->received_date;
	return 0;
}

static int dbox_mail_get_save_date(struct mail *_mail, time_t *date_r)
{
	struct dbox_mail *mail = (struct dbox_mail *)_mail;
	struct index_mail_data *data = &mail->imail.data;
	struct dbox_file *file;
	struct stat st;
	const char *value;

	if (index_mail_get_save_date(_mail, date_r) == 0)
		return 0;

	if (dbox_mail_metadata_seek(mail, &file) < 0)
		return -1;

	value = dbox_file_metadata_get(file, DBOX_METADATA_SAVE_TIME);
	data->save_date = value == NULL ? 0 : strtoul(value, NULL, 16);

	if (data->save_date == 0) {
		/* missing / corrupted save time - use the file's ctime */
		i_assert(file->fd != -1);
		if (fstat(file->fd, &st) < 0) {
			mail_storage_set_critical(_mail->box->storage,
				"fstat(%s) failed: %m", file->current_path);
			return -1;
		}
		data->save_date = st.st_ctime;
	}
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
	*size_r = data->virtual_size;
	return 0;
}

static int dbox_mail_get_physical_size(struct mail *_mail, uoff_t *size_r)
{
	struct index_mail *mail = (struct index_mail *)_mail;
	struct index_mail_data *data = &mail->data;
	struct istream *input;

	if (index_mail_get_physical_size(_mail, size_r) == 0)
		return 0;

	if (mail_get_stream(_mail, NULL, NULL, &input) < 0)
		return -1;

	i_assert(data->physical_size != (uoff_t)-1);
	*size_r = data->physical_size;
	return 0;
}

static int
dbox_get_cached_metadata(struct dbox_mail *mail, enum dbox_metadata_key key,
			 enum index_cache_field cache_field,
			 const char **value_r)
{
	struct index_mail *imail = &mail->imail;
	const struct mail_cache_field *cache_fields = imail->ibox->cache_fields;
	struct dbox_file *file;
	const char *value;
	string_t *str;

	str = str_new(imail->data_pool, 64);
	if (mail_cache_lookup_field(imail->trans->cache_view, str,
				    imail->mail.mail.seq,
				    cache_fields[cache_field].idx) > 0) {
		*value_r = str_c(str);
		return 0;
	}

	if (dbox_mail_metadata_seek(mail, &file) < 0)
		return -1;

	value = dbox_file_metadata_get(file, key);
	if (value == NULL)
		value = "";
	index_mail_cache_add_idx(imail, cache_fields[cache_field].idx,
				 value, strlen(value)+1);
	*value_r = value;
	return 0;
}

static int
dbox_mail_get_special(struct mail *_mail, enum mail_fetch_field field,
		      const char **value_r)
{
	struct dbox_mail *mail = (struct dbox_mail *)_mail;

	/* keep the UIDL in cache file, otherwise POP3 would open all
	   mail files and read the metadata. same for GUIDs if they're
	   used. */
	switch (field) {
	case MAIL_FETCH_UIDL_BACKEND:
		return dbox_get_cached_metadata(mail, DBOX_METADATA_POP3_UIDL,
						MAIL_CACHE_POP3_UIDL, value_r);
	case MAIL_FETCH_GUID:
		return dbox_get_cached_metadata(mail, DBOX_METADATA_GUID,
						MAIL_CACHE_GUID, value_r);
	default:
		break;
	}

	return index_mail_get_special(_mail, field, value_r);
}
							
static int
dbox_mail_get_stream(struct mail *_mail, struct message_size *hdr_size,
		     struct message_size *body_size, struct istream **stream_r)
{
	struct dbox_mail *mail = (struct dbox_mail *)_mail;
	struct index_mail_data *data = &mail->imail.data;
	struct istream *input;
	uoff_t offset, size;
	bool expunged;
	int ret;

	if (data->stream == NULL) {
		if (dbox_mail_open(mail, &offset, &mail->open_file) < 0)
			return -1;

		ret = dbox_file_get_mail_stream(mail->open_file, offset,
						&size, &input, &expunged);
		if (ret < 0)
			return -1;
		if (ret > 0 && expunged) {
			mail_set_expunged(_mail);
			return -1;
		}
		if (ret == 0) {
			/* FIXME: broken file/offset */
			if (ret > 0)
				i_stream_unref(&input);
			mail_storage_set_critical(_mail->box->storage,
				"broken pointer to dbox file %s",
				mail->open_file->current_path);
			return -1;
		}
		data->physical_size = size;
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
	index_mail_get_keyword_indexes,
	index_mail_get_modseq,
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
	dbox_mail_get_special,
	index_mail_update_flags,
	index_mail_update_keywords,
	index_mail_expunge,
	index_mail_set_cache_corrupted,
	index_mail_get_index_mail
};
