/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "buffer.h"
#include "istream.h"
#include "str.h"
#include "message-address.h"
#include "message-date.h"
#include "message-part-serialize.h"
#include "imap-bodystructure.h"
#include "imap-envelope.h"
#include "mail-index.h"
#include "mail-index-util.h"
#include "mail-custom-flags.h"
#include "mail-cache.h"
#include "index-storage.h"
#include "index-expunge.h"
#include "index-mail.h"

#include <ctype.h>

static struct message_part *get_cached_parts(struct index_mail *mail)
{
	struct message_part *part;
	const void *part_data;
	const char *error;
	size_t part_size;

	if ((mail->data.cached_fields & MAIL_CACHE_MESSAGEPART) == 0) {
		mail_cache_mark_missing(mail->ibox->index->cache,
					MAIL_CACHE_MESSAGEPART);
		return NULL;
	}

	// FIXME: for non-multipart messages we could build it

	if (!mail_cache_lookup_field(mail->ibox->index->cache, mail->data.rec,
				     MAIL_CACHE_MESSAGEPART,
				     &part_data, &part_size)) {
		/* unexpected - must be an error */
		return NULL;
	}

	part = message_part_deserialize(mail->pool, part_data, part_size,
					&error);
	if (part == NULL) {
		mail_cache_set_corrupted(mail->ibox->index->cache,
			"Corrupted cached message_part data (%s)", error);
		return NULL;
	}

	/* we know the NULs now, update them */
	if ((part->flags & MESSAGE_PART_FLAG_HAS_NULS) != 0) {
		mail->mail.has_nuls = TRUE;
		mail->mail.has_no_nuls = FALSE;
	} else {
		mail->mail.has_nuls = FALSE;
		mail->mail.has_no_nuls = TRUE;
	}

	return part;
}

static char *get_cached_string(struct index_mail *mail,
			       enum mail_cache_field field)
{
	const char *ret;

	if ((mail->data.cached_fields & field) == 0) {
		mail_cache_mark_missing(mail->ibox->index->cache, field);
		return NULL;
	}

	ret = mail_cache_lookup_string_field(mail->ibox->index->cache,
					     mail->data.rec, field);
	return p_strdup(mail->pool, ret);
}

static uoff_t get_cached_uoff_t(struct index_mail *mail,
				enum mail_cache_field field)
{
	uoff_t uoff;

	if (!mail_cache_copy_fixed_field(mail->ibox->index->cache,
					 mail->data.rec, field,
					 &uoff, sizeof(uoff))) {
		mail_cache_mark_missing(mail->ibox->index->cache, field);
		uoff = (uoff_t)-1;
	}

	return uoff;
}

static uoff_t get_cached_virtual_size(struct index_mail *mail)
{
	return get_cached_uoff_t(mail, MAIL_CACHE_VIRTUAL_FULL_SIZE);
}

static time_t get_cached_received_date(struct index_mail *mail)
{
	time_t t;

	if (!mail_cache_copy_fixed_field(mail->ibox->index->cache,
					 mail->data.rec,
					 MAIL_CACHE_RECEIVED_DATE,
					 &t, sizeof(t))) {
		mail_cache_mark_missing(mail->ibox->index->cache,
					MAIL_CACHE_RECEIVED_DATE);
		t = (time_t)-1;
	}

	return t;
}

static void get_cached_sent_date(struct index_mail *mail,
				 struct mail_sent_date *sent_date)
{
	if (!mail_cache_copy_fixed_field(mail->ibox->index->cache,
					 mail->data.rec, MAIL_CACHE_SENT_DATE,
					 sent_date, sizeof(*sent_date))) {
		mail_cache_mark_missing(mail->ibox->index->cache,
					MAIL_CACHE_SENT_DATE);

		sent_date->time = (time_t)-1;
		sent_date->timezone = 0;
	}
}

static int index_mail_cache_transaction_begin(struct index_mail *mail)
{
	if (mail->ibox->trans_ctx != NULL)
		return TRUE;

	if (mail_cache_transaction_begin(mail->ibox->index->cache, TRUE,
					 &mail->ibox->trans_ctx) <= 0)
		return FALSE;

	mail->data.cached_fields =
		mail_cache_get_fields(mail->ibox->index->cache,
				      mail->data.rec);
	return TRUE;
}

static int index_mail_cache_can_add(struct index_mail *mail,
				    enum mail_cache_field field)
{
	if ((mail->data.cached_fields & field) != 0)
		return FALSE;

	// FIXME: check if we really want to cache this

	if (!index_mail_cache_transaction_begin(mail))
		return FALSE;

	/* cached_fields may have changed, recheck */
	if ((mail->data.cached_fields & field) != 0)
		return FALSE;

	return TRUE;
}

static void index_mail_cache_add(struct index_mail *mail,
				 enum mail_cache_field field,
				 const void *data, size_t size)
{
	struct index_mailbox *ibox = mail->ibox;

        if (!index_mail_cache_can_add(mail, field))
		return;

	if (!mail_cache_add(ibox->trans_ctx, mail->data.rec,
			    field, data, size))
		mail_cache_transaction_rollback(ibox->trans_ctx);

	mail->data.cached_fields |= field;
}

static int open_stream(struct index_mail *mail, uoff_t position)
{
	struct index_mail_data *data = &mail->data;
	int deleted;

	if (data->stream == NULL) {
		data->stream = mail->ibox->index->
			open_mail(mail->ibox->index, data->rec,
				  &data->received_date, &deleted);
		data->deleted = deleted;

		if (data->stream == NULL)
			return FALSE;

		if (data->received_date != (time_t)-1) {
			index_mail_cache_add(mail, MAIL_CACHE_RECEIVED_DATE,
					     &data->received_date,
					     sizeof(data->received_date));
		}
	}

	i_stream_seek(mail->data.stream, position);
	return TRUE;
}

static int find_wanted_headers(struct mail_cache *cache,
			       const char *const wanted_headers[])
{
	const char *const *headers, *const *tmp, *const *tmp2;
	int i;

	if (wanted_headers == NULL || *wanted_headers == NULL)
		return -1;

	for (i = MAIL_CACHE_HEADERS_COUNT-1; i >= 0; i--) {
		headers = mail_cache_get_header_fields(cache, i);
		if (headers == NULL)
			continue;

		for (tmp = wanted_headers; *tmp != NULL; tmp++) {
			for (tmp2 = headers; *tmp2 != NULL; tmp2++) {
				if (strcasecmp(*tmp2, *tmp) == 0)
					break;
			}

			if (*tmp2 == NULL)
				break;
		}

		if (*tmp == NULL)
			return i;
	}

	return -1;
}

static struct cached_header *
find_cached_header(struct index_mail *mail, const char *name, size_t len)
{
	struct cached_header *hdr;

	for (hdr = mail->data.headers; hdr != NULL; hdr = hdr->next) {
		if (len == hdr->name_len &&
		    memcasecmp(hdr->name, name, len) == 0)
			return hdr;
	}

	return NULL;
}

void index_mail_parse_header(struct message_part *part __attr_unused__,
			     struct message_header_line *hdr, void *context)
{
	struct index_mail *mail = context;
	struct index_mail_data *data = &mail->data;
	struct cached_header *cached_hdr;

	if (data->save_envelope) {
		imap_envelope_parse_header(mail->pool,
					   &data->envelope_data, hdr);

		if (hdr == NULL) {
			/* finalize the envelope */
			string_t *str;

			str = str_new(mail->pool, 256);
			imap_envelope_write_part_data(data->envelope_data, str);
			data->envelope = str_c(str);
		}
	}

	if (hdr == NULL) {
		/* end of headers */
		if (data->save_sent_date) {
			/* not found */
			data->sent_date.time = 0;
			data->sent_date.timezone = 0;
			data->save_sent_date = FALSE;
		}
		if (data->sent_date.time != (time_t)-1) {
			index_mail_cache_add(mail, MAIL_CACHE_SENT_DATE,
					     &data->sent_date,
					     sizeof(data->sent_date));
		}

		/* mark parsed headers as fully saved */
                cached_hdr = data->headers;
		for (; cached_hdr != NULL; cached_hdr = cached_hdr->next) {
			if (cached_hdr->parsing) {
				cached_hdr->parsing = FALSE;
				cached_hdr->fully_saved = TRUE;
			}
		}
		return;
	}

	if (data->save_sent_date && strcasecmp(hdr->name, "Date") == 0) {
		if (hdr->continues) {
			hdr->use_full_value = TRUE;
			return;
		}
		if (!message_date_parse(hdr->full_value, hdr->full_value_len,
					&data->sent_date.time,
					&data->sent_date.timezone)) {
			/* 0 == parse error */
			data->sent_date.time = 0;
			data->sent_date.timezone = 0;
		}
		data->save_sent_date = FALSE;
	}

	cached_hdr = find_cached_header(mail, hdr->name, hdr->name_len);
	if (cached_hdr != NULL && !cached_hdr->fully_saved) {
		if (!hdr->continued) {
			str_append(data->header_data, hdr->name);
			str_append(data->header_data, ": ");
		}
		if (cached_hdr->value_idx == 0)
			cached_hdr->value_idx = str_len(data->header_data);
		str_append_n(data->header_data, hdr->value, hdr->value_len);
		if (!hdr->no_newline)
			str_append(data->header_data, "\n");
	}
}

static struct cached_header *
add_cached_header(struct index_mail *mail, const char *name)
{
	struct cached_header *hdr;

	i_assert(*name != '\0');

	hdr = find_cached_header(mail, name, strlen(name));
	if (hdr != NULL)
		return hdr;

	hdr = p_new(mail->pool, struct cached_header, 1);
	hdr->name = p_strdup(mail->pool, name);
	hdr->name_len = strlen(name);

	hdr->next = mail->data.headers;
	mail->data.headers = hdr;

	return hdr;
}

static const char *const *get_header_names(struct cached_header *hdr)
{
	const char *null = NULL;
	buffer_t *buffer;

	buffer = buffer_create_dynamic(data_stack_pool, 128, (size_t)-1);
	for (; hdr != NULL; hdr = hdr->next)
		buffer_append(buffer, &hdr->name, sizeof(const char *));
	buffer_append(buffer, &null, sizeof(const char *));

	return buffer_get_data(buffer, NULL);
}

static int find_unused_header_idx(struct mail_cache *cache)
{
	int i;

	for (i = 0; i < MAIL_CACHE_HEADERS_COUNT; i++) {
		if (mail_cache_get_header_fields(cache, i) == NULL)
			return i;
	}
	return -1;
}

void index_mail_parse_header_init(struct index_mail *mail,
				  const char *const *headers)
{
	struct cached_header *hdr;
	const char *const *tmp;

	if (mail->data.header_data == NULL)
		mail->data.header_data = str_new(mail->pool, 4096);

	if (headers == NULL) {
		/* parsing all headers */
		for (hdr = mail->data.headers; hdr != NULL; hdr = hdr->next)
			hdr->parsing = TRUE;
	} else {
		for (hdr = mail->data.headers; hdr != NULL; hdr = hdr->next) {
			for (tmp = headers; *tmp != NULL; tmp++) {
				if (strcasecmp(*tmp, hdr->name) == 0)
					hdr->parsing = TRUE;
			}
		}
	}
}

static int parse_header(struct index_mail *mail)
{
	struct mail_cache *cache = mail->ibox->index->cache;
	const char *const *headers, *const *tmp;
	int idx;

	if (!open_stream(mail, 0))
		return FALSE;

	if (mail->data.save_cached_headers) {
		/* we want to save some of the headers. that means we'll have
		   to save all the headers in that group. if we're creating a
		   new group, save all the headers in previous group in it
		   too. */
		idx = mail->data.save_header_idx;
		if (idx < 0) {
			/* can we reuse existing? */
			headers = get_header_names(mail->data.headers);
			idx = find_wanted_headers(cache, headers);
			if (idx >= 0)
				mail->data.save_header_idx = idx;
		}
		if (idx < 0) {
			idx = find_unused_header_idx(cache);
			idx--; /* include all previous headers too */
		}

		headers = idx < 0 ? NULL :
			mail_cache_get_header_fields(cache, idx);

		if (headers != NULL) {
			for (tmp = headers; *tmp != NULL; tmp++)
				add_cached_header(mail, *tmp);
		}
	}

	index_mail_parse_header_init(mail, NULL);
	message_parse_header(NULL, mail->data.stream, &mail->data.hdr_size,
			     index_mail_parse_header, mail);
	mail->data.parse_header = FALSE;
	mail->data.headers_read = TRUE;
	mail->data.hdr_size_set = TRUE;

	return TRUE;
}

static int parse_cached_header(struct index_mail *mail, int idx)
{
	struct istream *istream;
	const char *str, *const *idx_headers;

	idx_headers = mail_cache_get_header_fields(mail->ibox->index->cache,
						   idx);
	i_assert(idx_headers != NULL);

	str = mail_cache_lookup_string_field(mail->ibox->index->cache,
					     mail->data.rec,
					     mail_cache_header_fields[idx]);
	if (str == NULL)
		return FALSE;

	t_push();
	istream = i_stream_create_from_data(data_stack_pool, str, strlen(str));
	index_mail_parse_header_init(mail, idx_headers);
	message_parse_header(NULL, istream, NULL,
			     index_mail_parse_header, mail);

	i_stream_unref(istream);
	t_pop();

	if (idx == mail->data.header_idx)
		mail->data.headers_read = TRUE;
	return TRUE;
}

static const struct mail_full_flags *get_flags(struct mail *_mail)
{
	struct index_mail *mail = (struct index_mail *) _mail;
	struct index_mail_data *data = &mail->data;

	data->flags.flags = data->rec->msg_flags;
	data->flags.custom_flags =
		mail_custom_flags_list_get(mail->ibox->index->custom_flags);
	data->flags.custom_flags_count = MAIL_CUSTOM_FLAGS_COUNT;

	if (data->rec->uid >= mail->ibox->index->first_recent_uid)
		data->flags.flags |= MAIL_RECENT;

	return &data->flags;
}

static const struct message_part *get_parts(struct mail *_mail)
{
	struct index_mail *mail = (struct index_mail *) _mail;
	struct index_mail_data *data = &mail->data;
	buffer_t *buffer;
	const void *buf_data;
	size_t buf_size;

	if (data->parts != NULL)
		return data->parts;

	if ((mail->wanted_fields & MAIL_FETCH_MESSAGE_PARTS) == 0) {
		data->parts = get_cached_parts(mail);
		if (data->parts != NULL)
			return data->parts;
	}

	if (!open_stream(mail, 0))
		return NULL;

	data->parts = message_parse(mail->pool, data->stream,
				    index_mail_parse_header, mail);

	/* we know the NULs now, update them */
	if ((data->parts->flags & MESSAGE_PART_FLAG_HAS_NULS) != 0) {
		_mail->has_nuls = TRUE;
		_mail->has_no_nuls = FALSE;
	} else {
		_mail->has_nuls = FALSE;
		_mail->has_no_nuls = TRUE;
	}

	if (index_mail_cache_can_add(mail, MAIL_CACHE_MESSAGEPART)) {
		t_push();
		buffer = buffer_create_dynamic(data_stack_pool,
					       1024, (size_t)-1);
		message_part_serialize(data->parts, buffer);

		buf_data = buffer_get_data(buffer, &buf_size);
		index_mail_cache_add(mail, MAIL_CACHE_MESSAGEPART,
				     buf_data, buf_size);
		t_pop();
	}
	return data->parts;
}

static time_t get_received_date(struct mail *_mail)
{
	struct index_mail *mail = (struct index_mail *) _mail;
	struct index_mail_data *data = &mail->data;

	if (data->received_date != (time_t)-1)
		return data->received_date;

	if ((mail->wanted_fields & MAIL_FETCH_RECEIVED_DATE) == 0) {
		data->received_date = get_cached_received_date(mail);
		if (data->received_date != (time_t)-1)
			return data->received_date;
	}

	data->received_date = mail->ibox->index->
		get_received_date(mail->ibox->index, mail->data.rec);
	if (data->received_date != (time_t)-1) {
		index_mail_cache_add(mail, MAIL_CACHE_RECEIVED_DATE,
				     &data->received_date,
				     sizeof(data->received_date));
	}
	return data->received_date;
}

static time_t get_date(struct mail *_mail, int *timezone)
{
	static const char *date_headers[] = { "Date", NULL };
	struct index_mail *mail = (struct index_mail *) _mail;
	struct index_mail_data *data = &mail->data;
	int idx;

	if (data->sent_date.time != (time_t)-1) {
		if (timezone != NULL)
			*timezone = data->sent_date.timezone;
		return data->sent_date.time;
	}

	if ((mail->wanted_fields & MAIL_FETCH_DATE) == 0)
		get_cached_sent_date(mail, &data->sent_date);

	if (data->sent_date.time == (time_t)-1) {
		idx = data->parse_header ? -1 :
			find_wanted_headers(mail->ibox->index->cache,
					    date_headers);

		data->save_sent_date = TRUE;
		if (idx >= 0) {
			if (!parse_cached_header(mail, idx))
				idx = -1;
		}
		if (idx < 0)
			parse_header(mail);

		index_mail_cache_add(mail, MAIL_CACHE_SENT_DATE,
				     &data->sent_date, sizeof(data->sent_date));
	}

	if (timezone != NULL)
		*timezone = data->sent_date.timezone;
	return data->sent_date.time;
}

static int get_msgpart_sizes(struct index_mail *mail)
{
	struct index_mail_data *data = &mail->data;

	if ((mail->wanted_fields & MAIL_FETCH_MESSAGE_PARTS) != 0)
		(void)get_parts(&mail->mail);

	if (data->parts == NULL)
		data->parts = get_cached_parts(mail);

	if (data->parts != NULL) {
		data->hdr_size = data->parts->header_size;
		data->body_size = data->parts->body_size;
		data->hdr_size_set = TRUE;
		data->body_size_set = TRUE;
	}

	return data->parts != NULL;
}

static void get_binary_sizes(struct index_mail *mail)
{
	enum mail_index_record_flag index_flags;
	uoff_t size;

	index_flags = mail_cache_get_index_flags(mail->ibox->index->cache,
						 mail->data. rec);

	if (!mail->data.hdr_size_set &&
	    (index_flags & MAIL_INDEX_FLAG_BINARY_HEADER) != 0) {
		size = get_cached_uoff_t(mail, MAIL_CACHE_HEADER_SIZE);
		if (size != (uoff_t)-1) {
			mail->data.hdr_size.physical_size =
				mail->data.hdr_size.virtual_size = size;
			mail->data.hdr_size_set = TRUE;
		}
	}

	if (!mail->data.body_size_set &&
	    (index_flags & MAIL_INDEX_FLAG_BINARY_BODY) != 0) {
		size = get_cached_uoff_t(mail, MAIL_CACHE_BODY_SIZE);
		if (size != (uoff_t)-1) {
			mail->data.body_size.physical_size =
				mail->data.body_size.virtual_size = size;
			mail->data.body_size_set = TRUE;
		}
	}
}

static void index_mail_cache_add_sizes(struct index_mail *mail)
{
	if (mail->data.hdr_size_set) {
		index_mail_cache_add(mail, MAIL_CACHE_HEADER_SIZE,
				     &mail->data.hdr_size.physical_size,
				     sizeof(uoff_t));
	}
	if (mail->data.body_size_set) {
		index_mail_cache_add(mail, MAIL_CACHE_BODY_SIZE,
				     &mail->data.body_size.physical_size,
				     sizeof(uoff_t));
	}
}

static uoff_t get_size(struct mail *_mail)
{
	struct index_mail *mail = (struct index_mail *) _mail;
	struct index_mail_data *data = &mail->data;
	uoff_t hdr_size, body_size, hdr_phys_size;

	if (data->size != (uoff_t)-1)
		return data->size;

	if ((mail->wanted_fields & MAIL_FETCH_SIZE) == 0) {
		data->size = get_cached_virtual_size(mail);
		if (data->size != (uoff_t)-1)
			return data->size;
	}

	if (!get_msgpart_sizes(mail)) {
		if (data->parse_header)
			parse_header(mail);
	}

	hdr_size = data->hdr_size_set ?
		data->hdr_size.virtual_size : (uoff_t)-1;
	body_size = data->body_size_set ?
		data->body_size.virtual_size : (uoff_t)-1;

	if (body_size != (uoff_t)-1 && hdr_size != (uoff_t)-1) {
		data->size = hdr_size + body_size;
		return data->size;
	}

	/* maybe it's binary */
	get_binary_sizes(mail);
	if (data->hdr_size_set && hdr_size == (uoff_t)-1)
		hdr_size = data->hdr_size.virtual_size;
	if (data->body_size_set && body_size == (uoff_t)-1)
		body_size = data->body_size.virtual_size;

	if (body_size != (uoff_t)-1 && hdr_size != (uoff_t)-1) {
		data->size = hdr_size + body_size;
		return data->size;
	}

	/* have to parse, slow.. */
	hdr_phys_size = hdr_size != (uoff_t)-1 && data->hdr_size_set ?
		data->hdr_size.physical_size : (uoff_t)-1;
	if (!open_stream(mail, hdr_phys_size != (uoff_t)-1 ? hdr_phys_size : 0))
		return (uoff_t)-1;

	if (hdr_phys_size == (uoff_t)-1) {
		message_get_header_size(data->stream, &data->hdr_size, NULL);
		hdr_size = data->hdr_size.virtual_size;
		data->hdr_size_set = TRUE;
	}
	if (body_size == (uoff_t)-1) {
		message_get_body_size(data->stream, &data->body_size, NULL);
		body_size = data->body_size.virtual_size;
		data->body_size_set = TRUE;
	}
	data->size = hdr_size + body_size;

	index_mail_cache_add_sizes(mail);
	index_mail_cache_add(mail, MAIL_CACHE_VIRTUAL_FULL_SIZE,
			     &data->size, sizeof(data->size));

	return data->size;
}

static const char *get_header(struct mail *_mail, const char *field)
{
	struct index_mail *mail = (struct index_mail *) _mail;
	struct cached_header *hdr;
	size_t field_len;
	int idx;

	field_len = strlen(field);
	hdr = find_cached_header(mail, field, field_len);
	if (hdr == NULL) {
		/* not wanted initially, add it and check if we can
		   get it from cache */
		const char *headers[2];

		hdr = add_cached_header(mail, field);

		headers[0] = field; headers[1] = NULL;
		idx = find_wanted_headers(mail->ibox->index->cache, headers);
	} else {
		idx = mail->data.header_idx;
	}

	if (!hdr->fully_saved) {
		if (idx >= 0) {
			if (!parse_cached_header(mail, idx))
				idx = -1;
		}
		if (idx < 0) {
			mail->data.save_cached_headers = TRUE;
			parse_header(mail);
		}

		hdr = find_cached_header(mail, field, field_len);
	}

	return hdr->value_idx == 0 ? NULL :
		t_strcut(str_c(mail->data.header_data) + hdr->value_idx, '\n');
}

static struct istream *get_headers(struct mail *_mail,
				   const char *const minimum_fields[])
{
	struct index_mail *mail = (struct index_mail *) _mail;
	struct cached_header *hdr;
	const char *const *tmp, *str;
	int idx, all_exists, all_saved;

	i_assert(*minimum_fields != NULL);

	all_exists = all_saved = TRUE;
	for (tmp = minimum_fields; *tmp != NULL; tmp++) {
		hdr = find_cached_header(mail, *tmp, strlen(*tmp));
		if (hdr == NULL) {
			add_cached_header(mail, *tmp);
			all_exists = FALSE;
		} else if (!hdr->fully_saved)
			all_saved = FALSE;
	}

	if (all_exists) {
		if (all_saved) {
			return i_stream_create_from_data(mail->pool,
					str_data(mail->data.header_data),
					str_len(mail->data.header_data));
		}

		idx = mail->data.header_idx;
	} else {
		idx = find_wanted_headers(mail->ibox->index->cache,
					  get_header_names(mail->data.headers));
	}

	if (idx >= 0) {
		/* everything should be cached */
		str = mail_cache_lookup_string_field(mail->ibox->index->cache,
				mail->data.rec, mail_cache_header_fields[idx]);
		if (str != NULL) {
			return i_stream_create_from_data(mail->pool,
							 str, strlen(str));
		}
	}
	if (idx < 0) {
		mail->data.save_cached_headers = TRUE;
		parse_header(mail);
	}

	return i_stream_create_from_data(mail->pool,
					 str_data(mail->data.header_data),
					 str_len(mail->data.header_data));
}

static const struct message_address *
get_address(struct mail *_mail, const char *field)
{
	struct index_mail *mail = (struct index_mail *) _mail;
	const char *str;

	str = get_header(_mail, field);
	if (str == NULL)
		return NULL;

	return message_address_parse(mail->pool, (const unsigned char *) str,
				     (size_t)-1, 1);
}

static const char *get_first_mailbox(struct mail *_mail, const char *field)
{
	struct index_mail *mail = (struct index_mail *) _mail;
	struct message_address *addr;
	const char *str;

	str = get_header(_mail, field);
	if (str == NULL)
		return NULL;

	addr = message_address_parse(mail->pool, (const unsigned char *) str,
				     (size_t)-1, 1);
	return addr != NULL ? addr->mailbox : NULL;
}

static struct istream *get_stream(struct mail *_mail,
				  struct message_size *hdr_size,
				  struct message_size *body_size)
{
	struct index_mail *mail = (struct index_mail *) _mail;
	struct index_mail_data *data = &mail->data;

	if (!open_stream(mail, 0))
		return NULL;

	if (hdr_size != NULL || body_size != NULL) {
		if (!get_msgpart_sizes(mail))
			get_binary_sizes(mail);
	}

	if (hdr_size != NULL) {
		if (!data->hdr_size_set) {
			message_get_header_size(data->stream, &data->hdr_size,
						NULL);
			data->hdr_size_set = TRUE;
		}

		*hdr_size = data->hdr_size;
	}

	if (body_size != NULL) {
		if (!data->body_size_set) {
			i_stream_seek(data->stream,
				      data->hdr_size.physical_size);

			message_get_body_size(data->stream, &data->body_size,
					      NULL);
			data->body_size_set = TRUE;
		}

		*body_size = data->body_size;
	}

	index_mail_cache_add_sizes(mail);
	i_stream_seek(data->stream, 0);
	return data->stream;
}

static const char *get_special(struct mail *_mail, enum mail_fetch_field field)
{
	struct index_mail *mail = (struct index_mail *) _mail;
	struct index_mail_data *data = &mail->data;
	struct mail_cache *cache = mail->ibox->index->cache;
	enum mail_cache_field cache_field;
	char *str;
	int i, idx;

	switch (field) {
	case MAIL_FETCH_IMAP_BODY:
		if ((data->cached_fields & MAIL_CACHE_BODY) &&
		    data->body == NULL)
			data->body = get_cached_string(mail, MAIL_CACHE_BODY);
		if (data->body != NULL)
			return data->body;
		/* fall through */
	case MAIL_FETCH_IMAP_BODYSTRUCTURE:
		if ((data->cached_fields & MAIL_CACHE_BODYSTRUCTURE) &&
		    data->bodystructure == NULL) {
			data->bodystructure =
				get_cached_string(mail,
						  MAIL_CACHE_BODYSTRUCTURE);
		}

		if (data->bodystructure != NULL) {
			if (field == MAIL_FETCH_IMAP_BODYSTRUCTURE)
				return data->bodystructure;

			/* create BODY from cached BODYSTRUCTURE */
			t_push();
			data->body = p_strdup(mail->pool,
				imap_body_parse_from_bodystructure(
							data->bodystructure));
			t_pop();

			if (data->body == NULL) {
				mail_cache_set_corrupted(cache,
					"Corrupted BODYSTRUCTURE");
			}
			return data->body;
		}

		if (!open_stream(mail, 0))
			return NULL;

		if (data->parts == NULL)
			data->parts = get_cached_parts(mail);

		t_push();
		str = p_strdup(mail->pool, imap_part_get_bodystructure(
				mail->pool, &data->parts, data->stream,
				field == MAIL_FETCH_IMAP_BODYSTRUCTURE));
		t_pop();

		/* should never fail */
		i_assert(str != NULL);

		cache_field = field == MAIL_FETCH_IMAP_BODYSTRUCTURE ?
			MAIL_CACHE_BODYSTRUCTURE : MAIL_CACHE_BODY;
		index_mail_cache_add(mail, cache_field, str, strlen(str)+1);

		if (field == MAIL_FETCH_IMAP_BODYSTRUCTURE)
			data->bodystructure = str;
		else
			data->body = str;
		return str;
	case MAIL_FETCH_IMAP_ENVELOPE:
		if (data->envelope != NULL)
			return data->envelope;

		if (data->parse_header) {
			data->save_envelope = TRUE;
			parse_header(mail);
			return data->envelope;
		}

		if (data->save_envelope) {
			/* it was in wanted_fields, header_idx should be
			   correct */
			idx = data->header_idx;
			i_assert(idx >= 0);
		} else {
			idx = find_wanted_headers(cache, imap_envelope_headers);
		}

		data->save_envelope = TRUE;
		if (idx >= 0) {
			if (!parse_cached_header(mail, idx))
				idx = -1;
		}
		if (idx < 0) {
			for (i = 0; imap_envelope_headers[i] != NULL; i++) {
				add_cached_header(mail,
						  imap_envelope_headers[i]);
			}
			data->save_cached_headers = TRUE;
			parse_header(mail);
		}
		return data->envelope;
	default:
		i_unreached();
		return NULL;
	}
}

static struct mail index_mail = {
	0, 0, 0, 0, 0,

	get_flags,
	get_parts,
	get_received_date,
	get_date,
	get_size,
	get_header,
	get_headers,
	get_address,
	get_first_mailbox,
	get_stream,
	get_special,
	index_storage_update_flags,
	index_storage_copy,
	index_storage_expunge
};

void index_mail_init(struct index_mailbox *ibox, struct index_mail *mail,
		     enum mail_fetch_field wanted_fields,
		     const char *const wanted_headers[])
{
	mail->mail = index_mail;
	mail->mail.box = &ibox->box;

	mail->wanted_headers_idx =
		find_wanted_headers(ibox->index->cache, wanted_headers);

	mail->pool = pool_alloconly_create("index_mail", 16384);
	mail->ibox = ibox;
	mail->wanted_fields = wanted_fields;
	mail->wanted_headers = wanted_headers;
	mail->expunge_counter = ibox->index->expunge_counter;

	if (ibox->mail_init != NULL)
		ibox->mail_init(mail);
}

static void index_mail_close(struct index_mail *mail)
{
	struct index_mail_data *data = &mail->data;
	const char *const *headers;

	if (data->stream != NULL)
		i_stream_unref(data->stream);

	if (!data->save_cached_headers || !data->headers_read)
		return;

	/* save cached headers - FIXME: this breaks if fetch_uid() and
	   fetch/search are both accessing headers from same message.
	   index_mails should probably be shared.. */
	if (!index_mail_cache_transaction_begin(mail))
		return;

	if (data->save_header_idx < 0) {
		data->save_header_idx =
			find_unused_header_idx(mail->ibox->index->cache);
		if (data->save_header_idx < 0)
			return;

                headers = get_header_names(data->headers);
		if (!mail_cache_set_header_fields(mail->ibox->trans_ctx,
						  data->save_header_idx,
						  headers))
			return;
	}

	mail_cache_add(mail->ibox->trans_ctx, data->rec,
		       mail_cache_header_fields[data->save_header_idx],
		       str_c(mail->data.header_data),
		       str_len(mail->data.header_data)+1);
	data->save_cached_headers = FALSE;
}

int index_mail_next(struct index_mail *mail, struct mail_index_record *rec,
		    unsigned int idx_seq, int delay_open)
{
	struct mail_index *index = mail->ibox->index;
	struct index_mail_data *data = &mail->data;
        enum mail_index_record_flag index_flags;
	int i, ret, open_mail, only_wanted_headers;

	i_assert(mail->expunge_counter == index->expunge_counter);

	t_push();

	index_mail_close(mail);
	memset(data, 0, sizeof(*data));
	p_clear(mail->pool);

        data->cached_fields = mail_cache_get_fields(index->cache, rec);
	index_flags = (data->cached_fields & MAIL_CACHE_INDEX_FLAGS) == 0 ? 0 :
		mail_cache_get_index_flags(index->cache, rec);

	mail->mail.has_nuls = (index_flags & MAIL_INDEX_FLAG_HAS_NULS) != 0;
	mail->mail.has_no_nuls =
		(index_flags & MAIL_INDEX_FLAG_HAS_NO_NULS) != 0;

	data->rec = rec;
	data->idx_seq = idx_seq;
	data->size = (uoff_t)-1;
	data->received_date = data->sent_date.time = (time_t)-1;

	/* if some wanted fields are cached, get them */
	if (mail->wanted_fields & MAIL_FETCH_MESSAGE_PARTS)
		data->parts = get_cached_parts(mail);
	if (mail->wanted_fields & MAIL_FETCH_IMAP_BODY)
		data->body = get_cached_string(mail, MAIL_CACHE_BODY);
	if ((mail->wanted_fields & MAIL_FETCH_IMAP_BODYSTRUCTURE) ||
	    ((mail->wanted_fields & MAIL_FETCH_IMAP_BODY) &&
	     data->body == NULL)) {
		data->bodystructure =
			get_cached_string(mail, MAIL_CACHE_BODYSTRUCTURE);
	}
	if (mail->wanted_fields & MAIL_FETCH_SIZE)
		data->size = get_cached_virtual_size(mail);
	if (mail->wanted_fields & MAIL_FETCH_DATE)
		get_cached_sent_date(mail, &data->sent_date);

	/* see if we have to parse the message */
	open_mail = FALSE;
	if ((mail->wanted_fields & MAIL_FETCH_MESSAGE_PARTS) &&
	    data->parts == NULL)
		data->parse_header = TRUE;
	else if ((mail->wanted_fields & MAIL_FETCH_IMAP_BODYSTRUCTURE) &&
		 data->bodystructure == NULL) {
		if (data->parts == NULL)
			data->parts = get_cached_parts(mail);
		open_mail = TRUE;
		data->parse_header = data->parts == NULL;
	} else if ((mail->wanted_fields & MAIL_FETCH_IMAP_BODY) &&
		   data->body == NULL && data->bodystructure == NULL) {
		if (data->parts == NULL)
			data->parts = get_cached_parts(mail);
		open_mail = TRUE;
		data->parse_header = data->parts == NULL;
	} else if (mail->wanted_fields & (MAIL_FETCH_STREAM_HEADER |
					  MAIL_FETCH_STREAM_BODY))
		open_mail = TRUE;

	/* check headers */
	if (mail->wanted_fields & MAIL_FETCH_IMAP_ENVELOPE) {
		for (i = 0; imap_envelope_headers[i] != NULL; i++) 
			add_cached_header(mail, imap_envelope_headers[i]);
	} else if ((mail->wanted_fields & MAIL_FETCH_DATE) &&
		   data->sent_date.time == (time_t)-1)
		add_cached_header(mail, "Date");

	only_wanted_headers = mail->data.headers == NULL;
	if (mail->wanted_headers != NULL) {
		const char *const *tmp;

		for (tmp = mail->wanted_headers; *tmp != NULL; tmp++)
			add_cached_header(mail, *tmp);
	}

	data->save_header_idx = -1;
	if (data->headers != NULL &&
	    (mail->wanted_fields & (MAIL_FETCH_STREAM_HEADER |
				    MAIL_FETCH_STREAM_BODY)) == 0) {
		/* we're not explicitly opening the file, caching the headers
		   could be a good idea if they're not already cached */
		if (only_wanted_headers) {
			/* no extra headers, we already know if it's indexed */
			data->header_idx = mail->wanted_headers_idx;
		} else {
			const char *const *headers;

			headers = get_header_names(data->headers);
			data->header_idx =
				find_wanted_headers(index->cache, headers);
		}
		if (data->header_idx == -1 ||
		    (data->cached_fields &
		     mail_cache_header_fields[data->header_idx]) == 0) {
			data->save_cached_headers = TRUE;
			data->parse_header = TRUE;
			data->save_header_idx = data->header_idx;
		}
	} else {
		data->header_idx = -1;
	}

	if ((open_mail || data->parse_header) && !delay_open) {
		if (!open_stream(mail, 0))
			ret = data->deleted ? 0 : -1;
		else
			ret = 1;
	} else {
		if (mail->wanted_fields & MAIL_FETCH_RECEIVED_DATE) {
			/* check this only after open_mail() */
			data->received_date = get_cached_received_date(mail);
		}
		ret = 1;
	}

	if ((mail->wanted_fields & MAIL_FETCH_DATE) &&
	    data->sent_date.time == (time_t)-1)
		data->save_sent_date = TRUE;

	if (mail->wanted_fields & MAIL_FETCH_IMAP_ENVELOPE)
		data->save_envelope = TRUE;

	t_pop();
	return ret;
}

void index_mail_deinit(struct index_mail *mail)
{
	t_push();
	index_mail_close(mail);
	t_pop();

	pool_unref(mail->pool);
	memset(mail, 0, sizeof(*mail));
}
