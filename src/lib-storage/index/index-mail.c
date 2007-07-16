/* Copyright (C) 2002-2006 Timo Sirainen */

#include "lib.h"
#include "array.h"
#include "buffer.h"
#include "istream.h"
#include "hex-binary.h"
#include "str.h"
#include "message-date.h"
#include "message-part-serialize.h"
#include "message-parser.h"
#include "imap-bodystructure.h"
#include "imap-envelope.h"
#include "mail-cache.h"
#include "index-storage.h"
#include "index-mail.h"

struct mail_cache_field global_cache_fields[MAIL_INDEX_CACHE_FIELD_COUNT] = {
	{ "flags", 0, MAIL_CACHE_FIELD_BITMASK, sizeof(uint32_t), 0 },
	{ "date.sent", 0, MAIL_CACHE_FIELD_FIXED_SIZE,
	  sizeof(struct mail_sent_date), 0 },
	{ "date.received", 0, MAIL_CACHE_FIELD_FIXED_SIZE,
	  sizeof(uint32_t), 0 },
	{ "date.save", 0, MAIL_CACHE_FIELD_FIXED_SIZE,
	  sizeof(uint32_t), 0 },
	{ "size.virtual", 0, MAIL_CACHE_FIELD_FIXED_SIZE,
	  sizeof(uoff_t), 0 },
	{ "size.physical", 0, MAIL_CACHE_FIELD_FIXED_SIZE,
	  sizeof(uoff_t), 0 },
	{ "imap.body", 0, MAIL_CACHE_FIELD_STRING, 0, 0 },
	{ "imap.bodystructure", 0, MAIL_CACHE_FIELD_STRING, 0, 0 },
	{ "imap.envelope", 0, MAIL_CACHE_FIELD_STRING, 0, 0 },
	{ "mime.parts", 0, MAIL_CACHE_FIELD_VARIABLE_SIZE, 0, 0 }
};

static void index_mail_parse_body(struct index_mail *mail,
				  enum index_cache_field field);

static bool get_cached_parts(struct index_mail *mail)
{
	struct mail_cache_field *cache_fields = mail->ibox->cache_fields;
	struct message_part *part;
	buffer_t *part_buf;
	const char *error;

	t_push();
	part_buf = buffer_create_dynamic(pool_datastack_create(), 128);
	if (mail_cache_lookup_field(mail->trans->cache_view, part_buf,
			mail->data.seq,
			cache_fields[MAIL_CACHE_MESSAGE_PARTS].idx) <= 0) {
		t_pop();
		return FALSE;
	}

	part = message_part_deserialize(mail->data_pool,
					part_buf->data, part_buf->used, &error);
	t_pop();

	if (part == NULL) {
		mail_cache_set_corrupted(mail->ibox->cache,
			"Corrupted cached message_part data (%s)", error);
		return FALSE;
	}

	/* we know the NULs now, update them */
	if ((part->flags & MESSAGE_PART_FLAG_HAS_NULS) != 0) {
		mail->mail.mail.has_nuls = TRUE;
		mail->mail.mail.has_no_nuls = FALSE;
	} else {
		mail->mail.mail.has_nuls = FALSE;
		mail->mail.mail.has_no_nuls = TRUE;
	}

	mail->data.parts = part;
	return TRUE;
}

static bool index_mail_get_fixed_field(struct index_mail *mail,
				       enum index_cache_field field,
				       void *data, size_t data_size)
{
	buffer_t *buf;
	int ret;

	t_push();
	buf = buffer_create_data(pool_datastack_create(), data, data_size);
	if (mail_cache_lookup_field(mail->trans->cache_view, buf,
				    mail->data.seq,
				    mail->ibox->cache_fields[field].idx) <= 0) {
		ret = FALSE;
	} else {
		i_assert(buf->used == data_size);
		ret = TRUE;
	}
	t_pop();

	return ret;
}

uoff_t index_mail_get_cached_uoff_t(struct index_mail *mail,
				    enum index_cache_field field)
{
	uoff_t uoff;

	if (!index_mail_get_fixed_field(mail,
					mail->ibox->cache_fields[field].idx,
					&uoff, sizeof(uoff)))
		uoff = (uoff_t)-1;

	return uoff;
}

enum mail_flags index_mail_get_flags(struct mail *_mail)
{
	struct index_mail *mail = (struct index_mail *) _mail;
	struct index_mail_data *data = &mail->data;

	data->flags = data->rec->flags & MAIL_FLAGS_NONRECENT;
	if (index_mailbox_is_recent(mail->ibox, data->seq))
		data->flags |= MAIL_RECENT;

	return data->flags;
}

const char *const *index_mail_get_keywords(struct mail *_mail)
{
	static const char *const no_keywords[] = { NULL };
	struct index_mail *mail = (struct index_mail *) _mail;
	struct index_mail_data *data = &mail->data;
	ARRAY_TYPE(keyword_indexes) keyword_indexes_arr;
	const char *const *names;
	const unsigned int *keyword_indexes;
	unsigned int i, count, names_count;

	if (array_is_created(&data->keywords))
		return array_idx(&data->keywords, 0);

	t_push();
	t_array_init(&keyword_indexes_arr, 128);
	if (mail_index_lookup_keywords(mail->ibox->view, mail->data.seq,
				       &keyword_indexes_arr) < 0) {
		mail_storage_set_index_error(mail->ibox);
		t_pop();
		return NULL;
	}

	keyword_indexes = array_get(&keyword_indexes_arr, &count);
	if (count == 0) {
		t_pop();
		return no_keywords;
	}

	names = array_get(mail->ibox->keyword_names, &names_count);
	p_array_init(&data->keywords, mail->data_pool, count);
	for (i = 0; i < count; i++) {
		const char *name;
		i_assert(keyword_indexes[i] < names_count);

		name = names[keyword_indexes[i]];
		array_append(&data->keywords, &name, 1);
	}

	/* end with NULL */
	(void)array_append_space(&data->keywords);

	t_pop();
	return array_idx(&data->keywords, 0);
}

const struct message_part *index_mail_get_parts(struct mail *_mail)
{
	struct index_mail *mail = (struct index_mail *) _mail;
	struct index_mail_data *data = &mail->data;

	if (data->parts != NULL)
		return data->parts;

	if (get_cached_parts(mail))
		return data->parts;

	if (data->parser_ctx == NULL) {
		if (index_mail_parse_headers(mail, NULL) < 0)
			return NULL;
	}

	data->save_message_parts = TRUE;
	index_mail_parse_body(mail, 0);

	return data->parts;
}

time_t index_mail_get_received_date(struct mail *_mail)
{
	struct index_mail *mail = (struct index_mail *) _mail;
	struct index_mail_data *data = &mail->data;

	if (data->received_date == (time_t)-1) {
		uint32_t t;

		if (!index_mail_get_fixed_field(mail, MAIL_CACHE_RECEIVED_DATE,
						&t, sizeof(t)))
			return (time_t)-1;

		data->received_date = t;
	}

	return data->received_date;
}

time_t index_mail_get_save_date(struct mail *_mail)
{
	struct index_mail *mail = (struct index_mail *) _mail;
	struct index_mail_data *data = &mail->data;

	if (data->save_date == (time_t)-1) {
		uint32_t t;

		if (!index_mail_get_fixed_field(mail, MAIL_CACHE_SAVE_DATE,
						&t, sizeof(t)))
			return (time_t)-1;

		data->save_date = t;
	}

	return data->save_date;
}

time_t index_mail_get_date(struct mail *_mail, int *timezone)
{
	struct index_mail *mail = (struct index_mail *) _mail;
	struct index_mail_data *data = &mail->data;
	const char *str;

	if (data->sent_date.time != (uint32_t)-1) {
		if (timezone != NULL)
			*timezone = data->sent_date.timezone;
		return data->sent_date.time;
	}

	(void)index_mail_get_fixed_field(mail, MAIL_CACHE_SENT_DATE,
					 &data->sent_date,
					 sizeof(data->sent_date));

	if (data->sent_date.time == (uint32_t)-1) {
		time_t t;
		int tz;

		str = mail_get_first_header(_mail, "Date");
		if (str == NULL ||
		    !message_date_parse((const unsigned char *)str,
					strlen(str), &t, &tz)) {
			/* 0 = not found / invalid */
			t = 0;
			tz = 0;
		}
		data->sent_date.time = t;
		data->sent_date.timezone = tz;
		index_mail_cache_add(mail, MAIL_CACHE_SENT_DATE,
				     &data->sent_date, sizeof(data->sent_date));
	}

	if (timezone != NULL)
		*timezone = data->sent_date.timezone;
	return data->sent_date.time;
}

static bool get_cached_msgpart_sizes(struct index_mail *mail)
{
	struct index_mail_data *data = &mail->data;

	if (data->parts == NULL)
		get_cached_parts(mail);

	if (data->parts != NULL) {
		data->hdr_size_set = TRUE;
		data->hdr_size = data->parts->header_size;
		data->body_size = data->parts->body_size;
		data->body_size_set = TRUE;
		data->virtual_size = data->parts->header_size.virtual_size +
			data->body_size.virtual_size;
		data->physical_size = data->parts->header_size.physical_size +
			data->body_size.physical_size;
	}

	return data->parts != NULL;
}

uoff_t index_mail_get_cached_virtual_size(struct index_mail *mail)
{
	uoff_t size;

	if (mail->data.virtual_size != (uoff_t)-1)
		return mail->data.virtual_size;

	size = index_mail_get_cached_uoff_t(mail, MAIL_CACHE_VIRTUAL_FULL_SIZE);
	if (size != (uoff_t)-1)
		mail->data.virtual_size = size;
	else
		(void)get_cached_msgpart_sizes(mail);
	return mail->data.virtual_size;
}

uoff_t index_mail_get_virtual_size(struct mail *_mail)
{
	struct index_mail *mail = (struct index_mail *) _mail;
	struct index_mail_data *data = &mail->data;
	struct message_size hdr_size, body_size;
	uoff_t old_offset;

	if (index_mail_get_cached_virtual_size(mail) != (uoff_t)-1)
		return data->virtual_size;

	old_offset = data->stream == NULL ? 0 : data->stream->v_offset;
	if (mail_get_stream(_mail, &hdr_size, &body_size) == NULL)
		return (uoff_t)-1;
	i_stream_seek(data->stream, old_offset);

	i_assert(data->virtual_size != (uoff_t)-1);
	index_mail_cache_add(mail, MAIL_CACHE_VIRTUAL_FULL_SIZE,
			     &data->virtual_size, sizeof(data->virtual_size));
	return data->virtual_size;
}

uoff_t index_mail_get_physical_size(struct mail *_mail)
{
	struct index_mail *mail = (struct index_mail *) _mail;
	struct index_mail_data *data = &mail->data;
	uoff_t size;

	if (data->physical_size != (uoff_t)-1)
		return data->physical_size;

	size = index_mail_get_cached_uoff_t(mail,
					    MAIL_CACHE_PHYSICAL_FULL_SIZE);
	if (size != (uoff_t)-1)
		data->physical_size = size;
	else
		(void)get_cached_msgpart_sizes(mail);
	return data->physical_size;
}

void index_mail_cache_add(struct index_mail *mail, enum index_cache_field field,
			  const void *data, size_t data_size)
{
	index_mail_cache_add_idx(mail, mail->ibox->cache_fields[field].idx,
				 data, data_size);
}

void index_mail_cache_add_idx(struct index_mail *mail, unsigned int field_idx,
			      const void *data, size_t data_size)
{
	const struct mail_index_header *hdr;

	if (mail->ibox->mail_cache_min_mail_count > 0) {
		/* First check if we've configured caching not to be used with
		   low enough message count. */
		hdr = mail_index_get_header(mail->ibox->view);
		if (hdr->messages_count < mail->ibox->mail_cache_min_mail_count)
			return;
	}

	mail_cache_add(mail->trans->cache_trans, mail->data.seq,
		       field_idx, data, data_size);
}

static void parse_bodystructure_part_header(struct message_part *part,
					    struct message_header_line *hdr,
					    pool_t pool)
{
	imap_bodystructure_parse_header(pool, part, hdr);
}

static bool want_plain_bodystructure_cached(struct index_mail *mail)
{
	if ((mail->wanted_fields & (MAIL_FETCH_IMAP_BODY |
				    MAIL_FETCH_IMAP_BODYSTRUCTURE)) != 0)
		return TRUE;

	if (mail_cache_field_want_add(mail->trans->cache_trans, mail->data.seq,
		mail->ibox->cache_fields[MAIL_CACHE_IMAP_BODY].idx))
		return TRUE;
	if (mail_cache_field_want_add(mail->trans->cache_trans, mail->data.seq,
		mail->ibox->cache_fields[MAIL_CACHE_IMAP_BODYSTRUCTURE].idx))
		return TRUE;
	return FALSE;
}

static void index_mail_body_parsed_cache_flags(struct index_mail *mail)
{
	struct index_mail_data *data = &mail->data;
	unsigned int cache_flags_idx;
	uint32_t cache_flags = data->cache_flags;
	bool want_cached;

	cache_flags_idx = mail->ibox->cache_fields[MAIL_CACHE_FLAGS].idx;
	want_cached = mail_cache_field_want_add(mail->trans->cache_trans,
						data->seq, cache_flags_idx);

	if (data->parsed_bodystructure &&
	    imap_bodystructure_is_plain_7bit(data->parts) &&
	    (want_cached || want_plain_bodystructure_cached(mail))) {
		cache_flags |= MAIL_CACHE_FLAG_TEXT_PLAIN_7BIT_ASCII;
		/* we need message_parts cached to be able to
		   actually use it in BODY/BODYSTRUCTURE reply */
		want_cached = TRUE;
		data->save_message_parts = TRUE;
	}

	/* cache flags should never get unset as long as the message doesn't
	   change, but try to handle it anyway */
	cache_flags &= ~(MAIL_CACHE_FLAG_BINARY_HEADER |
			 MAIL_CACHE_FLAG_BINARY_BODY |
			 MAIL_CACHE_FLAG_HAS_NULS |
			 MAIL_CACHE_FLAG_HAS_NO_NULS);
	if ((data->parts->flags & MESSAGE_PART_FLAG_HAS_NULS) != 0) {
		mail->mail.mail.has_nuls = TRUE;
		mail->mail.mail.has_no_nuls = FALSE;
		cache_flags |= MAIL_CACHE_FLAG_HAS_NULS;
	} else {
		mail->mail.mail.has_nuls = FALSE;
		mail->mail.mail.has_no_nuls = TRUE;
		cache_flags |= MAIL_CACHE_FLAG_HAS_NO_NULS;
	}

	if (data->hdr_size.virtual_size == data->hdr_size.physical_size)
		cache_flags |= MAIL_CACHE_FLAG_BINARY_HEADER;
	if (data->body_size.virtual_size == data->body_size.physical_size)
		cache_flags |= MAIL_CACHE_FLAG_BINARY_BODY;

	if (cache_flags != data->cache_flags && want_cached) {
		index_mail_cache_add_idx(mail, cache_flags_idx,
					 &cache_flags, sizeof(cache_flags));
	}
	data->cache_flags = cache_flags;
}

static void index_mail_body_parsed_cache_message_parts(struct index_mail *mail)
{
	struct index_mail_data *data = &mail->data;
	unsigned int cache_field =
		mail->ibox->cache_fields[MAIL_CACHE_MESSAGE_PARTS].idx;
	enum mail_cache_decision_type decision;
	buffer_t *buffer;

	if (data->messageparts_saved_to_cache ||
	    mail_cache_field_exists(mail->trans->cache_view, mail->data.seq,
				    cache_field) != 0) {
		/* already cached */
		return;
	}

	decision = mail_cache_field_get_decision(mail->ibox->cache,
						 cache_field);
	if (decision == (MAIL_CACHE_DECISION_NO | MAIL_CACHE_DECISION_FORCED)) {
		/* we never want it cached */
		return;
	}
	if (decision == MAIL_CACHE_DECISION_NO &&
	    !data->save_message_parts &&
	    (mail->wanted_fields & MAIL_FETCH_MESSAGE_PARTS) == 0) {
		/* we didn't really care about the message parts themselves,
		   just wanted to use something that depended on it */
		return;
	}

	t_push();
	buffer = buffer_create_dynamic(pool_datastack_create(), 1024);
	message_part_serialize(mail->data.parts, buffer);
	index_mail_cache_add(mail, MAIL_CACHE_MESSAGE_PARTS,
			     buffer->data, buffer->used);
	t_pop();

	data->messageparts_saved_to_cache = TRUE;
}

static void
index_mail_body_parsed_cache_bodystructure(struct index_mail *mail,
					   enum index_cache_field field)
{
	struct index_mail_data *data = &mail->data;
	unsigned int cache_field_parts =
		mail->ibox->cache_fields[MAIL_CACHE_MESSAGE_PARTS].idx;
	unsigned int cache_field_body =
		mail->ibox->cache_fields[MAIL_CACHE_IMAP_BODY].idx;
	unsigned int cache_field_bodystructure =
		mail->ibox->cache_fields[MAIL_CACHE_IMAP_BODYSTRUCTURE].idx;
	enum mail_cache_decision_type dec;
	string_t *str;
	bool bodystructure_cached = FALSE;
	bool plain_bodystructure = FALSE;
	bool cache_bodystructure, cache_body;

	if ((data->cache_flags & MAIL_CACHE_FLAG_TEXT_PLAIN_7BIT_ASCII) != 0) {
		if (data->messageparts_saved_to_cache ||
		    mail_cache_field_exists(mail->trans->cache_view, data->seq,
					    cache_field_parts) > 0) {
			/* cached it as flag + message_parts */
			plain_bodystructure = TRUE;
		}
	}

	/* If BODY is fetched first but BODYSTRUCTURE is also wanted, we don't
	   normally want to first cache BODY and then BODYSTRUCTURE. So check
	   the wanted_fields also in here. */
	if (plain_bodystructure)
		cache_bodystructure = FALSE;
	else if (field == MAIL_CACHE_IMAP_BODYSTRUCTURE ||
		 (mail->wanted_fields & MAIL_FETCH_IMAP_BODYSTRUCTURE) != 0) {
		cache_bodystructure =
			mail_cache_field_can_add(mail->trans->cache_trans,
				data->seq, cache_field_bodystructure);
	} else {
		cache_bodystructure =
			mail_cache_field_want_add(mail->trans->cache_trans,
				data->seq, cache_field_bodystructure);
	}
	if (field == MAIL_CACHE_IMAP_BODYSTRUCTURE || cache_bodystructure) {
		str = str_new(mail->data_pool, 128);
		imap_bodystructure_write(data->parts, str, TRUE);
		data->bodystructure = str_c(str);

		if (cache_bodystructure) {
			index_mail_cache_add(mail,
					     MAIL_CACHE_IMAP_BODYSTRUCTURE,
					     str_c(str), str_len(str)+1);
			bodystructure_cached = TRUE;
		}
	} else {
		bodystructure_cached =
			mail_cache_field_exists(mail->trans->cache_view,
				data->seq, cache_field_bodystructure) > 0;
	}

	/* normally don't cache both BODY and BODYSTRUCTURE, but do it
	   if BODY is forced to be cached */
	dec = mail_cache_field_get_decision(mail->ibox->cache,
					    cache_field_body);
	if (plain_bodystructure ||
	    (bodystructure_cached &&
	     (dec != (MAIL_CACHE_DECISION_FORCED | MAIL_CACHE_DECISION_YES))))
		cache_body = FALSE;
	else if (field == MAIL_CACHE_IMAP_BODY) {
		cache_body =
			mail_cache_field_can_add(mail->trans->cache_trans,
				data->seq, cache_field_body);
	} else {
		cache_body =
			mail_cache_field_want_add(mail->trans->cache_trans,
				data->seq, cache_field_body);
	}

	if (field == MAIL_CACHE_IMAP_BODY || cache_body) {
		str = str_new(mail->data_pool, 128);
		imap_bodystructure_write(data->parts, str, FALSE);
		data->body = str_c(str);

		if (cache_body) {
			index_mail_cache_add(mail, MAIL_CACHE_IMAP_BODY,
					     str_c(str), str_len(str)+1);
		}
	}
}

static void
index_mail_body_parsed_cache_virtual_size(struct index_mail *mail)
{
	unsigned int cache_field =
		mail->ibox->cache_fields[MAIL_CACHE_VIRTUAL_FULL_SIZE].idx;

	if (mail_cache_field_want_add(mail->trans->cache_trans,
				      mail->data.seq, cache_field)) {
		index_mail_cache_add(mail, MAIL_CACHE_VIRTUAL_FULL_SIZE,
				     &mail->data.virtual_size,
				     sizeof(mail->data.virtual_size));
	}
}

static void index_mail_parse_body_finish(struct index_mail *mail,
					 enum index_cache_field field,
					 bool appended_mail)
{
	mail->data.parts = message_parser_deinit(&mail->data.parser_ctx);

	if (appended_mail) {
		bool use_crlf = (mail->ibox->box.storage->flags &
				 MAIL_STORAGE_FLAG_SAVE_CRLF) != 0;
		message_parser_set_crlfs(mail->data.parts, use_crlf);
	}

	(void)get_cached_msgpart_sizes(mail);

	index_mail_body_parsed_cache_flags(mail);
	index_mail_body_parsed_cache_message_parts(mail);
	index_mail_body_parsed_cache_bodystructure(mail, field);
	index_mail_body_parsed_cache_virtual_size(mail);
}

static void index_mail_parse_body(struct index_mail *mail,
				  enum index_cache_field field)
{
	struct index_mail_data *data = &mail->data;
	uoff_t old_offset;

	i_assert(data->parser_ctx != NULL);

	old_offset = data->stream->v_offset;
	i_stream_seek(data->stream, data->hdr_size.physical_size);

	if (data->save_bodystructure_body) {
		/* bodystructure header is parsed, we want the body's mime
		   headers too */
		i_assert(!data->save_bodystructure_header);
		message_parser_parse_body(data->parser_ctx,
					  parse_bodystructure_part_header,
					  mail->data_pool);
		data->save_bodystructure_body = FALSE;
		data->parsed_bodystructure = TRUE;
	} else {
		message_parser_parse_body(data->parser_ctx,
			null_message_part_header_callback, NULL);
	}
	index_mail_parse_body_finish(mail, field, FALSE);

	i_stream_seek(data->stream, old_offset);
}

struct istream *index_mail_init_stream(struct index_mail *_mail,
				       struct message_size *hdr_size,
				       struct message_size *body_size)
{
	struct index_mail *mail = (struct index_mail *) _mail;
	struct index_mail_data *data = &mail->data;

	if (hdr_size != NULL || body_size != NULL)
		(void)get_cached_msgpart_sizes(mail);

	if (hdr_size != NULL || body_size != NULL) {
		i_stream_seek(data->stream, 0);
		if (!data->hdr_size_set) {
			if ((data->access_part & PARSE_HDR) != 0) {
				(void)get_cached_parts(mail);
				if (index_mail_parse_headers(mail, NULL) < 0)
					return NULL;
			} else {
				message_get_header_size(data->stream,
							&data->hdr_size, NULL);
				data->hdr_size_set = TRUE;
			}
		}

		if (hdr_size != NULL)
			*hdr_size = data->hdr_size;
	}

	if (body_size != NULL) {
		i_stream_seek(data->stream, data->hdr_size.physical_size);
		if (!data->body_size_set) {
			if ((data->access_part & PARSE_BODY) != 0)
				index_mail_parse_body(mail, 0);
			else {
				message_get_body_size(data->stream,
						      &data->body_size, NULL);
				data->body_size_set = TRUE;
			}
		}

		*body_size = data->body_size;
	}

	if (data->hdr_size_set && data->body_size_set) {
		data->virtual_size = data->hdr_size.virtual_size +
			data->body_size.virtual_size;
		data->physical_size = data->hdr_size.physical_size +
			data->body_size.physical_size;
	}

	i_stream_seek(data->stream, 0);
	return data->stream;
}

static void index_mail_parse_bodystructure(struct index_mail *mail,
					   enum index_cache_field field)
{
	struct index_mail_data *data = &mail->data;

	if (data->parsed_bodystructure) {
		/* we have everything parsed already, but just not written to
		   a string */
		index_mail_body_parsed_cache_bodystructure(mail, field);
		return;
	}

	if (data->save_bodystructure_header ||
	    !data->save_bodystructure_body) {
		/* we haven't parsed the header yet */
		data->save_bodystructure_header = TRUE;
		data->save_bodystructure_body = TRUE;
		(void)get_cached_parts(mail);
		if (index_mail_parse_headers(mail, NULL) < 0)
			return;
	}

	index_mail_parse_body(mail, field);
}

static void
index_mail_get_plain_bodystructure(struct index_mail *mail, string_t *str,
				   bool extended)
{
	str_printfa(str, IMAP_BODY_PLAIN_7BIT_ASCII" %"PRIuUOFF_T" %u",
		    mail->data.parts->body_size.virtual_size,
		    mail->data.parts->body_size.lines);
	if (extended)
		str_append(str, " NIL NIL NIL");
}

const char *index_mail_get_special(struct mail *_mail,
				   enum mail_fetch_field field)
{
	struct index_mail *mail = (struct index_mail *) _mail;
	struct index_mail_data *data = &mail->data;
	struct mail_cache_field *cache_fields = mail->ibox->cache_fields;
	string_t *str;
	const void *ext_data;

	switch (field) {
	case MAIL_FETCH_IMAP_BODY: {
		unsigned int body_cache_field =
                        cache_fields[MAIL_CACHE_IMAP_BODY].idx;
		unsigned int bodystructure_cache_field =
                        cache_fields[MAIL_CACHE_IMAP_BODYSTRUCTURE].idx;
		if (data->body != NULL)
			return data->body;

		/* 1) use plain-7bit-ascii flag if it exists
		   2) get BODY if it exists
		   3) get it using BODYSTRUCTURE if it exists
		   4) parse body structure, and save BODY/BODYSTRUCTURE
		      depending on what we want cached */

		str = str_new(mail->data_pool, 128);
		if ((mail->data.cache_flags &
		     MAIL_CACHE_FLAG_TEXT_PLAIN_7BIT_ASCII) != 0 &&
		    get_cached_parts(mail)) {
			index_mail_get_plain_bodystructure(mail, str, FALSE);
			return str_c(str);
		}

		if (mail_cache_lookup_field(mail->trans->cache_view, str,
				mail->data.seq, body_cache_field) > 0) {
			data->body = str_c(str);
			return data->body;
		}
		if (mail_cache_lookup_field(mail->trans->cache_view, str,
					    mail->data.seq,
					    bodystructure_cache_field) > 0) {
			data->bodystructure =
				p_strdup(mail->data_pool, str_c(str));
			str_truncate(str, 0);

			if (imap_body_parse_from_bodystructure(
						data->bodystructure, str)) {
				data->body = str_c(str);
				return data->body;
			}

			/* broken, continue.. */
			mail_cache_set_corrupted(mail->ibox->cache,
				"Corrupted BODYSTRUCTURE for mail %u",
				mail->mail.mail.uid);
			data->bodystructure = NULL;
		}
		str_free(&str);

		index_mail_parse_bodystructure(mail, MAIL_CACHE_IMAP_BODY);
		return data->body;
	}
	case MAIL_FETCH_IMAP_BODYSTRUCTURE: {
		unsigned int bodystructure_cache_field =
                        cache_fields[MAIL_CACHE_IMAP_BODYSTRUCTURE].idx;

		if (data->bodystructure != NULL)
			return data->bodystructure;

		str = str_new(mail->data_pool, 128);
		if ((mail->data.cache_flags &
		     MAIL_CACHE_FLAG_TEXT_PLAIN_7BIT_ASCII) != 0 &&
		    get_cached_parts(mail)) {
			index_mail_get_plain_bodystructure(mail, str, TRUE);
			return str_c(str);
		}

		if (mail_cache_lookup_field(mail->trans->cache_view, str,
					    mail->data.seq,
					    bodystructure_cache_field) > 0) {
			data->bodystructure = str_c(str);
			return data->bodystructure;
		}
		str_free(&str);

		index_mail_parse_bodystructure(mail,
					       MAIL_CACHE_IMAP_BODYSTRUCTURE);
		return data->bodystructure;
	}
	case MAIL_FETCH_IMAP_ENVELOPE:
		if (data->envelope == NULL)
			index_mail_headers_get_envelope(mail);
		return data->envelope;
	case MAIL_FETCH_FROM_ENVELOPE:
	case MAIL_FETCH_UIDL_FILE_NAME:
		return NULL;
	case MAIL_FETCH_HEADER_MD5:
		if (mail_index_lookup_ext(mail->trans->trans_view, data->seq,
					  mail->ibox->md5hdr_ext_idx,
					  &ext_data) < 0) {
			mail_storage_set_index_error(mail->ibox);
			return NULL;
		}
		if (ext_data == NULL)
			return NULL;
		return binary_to_hex(ext_data, 16);
	default:
		i_unreached();
		return NULL;
	}
}

struct mail *
index_mail_alloc(struct mailbox_transaction_context *_t,
		 enum mail_fetch_field wanted_fields,
		 struct mailbox_header_lookup_ctx *_wanted_headers)
{
	struct index_transaction_context *t =
		(struct index_transaction_context *)_t;
	struct index_header_lookup_ctx *wanted_headers =
		(struct index_header_lookup_ctx *)_wanted_headers;
	struct index_mail *mail;
	const struct mail_index_header *hdr;
	pool_t pool;

	pool = pool_alloconly_create("mail", 1024);
	mail = p_new(pool, struct index_mail, 1);
	mail->mail.pool = pool;
	array_create(&mail->mail.module_contexts, pool, sizeof(void *), 5);

	mail->mail.v = *t->ibox->mail_vfuncs;
	mail->mail.mail.box = &t->ibox->box;
	mail->mail.mail.transaction = &t->mailbox_ctx;

	hdr = mail_index_get_header(t->ibox->view);
	mail->uid_validity = hdr->uid_validity;

	mail->data_pool = pool_alloconly_create("index_mail", 16384);
	mail->ibox = t->ibox;
	mail->trans = t;
	mail->wanted_fields = wanted_fields;
	mail->wanted_headers = wanted_headers;

	return &mail->mail.mail;
}

static void index_mail_close(struct index_mail *mail)
{
	if (mail->data.parser_ctx != NULL)
		(void)message_parser_deinit(&mail->data.parser_ctx);
	if (mail->data.stream != NULL)
		i_stream_destroy(&mail->data.stream);
	if (mail->data.filter_stream != NULL)
		i_stream_destroy(&mail->data.filter_stream);
}

static void index_mail_reset(struct index_mail *mail)
{
	struct index_mail_data *data = &mail->data;

	index_mail_close(mail);

	memset(data, 0, sizeof(*data));
	p_clear(mail->data_pool);

	data->virtual_size = (uoff_t)-1;
	data->physical_size = (uoff_t)-1;
	data->save_date = (time_t)-1;
	data->received_date = (time_t)-1;
	data->sent_date.time = (uint32_t)-1;
}

static void check_envelope(struct index_mail *mail)
{
	unsigned int cache_field_envelope =
		mail->ibox->cache_fields[MAIL_CACHE_IMAP_ENVELOPE].idx;
	unsigned int cache_field_hdr;

	if ((mail->data.access_part & PARSE_HDR) != 0) {
		mail->data.save_envelope = TRUE;
		return;
	}

	/* if "imap.envelope" is cached, that's all we need */
	if (mail_cache_field_exists(mail->trans->cache_view,
				    mail->mail.mail.seq,
				    cache_field_envelope) > 0)
		return;

	/* don't waste time doing full checks for all required
	   headers. assume that if we have "hdr.message-id" cached,
	   we don't need to parse the header. */
	cache_field_hdr = mail_cache_register_lookup(mail->ibox->cache,
						     "hdr.message-id");
	if (cache_field_hdr == (unsigned int)-1 ||
	    mail_cache_field_exists(mail->trans->cache_view,
				    mail->mail.mail.seq,
				    cache_field_hdr) <= 0)
		mail->data.access_part |= PARSE_HDR;
	mail->data.save_envelope = TRUE;
}

int index_mail_set_seq(struct mail *_mail, uint32_t seq)
{
	struct index_mail *mail = (struct index_mail *)_mail;
	struct index_mail_data *data = &mail->data;
	struct mail_cache_field *cache_fields = mail->ibox->cache_fields;
        struct mail_cache_view *cache_view = mail->trans->cache_view;
	const struct mail_index_record *rec;

	if (data->seq == seq)
		return 0;

	if (mail_index_lookup(mail->trans->trans_view, seq, &rec) < 0) {
		mail_storage_set_index_error(mail->ibox);
		return -1;
	}

	index_mail_reset(mail);

	data->rec = rec;
	data->seq = seq;

	if ((mail->wanted_fields & (MAIL_FETCH_NUL_STATE |
				    MAIL_FETCH_IMAP_BODY |
				    MAIL_FETCH_IMAP_BODYSTRUCTURE)) != 0) {
		(void)index_mail_get_fixed_field(mail, MAIL_CACHE_FLAGS,
						 &data->cache_flags,
						 sizeof(data->cache_flags));
	}

	/* set public fields */
	mail->mail.mail.seq = seq;
	mail->mail.mail.uid = rec->uid;
	mail->mail.mail.has_nuls =
		(data->cache_flags & MAIL_CACHE_FLAG_HAS_NULS) != 0;
	mail->mail.mail.has_no_nuls =
		(data->cache_flags & MAIL_CACHE_FLAG_HAS_NO_NULS) != 0;

	/* see if wanted_fields can tell us if we need to read/parse
	   header/body */
	if ((mail->wanted_fields & MAIL_FETCH_MESSAGE_PARTS) != 0) {
		unsigned int cache_field =
			cache_fields[MAIL_CACHE_MESSAGE_PARTS].idx;

		if (mail_cache_field_exists(cache_view, seq,
					    cache_field) <= 0) {
			data->access_part |= PARSE_HDR | PARSE_BODY;
			data->save_message_parts = TRUE;
		}
	}

	if ((mail->wanted_fields & MAIL_FETCH_VIRTUAL_SIZE) != 0) {
		unsigned int cache_field =
			cache_fields[MAIL_CACHE_VIRTUAL_FULL_SIZE].idx;

		if (mail_cache_field_exists(cache_view, seq, cache_field) <= 0)
			data->access_part |= READ_HDR | READ_BODY;
	}

	if ((mail->wanted_fields & MAIL_FETCH_IMAP_ENVELOPE) != 0)
		check_envelope(mail);

	if ((mail->wanted_fields & MAIL_FETCH_IMAP_BODY) != 0 &&
	    (data->cache_flags & MAIL_CACHE_FLAG_TEXT_PLAIN_7BIT_ASCII) == 0) {
		/* we need either imap.body or imap.bodystructure */
		unsigned int cache_field1 =
			cache_fields[MAIL_CACHE_IMAP_BODY].idx;
		unsigned int cache_field2 =
			cache_fields[MAIL_CACHE_IMAP_BODYSTRUCTURE].idx;

		if (mail_cache_field_exists(cache_view,
					    seq, cache_field1) <= 0 &&
		    mail_cache_field_exists(cache_view,
                                            seq, cache_field2) <= 0) {
			data->access_part |= PARSE_HDR | PARSE_BODY;
			data->save_bodystructure_header = TRUE;
			data->save_bodystructure_body = TRUE;
		}
	}

	if ((mail->wanted_fields & MAIL_FETCH_IMAP_BODYSTRUCTURE) != 0 &&
	    (data->cache_flags & MAIL_CACHE_FLAG_TEXT_PLAIN_7BIT_ASCII) == 0) {
		unsigned int cache_field =
			cache_fields[MAIL_CACHE_IMAP_BODYSTRUCTURE].idx;

                if (mail_cache_field_exists(cache_view, seq,
                                            cache_field) <= 0) {
			data->access_part |= PARSE_HDR | PARSE_BODY;
			data->save_bodystructure_header = TRUE;
			data->save_bodystructure_body = TRUE;
		}
	}

	if ((mail->wanted_fields & MAIL_FETCH_DATE) != 0) {
		unsigned int cache_field =
			cache_fields[MAIL_CACHE_SENT_DATE].idx;

		if (mail_cache_field_exists(cache_view, seq,
					    cache_field) <= 0) {
			data->access_part |= PARSE_HDR;
			data->save_sent_date = TRUE;
		}
	}

	if ((mail->wanted_fields & (MAIL_FETCH_STREAM_HEADER |
				    MAIL_FETCH_STREAM_BODY)) != 0) {
		/* open stream immediately to set expunged flag if
		   it's already lost */
		if ((mail->wanted_fields & MAIL_FETCH_STREAM_HEADER) != 0)
			data->access_part |= READ_HDR;
		if ((mail->wanted_fields & MAIL_FETCH_STREAM_BODY) != 0)
			data->access_part |= READ_BODY;

		(void)mail_get_stream(_mail, NULL, NULL);
	}

	return 0;
}

int index_mail_set_uid(struct mail *_mail, uint32_t uid)
{
	struct index_mail *mail = (struct index_mail *)_mail;
	uint32_t seq;

	if (mail_index_lookup_uid_range(mail->ibox->view,
					uid, uid, &seq, &seq) < 0)
		return -1;

	if (seq == 0) {
		index_mail_reset(mail);
		mail->mail.mail.uid = uid;
		mail_set_expunged(&mail->mail.mail);
		return 0;
	}

	if (index_mail_set_seq(_mail, seq) < 0)
		return -1;
	return 1;
}

void index_mail_free(struct mail *_mail)
{
	struct index_mail *mail = (struct index_mail *)_mail;

	index_mail_close(mail);

	if (mail->header_data != NULL)
		buffer_free(mail->header_data);
	if (array_is_created(&mail->header_lines))
		array_free(&mail->header_lines);
	if (array_is_created(&mail->header_match))
		array_free(&mail->header_match);
	if (array_is_created(&mail->header_match_lines))
		array_free(&mail->header_match_lines);

	pool_unref(mail->data_pool);
	pool_unref(mail->mail.pool);
}

void index_mail_cache_parse_continue(struct mail *_mail)
{
	struct index_mail *mail = (struct index_mail *)_mail;
	struct message_block block;
	int ret;

	while ((ret = message_parser_parse_next_block(mail->data.parser_ctx,
						      &block)) > 0) {
		if (block.size != 0)
			continue;

		if (!mail->data.header_parsed) {
			index_mail_parse_header(block.part, block.hdr, mail);
			if (block.hdr == NULL)
				mail->data.header_parsed = TRUE;
		} else {
			imap_bodystructure_parse_header(mail->data_pool,
							block.part, block.hdr);
		}
	}
}

void index_mail_cache_parse_deinit(struct mail *_mail)
{
	struct index_mail *mail = (struct index_mail *)_mail;

	mail->data.save_bodystructure_body = FALSE;
	mail->data.parsed_bodystructure = TRUE;
	index_mail_parse_body_finish(mail, 0, TRUE);
}

int index_mail_update_flags(struct mail *mail, enum modify_type modify_type,
			    enum mail_flags flags)
{
	struct index_mail *imail = (struct index_mail *)mail;

	mail_index_update_flags(imail->trans->trans, mail->seq, modify_type,
				flags & MAIL_FLAGS_NONRECENT);
	return 0;
}

int index_mail_update_keywords(struct mail *mail, enum modify_type modify_type,
			       struct mail_keywords *keywords)
{
	struct index_mail *imail = (struct index_mail *)mail;

	mail_index_update_keywords(imail->trans->trans, mail->seq, modify_type,
				   keywords);
	return 0;
}

int index_mail_expunge(struct mail *mail)
{
	struct index_mail *imail = (struct index_mail *)mail;

	mail_index_expunge(imail->trans->trans, mail->seq);
	return 0;
}
