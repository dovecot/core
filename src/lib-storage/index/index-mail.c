/* Copyright (C) 2002-2003 Timo Sirainen */

#include "lib.h"
#include "buffer.h"
#include "istream.h"
#include "str.h"
#include "message-date.h"
#include "message-part-serialize.h"
#include "message-parser.h"
#include "imap-bodystructure.h"
#include "imap-envelope.h"
#include "mail-cache.h"
#include "index-storage.h"
#include "index-mail.h"

struct mail_cache_field global_cache_fields[MAIL_CACHE_FIELD_COUNT] = {
	{ "flags", 0, MAIL_CACHE_FIELD_BITMASK, sizeof(uint32_t), 0 },
	{ "date.sent", 0, MAIL_CACHE_FIELD_FIXED_SIZE,
	  sizeof(struct mail_sent_date), 0 },
	{ "date.received", 0, MAIL_CACHE_FIELD_FIXED_SIZE,
	  sizeof(time_t), 0 },
	{ "size.virtual", 0, MAIL_CACHE_FIELD_FIXED_SIZE,
	  sizeof(uoff_t), 0 },
	{ "size.physical", 0, MAIL_CACHE_FIELD_FIXED_SIZE,
	  sizeof(uoff_t), 0 },
	{ "imap.body", 0, MAIL_CACHE_FIELD_STRING, 0, 0 },
	{ "imap.bodystructure", 0, MAIL_CACHE_FIELD_STRING, 0, 0 },
	{ "imap.envelope", 0, MAIL_CACHE_FIELD_STRING, 0, 0 },
	{ "mime.parts", 0, MAIL_CACHE_FIELD_VARIABLE_SIZE, 0, 0 },
	{ "mail.uid", 0, MAIL_CACHE_FIELD_STRING, 0, 0 }
};

static void index_mail_parse_body(struct index_mail *mail, int need_parts);

static struct message_part *get_cached_parts(struct index_mail *mail)
{
	struct mail_cache_field *cache_fields = mail->ibox->cache_fields;
	struct message_part *part;
	buffer_t *part_buf;
	const char *error;

	t_push();
	part_buf = buffer_create_dynamic(pool_datastack_create(),
					 128, (size_t)-1);
	if (mail_cache_lookup_field(mail->trans->cache_view, part_buf,
			mail->data.seq,
			cache_fields[MAIL_CACHE_MESSAGEPART].idx) <= 0) {
		t_pop();
		return NULL;
	}

	part = message_part_deserialize(mail->pool,
					buffer_get_data(part_buf, NULL),
					buffer_get_used_size(part_buf),
					&error);
	t_pop();

	if (part == NULL) {
		mail_cache_set_corrupted(mail->ibox->cache,
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

const char *index_mail_get_cached_string(struct index_mail *mail,
					 enum index_cache_field field)
{
	string_t *str;

	str = str_new(mail->pool, 32);
	if (mail_cache_lookup_field(mail->trans->cache_view, str,
				    mail->data.seq,
				    mail->ibox->cache_fields[field].idx) <= 0) {
		p_free(mail->pool, str);
		return NULL;
	}

	return str_c(str);
}

static int index_mail_get_fixed_field(struct index_mail *mail,
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
		i_assert(buffer_get_used_size(buf) == data_size);
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

uoff_t index_mail_get_cached_virtual_size(struct index_mail *mail)
{
	return index_mail_get_cached_uoff_t(mail, MAIL_CACHE_VIRTUAL_FULL_SIZE);
}

static uoff_t index_mail_get_cached_physical_size(struct index_mail *mail)
{
	return index_mail_get_cached_uoff_t(mail,
					    MAIL_CACHE_PHYSICAL_FULL_SIZE);
}

time_t index_mail_get_cached_received_date(struct index_mail *mail)
{
	time_t t;

	if (!index_mail_get_fixed_field(mail, MAIL_CACHE_RECEIVED_DATE,
					&t, sizeof(t)))
		t = (time_t)-1;
	return t;
}

static void get_cached_sent_date(struct index_mail *mail,
				 struct mail_sent_date *sent_date)
{
	if (!index_mail_get_fixed_field(mail, MAIL_CACHE_SENT_DATE,
					sent_date, sizeof(*sent_date))) {
		sent_date->time = (time_t)-1;
		sent_date->timezone = 0;
	}
}

const struct mail_full_flags *index_mail_get_flags(struct mail *_mail)
{
	struct index_mail *mail = (struct index_mail *) _mail;
	struct index_mail_data *data = &mail->data;

	data->flags.flags = data->rec->flags & MAIL_FLAGS_MASK;
	if (index_mailbox_is_recent(mail->ibox, data->seq))
		data->flags.flags |= MAIL_RECENT;

	/*FIXME:data->flags.keywords =
		mail_keywords_list_get(mail->ibox->index->keywords);
	data->flags.keywords_count = MAIL_KEYWORDS_COUNT;*/

	return &data->flags;
}

const struct message_part *index_mail_get_parts(struct mail *_mail)
{
	struct index_mail *mail = (struct index_mail *) _mail;
	struct index_mail_data *data = &mail->data;

	if (data->parts != NULL)
		return data->parts;

	data->parts = get_cached_parts(mail);
	if (data->parts != NULL)
		return data->parts;

	if (data->parser_ctx == NULL) {
		if (index_mail_parse_headers(mail, NULL) < 0)
			return NULL;
	}
	index_mail_parse_body(mail, TRUE);

	return data->parts;
}

time_t index_mail_get_received_date(struct mail *_mail)
{
	struct index_mail *mail = (struct index_mail *) _mail;
	struct index_mail_data *data = &mail->data;

	if (data->received_date == (time_t)-1) {
		data->received_date = index_mail_get_cached_received_date(mail);
		if (data->received_date != (time_t)-1)
			return data->received_date;
	}

	return data->received_date;
}

time_t index_mail_get_date(struct mail *_mail, int *timezone)
{
	struct index_mail *mail = (struct index_mail *) _mail;
	struct index_mail_data *data = &mail->data;
	struct mail_cache_field *cache_fields = mail->ibox->cache_fields;
	const char *str;
	int tz;

	if (data->sent_date.time != (time_t)-1) {
		if (timezone != NULL)
			*timezone = data->sent_date.timezone;
		return data->sent_date.time;
	}

	if ((mail->wanted_fields & MAIL_FETCH_DATE) == 0)
		get_cached_sent_date(mail, &data->sent_date);

	if (data->sent_date.time == (time_t)-1) {
		data->save_sent_date = TRUE;
		str = _mail->get_header(_mail, "Date");
		if (data->sent_date.time == (time_t)-1) {
			if (!message_date_parse(str, (size_t)-1,
						&data->sent_date.time, &tz)) {
				/* 0 == parse error */
				data->sent_date.time = 0;
				tz = 0;
			}
                        data->sent_date.timezone = tz;
			mail_cache_add(mail->trans->cache_trans, mail->data.seq,
				       cache_fields[MAIL_CACHE_SENT_DATE].idx,
				       &data->sent_date,
				       sizeof(data->sent_date));
		}
	}

	if (timezone != NULL)
		*timezone = data->sent_date.timezone;
	return data->sent_date.time;
}

static int get_cached_msgpart_sizes(struct index_mail *mail)
{
	struct index_mail_data *data = &mail->data;

	if (data->parts == NULL)
		data->parts = get_cached_parts(mail);

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

uoff_t index_mail_get_virtual_size(struct mail *_mail)
{
	struct index_mail *mail = (struct index_mail *) _mail;
	struct index_mail_data *data = &mail->data;
	struct mail_cache_field *cache_fields = mail->ibox->cache_fields;
	struct message_size hdr_size, body_size;

	if (data->virtual_size != (uoff_t)-1)
		return data->virtual_size;

	data->virtual_size = index_mail_get_cached_virtual_size(mail);
	if (data->virtual_size != (uoff_t)-1)
		return data->virtual_size;

	if (get_cached_msgpart_sizes(mail))
		return data->virtual_size;

	if (_mail->get_stream(_mail, &hdr_size, &body_size) == NULL)
		return (uoff_t)-1;

	mail_cache_add(mail->trans->cache_trans, mail->data.seq,
		       cache_fields[MAIL_CACHE_VIRTUAL_FULL_SIZE].idx,
		       &data->virtual_size, sizeof(data->virtual_size));
	return data->virtual_size;
}

uoff_t index_mail_get_physical_size(struct mail *_mail)
{
	struct index_mail *mail = (struct index_mail *) _mail;
	struct index_mail_data *data = &mail->data;

	if (data->physical_size != (uoff_t)-1)
		return data->physical_size;

	data->physical_size = index_mail_get_cached_physical_size(mail);
	if (data->physical_size != (uoff_t)-1)
		return data->physical_size;

	if (get_cached_msgpart_sizes(mail))
		return data->physical_size;

	return (uoff_t)-1;
}

static void parse_bodystructure_part_header(struct message_part *part,
					    struct message_header_line *hdr,
					    void *context)
{
	pool_t pool = context;

	imap_bodystructure_parse_header(pool, part, hdr);
}

static void index_mail_parse_body(struct index_mail *mail, int need_parts)
{
	struct index_mail_data *data = &mail->data;
	struct mail_cache_field *cache_fields = mail->ibox->cache_fields;
	enum mail_cache_decision_type decision;
	buffer_t *buffer;
	const void *buf_data;
	size_t buf_size;
	uint32_t cache_flags;

	i_assert(data->parts == NULL);
	i_assert(data->parser_ctx != NULL);

	i_stream_seek(data->stream, data->hdr_size.physical_size);

	if (data->save_bodystructure_body) {
		/* bodystructure header is parsed, we want the body's mime
		   headers too */
		i_assert(!data->save_bodystructure_header);
		message_parser_parse_body(data->parser_ctx,
					  parse_bodystructure_part_header,
					  NULL, mail->pool);
		data->save_bodystructure_body = FALSE;
		data->parsed_bodystructure = TRUE;
	} else {
		message_parser_parse_body(data->parser_ctx, NULL, NULL, NULL);
	}
	data->parts = message_parser_deinit(data->parser_ctx);
        data->parser_ctx = NULL;

	data->body_size = data->parts->body_size;
	data->body_size_set = TRUE;

	cache_flags = 0;
	if (!mail->mail.has_nuls && !mail->mail.has_no_nuls) {
		/* we know the NULs now, update them */
		if ((data->parts->flags & MESSAGE_PART_FLAG_HAS_NULS) != 0) {
			mail->mail.has_nuls = TRUE;
			mail->mail.has_no_nuls = FALSE;
		} else {
			mail->mail.has_nuls = FALSE;
			mail->mail.has_no_nuls = TRUE;
		}

		if (mail->mail.has_nuls)
			cache_flags |= MAIL_CACHE_FLAG_HAS_NULS;
		else
			cache_flags |= MAIL_CACHE_FLAG_HAS_NO_NULS;
	}

	if (data->hdr_size.virtual_size == data->hdr_size.physical_size)
		cache_flags |= MAIL_CACHE_FLAG_BINARY_HEADER;
	if (data->body_size.virtual_size == data->body_size.physical_size)
		cache_flags |= MAIL_CACHE_FLAG_BINARY_BODY;

	if ((cache_flags & ~data->cache_flags) != 0) {
		mail_cache_add(mail->trans->cache_trans, mail->data.seq,
			       cache_fields[MAIL_CACHE_FLAGS].idx,
			       &cache_flags, sizeof(cache_flags));
	}

	/* see if we want to cache the message part */
	if (mail_cache_field_exists(mail->trans->cache_view, mail->data.seq,
			cache_fields[MAIL_CACHE_MESSAGEPART].idx) != 0)
		return;

	decision = mail_cache_field_get_decision(mail->ibox->cache,
				cache_fields[MAIL_CACHE_MESSAGEPART].idx);
	if (decision != (MAIL_CACHE_DECISION_NO | MAIL_CACHE_DECISION_FORCED) &&
	    (decision != MAIL_CACHE_DECISION_NO || need_parts ||
	     (mail->wanted_fields & MAIL_FETCH_MESSAGE_PARTS) != 0)) {
		t_push();
		buffer = buffer_create_dynamic(pool_datastack_create(),
					       1024, (size_t)-1);
		message_part_serialize(mail->data.parts, buffer);

		buf_data = buffer_get_data(buffer, &buf_size);
		mail_cache_add(mail->trans->cache_trans, mail->data.seq,
			       cache_fields[MAIL_CACHE_MESSAGEPART].idx,
			       buf_data, buf_size);
		t_pop();
	}
}

struct istream *index_mail_init_stream(struct index_mail *_mail,
				       struct message_size *hdr_size,
				       struct message_size *body_size)
{
	struct index_mail *mail = (struct index_mail *) _mail;
	struct index_mail_data *data = &mail->data;

	if (hdr_size != NULL || body_size != NULL)
		(void)get_cached_msgpart_sizes(mail);

	if (hdr_size != NULL) {
		if (!data->hdr_size_set) {
			if (index_mail_parse_headers(mail, NULL) < 0)
				return NULL;
		}

		*hdr_size = data->hdr_size;
	}

	if (body_size != NULL) {
		if (!data->body_size_set)
			index_mail_parse_body(mail, FALSE);

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
	struct mail_cache_field *cache_fields = mail->ibox->cache_fields;
	enum mail_cache_decision_type dec;
	string_t *str;
	int bodystructure_cached = FALSE;

	if (!data->parsed_bodystructure) {
		if (data->save_bodystructure_header ||
		    !data->save_bodystructure_body) {
			/* we haven't parsed the header yet */
			data->save_bodystructure_header = TRUE;
			data->save_bodystructure_body = TRUE;
			if (index_mail_parse_headers(mail, NULL) < 0)
				return;
		}

		if (data->parts != NULL) {
			i_assert(data->parts->next == NULL);
			i_stream_seek(data->stream,
				      data->hdr_size.physical_size);
			message_parse_from_parts(data->parts->children,
						data->stream,
						parse_bodystructure_part_header,
						mail->pool);
			data->parsed_bodystructure = TRUE;
		} else {
			index_mail_parse_body(mail, FALSE);
		}
	}

	dec = mail_cache_field_get_decision(mail->ibox->cache,
				cache_fields[MAIL_CACHE_BODYSTRUCTURE].idx);
	if (field == MAIL_CACHE_BODYSTRUCTURE ||
	    ((dec & ~MAIL_CACHE_DECISION_FORCED) != MAIL_CACHE_DECISION_NO &&
	     mail_cache_field_exists(mail->trans->cache_view, data->seq,
			cache_fields[MAIL_CACHE_BODYSTRUCTURE].idx) == 0)) {
		str = str_new(mail->pool, 128);
		imap_bodystructure_write(data->parts, str, TRUE);
		data->bodystructure = str_c(str);

		if (dec !=
		    (MAIL_CACHE_DECISION_NO | MAIL_CACHE_DECISION_FORCED)) {
			mail_cache_add(mail->trans->cache_trans, data->seq,
				cache_fields[MAIL_CACHE_BODYSTRUCTURE].idx,
				str_c(str), str_len(str)+1);
			bodystructure_cached = TRUE;
		}
	}

	dec = mail_cache_field_get_decision(mail->ibox->cache,
					    cache_fields[MAIL_CACHE_BODY].idx);
	if (field == MAIL_CACHE_BODY ||
	    ((dec & ~MAIL_CACHE_DECISION_FORCED) != MAIL_CACHE_DECISION_NO &&
	     mail_cache_field_exists(mail->trans->cache_view, data->seq,
				     cache_fields[MAIL_CACHE_BODY].idx) == 0)) {
		str = str_new(mail->pool, 128);
		imap_bodystructure_write(data->parts, str, FALSE);
		data->body = str_c(str);

		if (!bodystructure_cached && dec !=
		    (MAIL_CACHE_DECISION_NO | MAIL_CACHE_DECISION_FORCED)) {
			mail_cache_add(mail->trans->cache_trans, data->seq,
				       cache_fields[MAIL_CACHE_BODY].idx,
				       str_c(str), str_len(str)+1);
		}
	}
}

const char *index_mail_get_special(struct mail *_mail,
				   enum mail_fetch_field field)
{
	struct index_mail *mail = (struct index_mail *) _mail;
	struct index_mail_data *data = &mail->data;
	struct mail_cache_field *cache_fields = mail->ibox->cache_fields;
	string_t *str;

	switch (field) {
	case MAIL_FETCH_IMAP_BODY:
		if (data->body != NULL)
			return data->body;

		/* 1) get BODY if it exists
		   2) get it using BODYSTRUCTURE if it exists
		   3) parse body structure, and save BODY/BODYSTRUCTURE
		      depending on what we want cached */

		str = str_new(mail->pool, 128);
		if (mail_cache_lookup_field(mail->trans->cache_view, str,
				mail->data.seq,
				cache_fields[MAIL_CACHE_BODY].idx) > 0) {
			data->body = str_c(str);
			return data->body;
		}
		if (mail_cache_lookup_field(mail->trans->cache_view, str,
			      mail->data.seq,
			      cache_fields[MAIL_CACHE_BODYSTRUCTURE].idx) > 0) {
			data->bodystructure = p_strdup(mail->pool, str_c(str));
			str_truncate(str, 0);

			if (imap_body_parse_from_bodystructure(
						data->bodystructure, str)) {
				data->body = str_c(str);
				return data->body;
			}

			/* broken, continue.. */
			mail_cache_set_corrupted(mail->ibox->cache,
				"Corrupted BODYSTRUCTURE for mail %u",
				mail->mail.uid);
			data->bodystructure = NULL;
		}
		p_free(mail->pool, str);

		index_mail_parse_bodystructure(mail, MAIL_CACHE_BODY);
		return data->body;
	case MAIL_FETCH_IMAP_BODYSTRUCTURE:
		if (data->bodystructure != NULL)
			return data->bodystructure;

		str = str_new(mail->pool, 128);
		if (mail_cache_lookup_field(mail->trans->cache_view, str,
			      mail->data.seq,
			      cache_fields[MAIL_CACHE_BODYSTRUCTURE].idx) > 0) {
			data->bodystructure = str_c(str);
			return data->bodystructure;
		}
		p_free(mail->pool, str);

		index_mail_parse_bodystructure(mail, MAIL_CACHE_BODYSTRUCTURE);
		return data->bodystructure;
	case MAIL_FETCH_IMAP_ENVELOPE:
		if (data->envelope == NULL)
			index_mail_headers_get_envelope(mail);
		return data->envelope;
	case MAIL_FETCH_FROM_ENVELOPE:
		return NULL;
	case MAIL_FETCH_UID_STRING:
		if (data->uid_string == NULL) {
			data->uid_string =
				p_strdup_printf(mail->pool, "%u.%u",
						mail->uid_validity, _mail->uid);
		}
		return data->uid_string;
	default:
		i_unreached();
		return NULL;
	}
}

void index_mail_init(struct index_transaction_context *t,
		     struct index_mail *mail,
		     enum mail_fetch_field wanted_fields,
		     struct mailbox_header_lookup_ctx *_wanted_headers)
{
	struct index_header_lookup_ctx *wanted_headers =
		(struct index_header_lookup_ctx *)_wanted_headers;
	const struct mail_index_header *hdr;
	int ret;

	mail->mail = *t->ibox->mail_interface;
	mail->mail.box = &t->ibox->box;

	ret = mail_index_get_header(t->ibox->view, &hdr);
	i_assert(ret == 0);

	mail->uid_validity = hdr->uid_validity;

	mail->pool = pool_alloconly_create("index_mail", 16384);
	mail->ibox = t->ibox;
	mail->trans = t;
	mail->wanted_fields = wanted_fields;
	mail->wanted_headers = wanted_headers;
}

static void index_mail_close(struct index_mail *mail)
{
	if (mail->data.stream != NULL)
		i_stream_unref(mail->data.stream);
	if (mail->data.filter_stream != NULL)
		i_stream_unref(mail->data.filter_stream);
}

int index_mail_next(struct index_mail *mail, uint32_t seq)
{
	struct index_mail_data *data = &mail->data;
        const struct mail_index_record *rec;
        uint32_t cache_flags;

	if (mail_index_lookup(mail->trans->trans_view, seq, &rec) < 0) {
		mail_storage_set_index_error(mail->ibox);
		return -1;
	}

	index_mail_close(mail);

	memset(data, 0, sizeof(*data));
	p_clear(mail->pool);

	data->rec = rec;
	data->seq = seq;
	data->virtual_size = (uoff_t)-1;
	data->physical_size = (uoff_t)-1;
	data->received_date = data->sent_date.time = (time_t)-1;

	if (!index_mail_get_fixed_field(mail, MAIL_CACHE_FLAGS,
					&cache_flags, sizeof(cache_flags)))
		cache_flags = 0;

	mail->mail.seq = seq;
	mail->mail.uid = rec->uid;
	mail->mail.has_nuls = (cache_flags & MAIL_CACHE_FLAG_HAS_NULS) != 0;
	mail->mail.has_no_nuls =
		(cache_flags & MAIL_CACHE_FLAG_HAS_NO_NULS) != 0;

	t_push();

	/* if some wanted fields are cached, get them */
	if (mail->wanted_fields & MAIL_FETCH_MESSAGE_PARTS)
		data->parts = get_cached_parts(mail);
	if (mail->wanted_fields & MAIL_FETCH_IMAP_BODY) {
		data->body =
			index_mail_get_cached_string(mail, MAIL_CACHE_BODY);
	}
	if ((mail->wanted_fields & MAIL_FETCH_IMAP_BODYSTRUCTURE) ||
	    ((mail->wanted_fields & MAIL_FETCH_IMAP_BODY) &&
	     data->body == NULL)) {
		data->bodystructure = index_mail_get_cached_string(mail,
					MAIL_CACHE_BODYSTRUCTURE);
	}
	if (mail->wanted_fields & MAIL_FETCH_VIRTUAL_SIZE)
		data->virtual_size = index_mail_get_cached_virtual_size(mail);
	if (mail->wanted_fields & MAIL_FETCH_PHYSICAL_SIZE)
		data->physical_size = index_mail_get_cached_physical_size(mail);
	if (mail->wanted_fields & MAIL_FETCH_DATE)
		get_cached_sent_date(mail, &data->sent_date);

	/* see if we have to parse the message */
	if ((mail->wanted_fields & MAIL_FETCH_MESSAGE_PARTS) &&
	    data->parts == NULL)
		data->parse_header = TRUE;
	else if ((mail->wanted_fields & MAIL_FETCH_IMAP_BODYSTRUCTURE) &&
		 data->bodystructure == NULL) {
		if (data->parts == NULL)
			data->parts = get_cached_parts(mail);
		data->open_mail = TRUE;
		data->parse_header = data->parts == NULL;
		data->save_bodystructure_header = TRUE;
		data->save_bodystructure_body = TRUE;
	} else if ((mail->wanted_fields & MAIL_FETCH_IMAP_BODY) &&
		   data->body == NULL && data->bodystructure == NULL) {
		if (data->parts == NULL)
			data->parts = get_cached_parts(mail);
		data->open_mail = TRUE;
		data->parse_header = data->parts == NULL;
		data->save_bodystructure_header = TRUE;
		data->save_bodystructure_body = TRUE;
	} else if (mail->wanted_fields & (MAIL_FETCH_STREAM_HEADER |
					  MAIL_FETCH_STREAM_BODY))
		data->open_mail = TRUE;

	if ((mail->wanted_fields & MAIL_FETCH_DATE) &&
	    data->sent_date.time == (time_t)-1)
		data->save_sent_date = TRUE;

	if (mail->wanted_fields & MAIL_FETCH_IMAP_ENVELOPE)
		data->save_envelope = TRUE;

	t_pop();
	return 0;
}

void index_mail_deinit(struct index_mail *mail)
{
	if (mail->ibox->mail_deinit != NULL)
                mail->ibox->mail_deinit(mail);

	index_mail_close(mail);

	if (mail->header_data != NULL)
		buffer_free(mail->header_data);
	if (mail->header_lines != NULL)
		buffer_free(mail->header_lines);
	if (mail->header_match != NULL)
		buffer_free(mail->header_match);
	if (mail->header_offsets != NULL)
		buffer_free(mail->header_offsets);

	pool_unref(mail->pool);
	memset(mail, 0, sizeof(*mail));
}

int index_mail_update_flags(struct mail *mail,
			    const struct mail_full_flags *flags,
			    enum modify_type modify_type)
{
	struct index_mail *imail = (struct index_mail *)mail;
	enum mail_flags modify_flags;
	keywords_mask_t keywords;

	modify_flags = flags->flags & MAIL_FLAGS_MASK;

	/*if (!index_mailbox_fix_keywords(ibox, &modify_flags,
					    flags->keywords,
					    flags->keywords_count))
		return FALSE;*/

	memset(keywords, 0, sizeof(keywords));
	mail_index_update_flags(imail->trans->trans, mail->seq, modify_type,
				flags->flags, keywords);

	/*if (mail_keywords_has_changes(ibox->index->keywords)) {
		storage->callbacks->new_keywords(&ibox->box,
			mail_keywords_list_get(ibox->index->keywords),
			MAIL_KEYWORDS_COUNT, storage->callback_context);
	}*/

	return 0;
}

int index_mail_expunge(struct mail *mail)
{
	struct index_mail *imail = (struct index_mail *)mail;

	mail_index_expunge(imail->trans->trans, mail->seq);
	return 0;
}
