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

static void index_mail_parse_body(struct index_mail *mail);

static struct message_part *get_cached_parts(struct index_mail *mail)
{
	struct message_part *part;
	const void *part_data;
	const char *error;
	size_t part_size;

	if ((mail->data.cached_fields & MAIL_CACHE_MESSAGEPART) == 0) {
		mail_cache_mark_missing(mail->trans->cache_view, mail->data.seq,
					MAIL_CACHE_MESSAGEPART);
		return NULL;
	}

	if (!mail_cache_lookup_field(mail->trans->cache_view, mail->data.seq,
				     MAIL_CACHE_MESSAGEPART,
				     &part_data, &part_size)) {
		/* unexpected - must be an error */
		return NULL;
	}

	part = message_part_deserialize(mail->pool, part_data, part_size,
					&error);
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

char *index_mail_get_cached_string(struct index_mail *mail,
				   enum mail_cache_field field)
{
	const char *ret;

	if ((mail->data.cached_fields & field) == 0) {
		mail_cache_mark_missing(mail->trans->cache_view,
					mail->data.seq, field);
		return NULL;
	}

	ret = mail_cache_lookup_string_field(mail->trans->cache_view,
					     mail->data.seq, field);
	return p_strdup(mail->pool, ret);
}

uoff_t index_mail_get_cached_uoff_t(struct index_mail *mail,
				    enum mail_cache_field field)
{
	uoff_t uoff;

	if (!mail_cache_copy_fixed_field(mail->trans->cache_view,
					 mail->data.seq, field,
					 &uoff, sizeof(uoff))) {
		mail_cache_mark_missing(mail->trans->cache_view,
					mail->data.seq, field);
		uoff = (uoff_t)-1;
	}

	return uoff;
}

uoff_t index_mail_get_cached_virtual_size(struct index_mail *mail)
{
	return index_mail_get_cached_uoff_t(mail, MAIL_CACHE_VIRTUAL_FULL_SIZE);
}

time_t index_mail_get_cached_received_date(struct index_mail *mail)
{
	time_t t;

	if (!mail_cache_copy_fixed_field(mail->trans->cache_view,
					 mail->data.seq,
					 MAIL_CACHE_RECEIVED_DATE,
					 &t, sizeof(t))) {
		mail_cache_mark_missing(mail->trans->cache_view, mail->data.seq,
					MAIL_CACHE_RECEIVED_DATE);
		t = (time_t)-1;
	}

	return t;
}

static void get_cached_sent_date(struct index_mail *mail,
				 struct mail_sent_date *sent_date)
{
	if (!mail_cache_copy_fixed_field(mail->trans->cache_view,
					 mail->data.seq,
					 MAIL_CACHE_SENT_DATE,
					 sent_date, sizeof(*sent_date))) {
		mail_cache_mark_missing(mail->trans->cache_view, mail->data.seq,
					MAIL_CACHE_SENT_DATE);

		sent_date->time = (time_t)-1;
		sent_date->timezone = 0;
	}
}

int index_mail_cache_transaction_begin(struct index_mail *mail)
{
	if (mail->trans->cache_trans != NULL)
		return TRUE;

	if (mail->trans->cache_trans_failed) {
		/* don't try more than once */
		return FALSE;
	}

	if (mail_cache_transaction_begin(mail->trans->cache_view, TRUE,
					 mail->trans->trans,
					 &mail->trans->cache_trans) <= 0) {
                mail->trans->cache_trans_failed = TRUE;
		return FALSE;
	}

	mail->data.cached_fields =
		mail_cache_get_fields(mail->trans->cache_view, mail->data.seq);
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

void index_mail_cache_add(struct index_mail *mail, enum mail_cache_field field,
			  const void *data, size_t size)
{
        if (!index_mail_cache_can_add(mail, field))
		return;

	if (mail_cache_add(mail->trans->cache_trans, mail->data.seq,
			   field, data, size) < 0)
		mail_cache_transaction_rollback(mail->trans->cache_trans);

	mail->data.cached_fields |= field;
}

const struct mail_full_flags *index_mail_get_flags(struct mail *_mail)
{
	struct index_mail *mail = (struct index_mail *) _mail;
	struct index_mail_data *data = &mail->data;

	data->flags.flags = data->rec->flags & MAIL_FLAGS_MASK;
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

	if ((mail->wanted_fields & MAIL_FETCH_MESSAGE_PARTS) == 0) {
		data->parts = get_cached_parts(mail);
		if (data->parts != NULL)
			return data->parts;
	}

	if (data->parser_ctx == NULL) {
		if (!index_mail_parse_headers(mail))
			return NULL;
	}
	index_mail_parse_body(mail);

	return data->parts;
}

time_t index_mail_get_received_date(struct mail *_mail)
{
	struct index_mail *mail = (struct index_mail *) _mail;
	struct index_mail_data *data = &mail->data;

	if (data->received_date == (time_t)-1 &&
	    (mail->wanted_fields & MAIL_FETCH_RECEIVED_DATE) == 0) {
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
			index_mail_cache_add(mail, MAIL_CACHE_SENT_DATE,
					     &data->sent_date,
					     sizeof(data->sent_date));
		}
	}

	if (timezone != NULL)
		*timezone = data->sent_date.timezone;
	return data->sent_date.time;
}

static int get_msgpart_sizes(struct index_mail *mail)
{
	struct index_mail_data *data = &mail->data;

	if (data->parts == NULL) {
		if ((mail->wanted_fields & MAIL_FETCH_MESSAGE_PARTS) != 0)
			(void)index_mail_get_parts(&mail->mail);
		else
			data->parts = get_cached_parts(mail);
	}

	if (data->parts != NULL) {
		data->hdr_size = data->parts->header_size;
		data->body_size = data->parts->body_size;
		data->hdr_size_set = TRUE;
		data->body_size_set = TRUE;
		data->size = data->hdr_size.virtual_size +
			data->body_size.virtual_size;
	}

	return data->parts != NULL;
}

uoff_t index_mail_get_size(struct mail *_mail)
{
	struct index_mail *mail = (struct index_mail *) _mail;
	struct index_mail_data *data = &mail->data;
	struct message_size hdr_size, body_size;

	if (data->size != (uoff_t)-1)
		return data->size;

	if ((mail->wanted_fields & MAIL_FETCH_SIZE) == 0) {
		data->size = index_mail_get_cached_virtual_size(mail);
		if (data->size != (uoff_t)-1)
			return data->size;
	}

	if (get_msgpart_sizes(mail))
		return data->size;

	if (_mail->get_stream(_mail, &hdr_size, &body_size) == NULL)
		return (uoff_t)-1;

	return data->size;
}

static void parse_bodystructure_header(struct message_part *part,
				       struct message_header_line *hdr,
				       void *context)
{
	pool_t pool = context;

	imap_bodystructure_parse_header(pool, part, hdr);
}

static void index_mail_parse_body(struct index_mail *mail)
{
	struct index_mail_data *data = &mail->data;
        enum mail_cache_record_flag cache_flags;
	buffer_t *buffer;
	const void *buf_data;
	size_t buf_size;

	i_assert(data->parts == NULL);
	i_assert(data->parser_ctx != NULL);

	i_stream_seek(data->stream, data->hdr_size.physical_size);

	if (data->bodystructure_header_parsed) {
		message_parser_parse_body(data->parser_ctx,
					  parse_bodystructure_header,
					  NULL, mail->pool);
	} else {
		message_parser_parse_body(data->parser_ctx, NULL, NULL, NULL);
	}
	data->parts = message_parser_deinit(data->parser_ctx);
        data->parser_ctx = NULL;

	data->body_size = data->parts->body_size;
	data->body_size_set = TRUE;

	if (mail->mail.has_nuls || mail->mail.has_no_nuls)
		return;

	/* we know the NULs now, update them */
	if ((data->parts->flags & MESSAGE_PART_FLAG_HAS_NULS) != 0) {
		mail->mail.has_nuls = TRUE;
		mail->mail.has_no_nuls = FALSE;
	} else {
		mail->mail.has_nuls = FALSE;
		mail->mail.has_no_nuls = TRUE;
	}

	if (!index_mail_cache_transaction_begin(mail))
		return;

	/* update cache_flags */
	cache_flags = mail_cache_get_record_flags(mail->trans->cache_view,
						  mail->data.seq);
	if (mail->mail.has_nuls)
		cache_flags |= MAIL_INDEX_FLAG_HAS_NULS;
	else
		cache_flags |= MAIL_INDEX_FLAG_HAS_NO_NULS;

	if (!mail_cache_update_record_flags(mail->trans->cache_view,
					    mail->data.seq, cache_flags))
		return;

	if (index_mail_cache_can_add(mail, MAIL_CACHE_MESSAGEPART)) {
		t_push();
		buffer = buffer_create_dynamic(pool_datastack_create(),
					       1024, (size_t)-1);
		message_part_serialize(mail->data.parts, buffer);

		buf_data = buffer_get_data(buffer, &buf_size);
		index_mail_cache_add(mail, MAIL_CACHE_MESSAGEPART,
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
		(void)get_msgpart_sizes(mail);

	if (hdr_size != NULL) {
		if (!data->hdr_size_set) {
			if (!index_mail_parse_headers(mail))
				return NULL;
		}

		*hdr_size = data->hdr_size;
	}

	if (body_size != NULL) {
		if (!data->body_size_set)
			index_mail_parse_body(mail);

		*body_size = data->body_size;
	}

	if (data->hdr_size_set && data->body_size_set) {
		data->size = data->hdr_size.virtual_size +
			data->body_size.virtual_size;
	}

	i_stream_seek(data->stream, 0);
	return data->stream;
}

const char *index_mail_get_special(struct mail *_mail,
				   enum mail_fetch_field field)
{
	struct index_mail *mail = (struct index_mail *) _mail;
	struct index_mail_data *data = &mail->data;
	struct mail_cache *cache = mail->ibox->cache;
	enum mail_cache_field cache_field;
	char *str;

	switch (field) {
	case MAIL_FETCH_IMAP_BODY:
		if ((data->cached_fields & MAIL_CACHE_BODY) &&
		    data->body == NULL) {
			data->body = index_mail_get_cached_string(mail,
					MAIL_CACHE_BODY);
		}
		if (data->body != NULL)
			return data->body;
		/* fall through */
	case MAIL_FETCH_IMAP_BODYSTRUCTURE:
		if ((data->cached_fields & MAIL_CACHE_BODYSTRUCTURE) &&
		    data->bodystructure == NULL) {
			data->bodystructure = index_mail_get_cached_string(mail,
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

		if (!data->bodystructure_header_parsed) {
			data->bodystructure_header_want = TRUE;
			if (!index_mail_parse_headers(mail))
				return NULL;
		}

		if (data->parts != NULL) {
			i_assert(data->parts->next == NULL);
			message_parse_from_parts(data->parts->children,
						 data->stream,
						 parse_bodystructure_header,
						 mail->pool);
		} else {
			index_mail_parse_body(mail);
		}

		t_push();
                str = p_strdup(mail->pool, imap_bodystructure_parse_finish(
			data->parts, field == MAIL_FETCH_IMAP_BODYSTRUCTURE));
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

		data->save_envelope = TRUE;
		(void)_mail->get_header(_mail, "Date");
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
		     const char *const wanted_headers[])
{
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

	index_mail_headers_init(mail);
}

static void index_mail_close(struct index_mail *mail)
{
	if (mail->data.stream != NULL)
		i_stream_unref(mail->data.stream);

	index_mail_headers_close(mail);
}

int index_mail_next(struct index_mail *mail,
		    const struct mail_index_record *rec,
		    uint32_t seq, int delay_open)
{
	struct index_mail_data *data = &mail->data;
        enum mail_cache_record_flag cache_flags;
	int ret, open_mail;

	t_push();

	index_mail_close(mail);
	memset(data, 0, sizeof(*data));
	p_clear(mail->pool);

	data->cached_fields =
		mail_cache_get_fields(mail->trans->cache_view, seq);
	cache_flags = (data->cached_fields & MAIL_CACHE_INDEX_FLAGS) == 0 ? 0 :
		mail_cache_get_record_flags(mail->trans->cache_view, seq);

	mail->mail.seq = seq;
	mail->mail.uid = rec->uid;
	mail->mail.has_nuls = (cache_flags & MAIL_INDEX_FLAG_HAS_NULS) != 0;
	mail->mail.has_no_nuls =
		(cache_flags & MAIL_INDEX_FLAG_HAS_NO_NULS) != 0;

	data->rec = rec;
	data->seq = seq;
	data->size = (uoff_t)-1;
	data->received_date = data->sent_date.time = (time_t)-1;

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
	if (mail->wanted_fields & MAIL_FETCH_SIZE)
		data->size = index_mail_get_cached_virtual_size(mail);
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
                data->bodystructure_header_want = TRUE;
	} else if ((mail->wanted_fields & MAIL_FETCH_IMAP_BODY) &&
		   data->body == NULL && data->bodystructure == NULL) {
		if (data->parts == NULL)
			data->parts = get_cached_parts(mail);
		open_mail = TRUE;
		data->parse_header = data->parts == NULL;
                data->bodystructure_header_want = TRUE;
	} else if (mail->wanted_fields & (MAIL_FETCH_STREAM_HEADER |
					  MAIL_FETCH_STREAM_BODY))
		open_mail = TRUE;

        index_mail_headers_init_next(mail);

	if ((open_mail || data->parse_header) && !delay_open) {
		if (mail->mail.get_stream(&mail->mail, NULL, NULL) == NULL)
			ret = data->deleted ? 0 : -1;
		else
			ret = 1;
	} else {
		if (mail->wanted_fields & MAIL_FETCH_RECEIVED_DATE) {
			/* check this only after open_mail() */
			data->received_date =
				index_mail_get_cached_received_date(mail);
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
	if (mail->ibox->mail_deinit != NULL)
                mail->ibox->mail_deinit(mail);

	t_push();
	index_mail_close(mail);
	t_pop();

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
