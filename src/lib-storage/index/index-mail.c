/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
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
#include "index-storage.h"
#include "index-mail.h"

#include <ctype.h>

static struct message_part *get_cached_parts(struct index_mail *mail)
{
	struct message_part *part;
	const void *part_data;
	const char *error;
	size_t part_size;

	part_data = mail->ibox->index->
		lookup_field_raw(mail->ibox->index, mail->data.rec,
				 DATA_FIELD_MESSAGEPART, &part_size);
	if (part_data == NULL) {
		mail->ibox->index->cache_fields_later(mail->ibox->index,
						      DATA_FIELD_MESSAGEPART);
		return NULL;
	}

	part = message_part_deserialize(mail->pool, part_data, part_size,
					&error);
	if (part == NULL) {
		index_set_corrupted(mail->ibox->index,
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

static char *get_cached_field(struct index_mail *mail,
			      enum mail_data_field field)
{
	const char *ret;

	ret = mail->ibox->index->lookup_field(mail->ibox->index,
					      mail->data.rec, field);
	if (ret == NULL)
		mail->ibox->index->cache_fields_later(mail->ibox->index, field);
	return p_strdup(mail->pool, ret);
}

static uoff_t get_cached_uoff_t(struct index_mail *mail,
				enum mail_data_field field,
				const char *field_name)
{
	const uoff_t *uoff_p;
	size_t size;

	uoff_p = mail->ibox->index->
		lookup_field_raw(mail->ibox->index, mail->data.rec,
				 field, &size);

	if (uoff_p == NULL)
		mail->ibox->index->cache_fields_later(mail->ibox->index, field);
	else if (size != sizeof(*uoff_p)) {
		index_set_corrupted(mail->ibox->index,
				    "Corrupted cached %s", field_name);
		uoff_p = NULL;
	}

	return uoff_p == NULL ? (uoff_t)-1 : *uoff_p;
}

static uoff_t get_cached_virtual_size(struct index_mail *mail)
{
	return get_cached_uoff_t(mail, DATA_HDR_VIRTUAL_SIZE, "virtual size");
}

static time_t get_cached_received_date(struct index_mail *mail)
{
	const time_t *time_p;
	size_t size;

	time_p = mail->ibox->index->
		lookup_field_raw(mail->ibox->index, mail->data.rec,
				 DATA_HDR_INTERNAL_DATE, &size);

	if (time_p == NULL) {
		mail->ibox->index->cache_fields_later(mail->ibox->index,
						      DATA_HDR_INTERNAL_DATE);
	} else if (size != sizeof(*time_p)) {
		index_set_corrupted(mail->ibox->index,
				    "Corrupted cached received time");
		time_p = NULL;
	}

	return time_p == NULL ? (time_t)-1 : *time_p;
}

static int open_stream(struct index_mail *mail, uoff_t position)
{
	int deleted;

	if (mail->data.stream == NULL) {
		mail->data.stream = mail->ibox->index->
			open_mail(mail->ibox->index, mail->data.rec,
				  &mail->data.received_date, &deleted);

		if (mail->data.stream == NULL)
			return FALSE;
	}

	i_stream_seek(mail->data.stream, position);
	return TRUE;
}

static void prepend_cached_header(struct index_mail *mail, const char *name)
{
	struct cached_header *hdr;

	hdr = p_new(mail->pool, struct cached_header, 1);
	hdr->name = name;
	hdr->name_len = strlen(name);

	hdr->next = mail->data.headers;
	mail->data.headers = hdr;
}

void index_mail_init_parse_header(struct index_mail *mail)
{
	const char *const *tmp;

	if (mail->wanted_headers != NULL) {
		for (tmp = mail->wanted_headers; *tmp != NULL; tmp++)
			prepend_cached_header(mail, *tmp);
	}
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
		if (data->save_sent_time) {
			/* not found */
			data->sent_time = 0;
			data->sent_timezone = 0;
			data->save_sent_time = FALSE;
		}
		return;
	}

	if (data->save_sent_time && strcasecmp(hdr->name, "Date") == 0) {
		if (hdr->continues) {
			hdr->use_full_value = TRUE;
			return;
		}
		if (!message_date_parse(hdr->full_value, hdr->full_value_len,
					&data->sent_time,
					&data->sent_timezone)) {
			/* 0 == parse error */
			data->sent_time = 0;
			data->sent_timezone = 0;
		}
		data->save_sent_time = FALSE;
	}

        cached_hdr = data->headers;
	while (cached_hdr != NULL) {
		if (cached_hdr->name_len == hdr->name_len &&
		    memcasecmp(hdr->name, hdr->name, hdr->name_len) == 0) {
			/* save only the first header */
			if (cached_hdr->value != NULL)
				break;

			if (hdr->continues) {
				hdr->use_full_value = TRUE;
				break;
			}

			cached_hdr->value = p_strndup(mail->pool,
						      hdr->full_value,
						      hdr->full_value_len);
			break;
		}
                cached_hdr = cached_hdr->next;
	}
}

static int parse_header(struct index_mail *mail)
{
	if (!open_stream(mail, 0))
		return FALSE;

        index_mail_init_parse_header(mail);
	message_parse_header(NULL, mail->data.stream, &mail->data.hdr_size,
			     index_mail_parse_header, mail);
	mail->data.parse_header = FALSE;
	mail->data.hdr_size_set = TRUE;

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

	if (data->parts != NULL)
		return data->parts;

	if ((mail->wanted_fields & MAIL_FETCH_MESSAGE_PARTS) == 0) {
		data->parts = get_cached_parts(mail);
		if (data->parts != NULL)
			return data->parts;
	}

	if (!open_stream(mail, 0))
		return NULL;

        index_mail_init_parse_header(mail);
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
		get_internal_date(mail->ibox->index, mail->data.rec);
	return data->received_date;
}

static time_t get_date(struct mail *_mail, int *timezone)
{
	struct index_mail *mail = (struct index_mail *) _mail;
	struct index_mail_data *data = &mail->data;
	const char *result;

	if (data->sent_time != (time_t)-1) {
		if (timezone != NULL)
			*timezone = data->sent_timezone;
		return data->sent_time;
	}

	if (data->parse_header || data->envelope == NULL) {
		data->save_sent_time = TRUE;
		parse_header(mail);
	} else {
		if (!imap_envelope_parse(data->envelope,
					 IMAP_ENVELOPE_DATE,
					 IMAP_ENVELOPE_RESULT_TYPE_STRING,
					 &result))
			return (time_t)-1;

		if (!message_date_parse((const unsigned char *) result,
					(size_t)-1, &data->sent_time,
					&data->sent_timezone))
			data->sent_time = 0;
	}

	if (timezone != NULL)
		*timezone = data->sent_timezone;
	return data->sent_time;
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
	uoff_t size;

	if (!mail->data.hdr_size_set &&
	    (mail->data.rec->index_flags & INDEX_MAIL_FLAG_BINARY_HEADER)) {
		size = get_cached_uoff_t(mail, DATA_HDR_HEADER_SIZE,
					 "header size");
		if (size != (uoff_t)-1) {
			mail->data.hdr_size.physical_size =
				mail->data.hdr_size.virtual_size = size;
			mail->data.hdr_size_set = TRUE;
		}
	}

	if (!mail->data.body_size_set &&
	    (mail->data.rec->index_flags & INDEX_MAIL_FLAG_BINARY_BODY)) {
		size = get_cached_uoff_t(mail, DATA_HDR_BODY_SIZE, "body size");
		if (size != (uoff_t)-1) {
			mail->data.body_size.physical_size =
				mail->data.body_size.virtual_size = size;
			mail->data.body_size_set = TRUE;
		}
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
	return data->size;
}

static const char *get_header(struct mail *_mail, const char *field)
{
	struct index_mail *mail = (struct index_mail *) _mail;
	struct index_mail_data *data = &mail->data;
	struct cached_header *hdr;
	enum imap_envelope_field env_field = 0;
	const char *str;
	char *ret;

	for (hdr = data->headers; hdr != NULL; hdr = hdr->next) {
		if (strcasecmp(hdr->name, field) == 0)
			return hdr->value;
	}

	if (data->parse_header || data->envelope == NULL ||
	    !imap_envelope_get_field(field, &env_field)) {
		/* if we have to parse the header, do it even if we could use
		   envelope - envelope parsing would just slow up. */
                prepend_cached_header(mail, field);
		parse_header(mail);

		for (hdr = data->headers; hdr != NULL; hdr = hdr->next) {
			if (strcasecmp(hdr->name, field) == 0)
				return hdr->value;
		}

		return NULL;
	} else {
		t_push();
		if (!imap_envelope_parse(data->envelope, env_field,
					 IMAP_ENVELOPE_RESULT_TYPE_STRING,
					 &str))
			str = NULL;
		ret = p_strdup(mail->pool, str);
		t_pop();
		return ret;
	}
}

static const struct message_address *
get_address(struct mail *_mail, const char *field)
{
	struct index_mail *mail = (struct index_mail *) _mail;
	const char *str;

	/* don't bother with checking envelope - we're most likely
	   creating it */
	str = get_header(_mail, field);
	if (str == NULL)
		return NULL;

	return message_address_parse(mail->pool, (const unsigned char *) str,
				     (size_t)-1, 1);
}

static const char *get_first_mailbox(struct mail *_mail, const char *field)
{
	struct index_mail *mail = (struct index_mail *) _mail;
	struct index_mail_data *data = &mail->data;
	enum imap_envelope_field env_field;
	const char *str;
	const char *ret = NULL;

	if (data->envelope != NULL &&
	    imap_envelope_get_field(field, &env_field)) {
		/* prefer parsing envelope - faster than having to actually
		   parse the header field */
		t_push();
		if (!imap_envelope_parse(data->envelope, env_field,
					IMAP_ENVELOPE_RESULT_TYPE_FIRST_MAILBOX,
					&str))
			str = NULL;
		ret = p_strdup(mail->pool, str);
		t_pop();
	} else {
		struct message_address *addr;

		str = get_header(_mail, field);
		if (str == NULL)
			return NULL;

		addr = message_address_parse(mail->pool,
					     (const unsigned char *) str,
					     (size_t)-1, 1);
		if (addr != NULL)
			ret = addr->mailbox;
	}

	return ret;
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

	i_stream_seek(data->stream, 0);
	return data->stream;
}

static const char *get_special(struct mail *_mail, enum mail_fetch_field field)
{
	struct index_mail *mail = (struct index_mail *) _mail;
	struct index_mail_data *data = &mail->data;
	char *str;

	switch (field) {
	case MAIL_FETCH_IMAP_BODY:
		if (data->body != NULL)
			return data->body;
		/* fall through */
	case MAIL_FETCH_IMAP_BODYSTRUCTURE:
		if (data->bodystructure != NULL) {
			if (field == MAIL_FETCH_IMAP_BODYSTRUCTURE)
				return data->bodystructure;

			/* create BODY from cached BODYSTRUCTURE */
			t_push();
			data->body = p_strdup(mail->pool,
				imap_body_parse_from_bodystructure(
							data->bodystructure));
			t_pop();
			return data->body;
		}

		if (data->parts == NULL)
			data->parts = get_cached_parts(mail);

		t_push();
		str = p_strdup(mail->pool, imap_part_get_bodystructure(
				mail->pool, &data->parts, data->stream,
				field == MAIL_FETCH_IMAP_BODYSTRUCTURE));
		t_pop();

		if (field == MAIL_FETCH_IMAP_BODYSTRUCTURE)
			data->bodystructure = str;
		else
			data->body = str;
		return str;
	case MAIL_FETCH_IMAP_ENVELOPE:
		if (data->envelope != NULL)
			return data->envelope;

		if ((mail->wanted_fields & MAIL_FETCH_IMAP_ENVELOPE) == 0) {
			data->envelope = p_strdup(mail->pool,
				get_cached_field(mail, DATA_FIELD_ENVELOPE));
			if (data->envelope != NULL)
				return data->envelope;
		}

		data->save_envelope = TRUE;
		parse_header(mail);
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
	get_address,
	get_first_mailbox,
	get_stream,
	get_special
};

void index_mail_init(struct index_mailbox *ibox, struct index_mail *mail,
		     enum mail_fetch_field wanted_fields,
		     const char *const wanted_headers[])
{
	mail->mail = index_mail;
	mail->pool = pool_alloconly_create("index_mail", 4096);

	mail->ibox = ibox;
	mail->wanted_fields = wanted_fields;
	mail->wanted_headers = wanted_headers;
}

int index_mail_next(struct index_mail *mail, struct mail_index_record *rec)
{
	struct index_mail_data *data = &mail->data;
	int ret, open_mail, parse_header;

	t_push();

	/* close the old one */
	if (data->stream != NULL)
		i_stream_unref(data->stream);

	memset(data, 0, sizeof(*data));
	p_clear(mail->pool);

	mail->mail.has_nuls =
		(rec->index_flags & INDEX_MAIL_FLAG_HAS_NULS) != 0;
	mail->mail.has_no_nuls =
		(rec->index_flags & INDEX_MAIL_FLAG_HAS_NO_NULS) != 0;

	data->rec = rec;
	data->size = (uoff_t)-1;
	data->received_date = data->sent_time = (time_t)-1;

	/* if some wanted fields are cached, get them */
	if (mail->wanted_fields & MAIL_FETCH_MESSAGE_PARTS)
		data->parts = get_cached_parts(mail);
	if (mail->wanted_fields & MAIL_FETCH_IMAP_ENVELOPE)
		data->envelope = get_cached_field(mail, DATA_FIELD_ENVELOPE);
	if (mail->wanted_fields & MAIL_FETCH_IMAP_BODY)
		data->body = get_cached_field(mail, DATA_FIELD_BODY);
	if (mail->wanted_fields & MAIL_FETCH_IMAP_BODYSTRUCTURE) {
		data->bodystructure =
			get_cached_field(mail, DATA_FIELD_BODYSTRUCTURE);
	}
	if (mail->wanted_fields & MAIL_FETCH_SIZE)
		data->size = get_cached_virtual_size(mail);

	/* see if we have to parse the message */
	open_mail = parse_header = FALSE;
	if ((mail->wanted_fields & MAIL_FETCH_MESSAGE_PARTS) &&
	    data->parts == NULL)
		parse_header = TRUE;
	else if ((mail->wanted_fields & (MAIL_FETCH_DATE |
					 MAIL_FETCH_IMAP_ENVELOPE)) &&
		 data->envelope == NULL)
		parse_header = TRUE;
	else if ((mail->wanted_fields & MAIL_FETCH_IMAP_BODYSTRUCTURE) &&
		 data->bodystructure == NULL) {
		if (data->parts == NULL)
			data->parts = get_cached_parts(mail);
		/* FIXME: this isn't helping really.. */
		open_mail = TRUE;
		parse_header = data->parts == NULL;
	} else if ((mail->wanted_fields & MAIL_FETCH_IMAP_BODY) &&
		   data->body == NULL && data->bodystructure == NULL) {
		if (data->parts == NULL)
			data->parts = get_cached_parts(mail);
		open_mail = TRUE;
		parse_header = data->parts == NULL;
	} else if (mail->wanted_fields & (MAIL_FETCH_STREAM_HEADER |
					  MAIL_FETCH_STREAM_BODY))
		open_mail = TRUE;
	else if ((mail->wanted_fields & MAIL_FETCH_SIZE) && data->size == 0)
		open_mail = TRUE;

	if (!parse_header && mail->wanted_headers != NULL) {
		const char *const *tmp;
		enum imap_envelope_field env_field;
		int envelope_headers = FALSE;

		for (tmp = mail->wanted_headers; *tmp != NULL; tmp++) {
			if (imap_envelope_get_field(*tmp, &env_field))
				envelope_headers = TRUE;
			else {
				open_mail = TRUE;
				parse_header = TRUE;
				break;
			}
		}

		if (!parse_header && envelope_headers &&
		    data->envelope == NULL) {
			data->envelope =
				get_cached_field(mail, DATA_FIELD_ENVELOPE);
			if (data->envelope == NULL)
				parse_header = TRUE;
		}
	}

	if (open_mail || parse_header) {
		int deleted;

		data->stream = mail->ibox->index->
			open_mail(mail->ibox->index, data->rec,
				  &data->received_date, &deleted);
		if (data->stream == NULL)
			ret = deleted ? 0 : -1;
		else
			ret = 1;
	} else {
		if ((mail->wanted_fields & MAIL_FETCH_RECEIVED_DATE) &&
		    data->received_date == (time_t)-1) {
			/* check this only after open_mail() */
			data->received_date = get_cached_received_date(mail);
		}

		if (mail->wanted_fields & MAIL_FETCH_DATE)
			data->save_sent_time = TRUE;
		if (mail->wanted_fields & MAIL_FETCH_IMAP_ENVELOPE)
			data->save_envelope = TRUE;

		data->parse_header = parse_header;
		ret = 1;
	}
	t_pop();
	return ret;
}

void index_mail_deinit(struct index_mail *mail)
{
	if (mail->data.stream != NULL) {
		i_stream_unref(mail->data.stream);
		mail->data.stream = NULL;
	}

	pool_unref(mail->pool);
	mail->pool = NULL;
}
