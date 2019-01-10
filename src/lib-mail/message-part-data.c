/* Copyright (c) 2014-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "wildcard-match.h"
#include "array.h"
#include "rfc822-parser.h"
#include "rfc2231-parser.h"
#include "message-address.h"
#include "message-header-parser.h"

#include "message-part-data.h"

const char *message_part_envelope_headers[] = {
	"Date", "Subject", "From", "Sender", "Reply-To",
	"To", "Cc", "Bcc", "In-Reply-To", "Message-ID",
	NULL
};

/*
 *
 */

bool message_part_data_is_plain_7bit(const struct message_part *part)
{
	const struct message_part_data *data = part->data;

	i_assert(data != NULL);
	i_assert(part->parent == NULL);

	/* if content-type is text/xxx we don't have to check any
	   multipart stuff */
	if ((part->flags & MESSAGE_PART_FLAG_TEXT) == 0)
		return FALSE;
	if (part->next != NULL || part->children != NULL)
		return FALSE; /* shouldn't happen normally.. */

	/* must be text/plain */
	if (data->content_subtype != NULL &&
	    strcasecmp(data->content_subtype, "plain") != 0)
		return FALSE;

	/* only allowed parameter is charset=us-ascii, which is also default */
	if (data->content_type_params_count == 0) {
		/* charset defaults to us-ascii */
	} else if (data->content_type_params_count != 1 ||
		   strcasecmp(data->content_type_params[0].name, "charset") != 0 ||
		   strcasecmp(data->content_type_params[0].value,
			      MESSAGE_PART_DEFAULT_CHARSET) != 0)
		return FALSE;

	if (data->content_id != NULL ||
	    data->content_description != NULL)
		return FALSE;

	if (data->content_transfer_encoding != NULL &&
	    strcasecmp(data->content_transfer_encoding, "7bit") != 0)
		return FALSE;

	/* BODYSTRUCTURE checks: */
	if (data->content_md5 != NULL ||
	    data->content_disposition != NULL ||
	    data->content_language != NULL ||
	    data->content_location != NULL)
		return FALSE;

	return TRUE;
}

bool message_part_data_get_filename(const struct message_part *part,
	const char **filename_r)
{
	const struct message_part_data *data = part->data;
	const struct message_part_param *params;
	unsigned int params_count, i;

	i_assert(data != NULL);

	params = data->content_disposition_params;
	params_count = data->content_disposition_params_count;

	if (data->content_disposition != NULL &&
		strcasecmp(data->content_disposition, "attachment") != 0) {
		return FALSE;
	}
	for (i = 0; i < params_count; i++) {
		if (strcasecmp(params[i].name, "filename") == 0 &&
			params[i].value != NULL) {
			*filename_r = params[i].value;
			return TRUE;
		}
	}
	return FALSE;
}

/*
 * Header parsing
 */

/* Message part envelope */

enum envelope_field {
	ENVELOPE_FIELD_DATE = 0,
	ENVELOPE_FIELD_SUBJECT,
	ENVELOPE_FIELD_FROM,
	ENVELOPE_FIELD_SENDER,
	ENVELOPE_FIELD_REPLY_TO,
	ENVELOPE_FIELD_TO,
	ENVELOPE_FIELD_CC,
	ENVELOPE_FIELD_BCC,
	ENVELOPE_FIELD_IN_REPLY_TO,
	ENVELOPE_FIELD_MESSAGE_ID,

	ENVELOPE_FIELD_UNKNOWN
};

static enum envelope_field
envelope_get_field(const char *name)
{
	switch (*name) {
	case 'B':
	case 'b':
		if (strcasecmp(name, "Bcc") == 0)
			return ENVELOPE_FIELD_BCC;
		break;
	case 'C':
	case 'c':
		if (strcasecmp(name, "Cc") == 0)
			return ENVELOPE_FIELD_CC;
		break;
	case 'D':
	case 'd':
		if (strcasecmp(name, "Date") == 0)
			return ENVELOPE_FIELD_DATE;
		break;
	case 'F':
	case 'f':
		if (strcasecmp(name, "From") == 0)
			return ENVELOPE_FIELD_FROM;
		break;
	case 'I':
	case 'i':
		if (strcasecmp(name, "In-reply-to") == 0)
			return ENVELOPE_FIELD_IN_REPLY_TO;
		break;
	case 'M':
	case 'm':
		if (strcasecmp(name, "Message-id") == 0)
			return ENVELOPE_FIELD_MESSAGE_ID;
		break;
	case 'R':
	case 'r':
		if (strcasecmp(name, "Reply-to") == 0)
			return ENVELOPE_FIELD_REPLY_TO;
		break;
	case 'S':
	case 's':
		if (strcasecmp(name, "Subject") == 0)
			return ENVELOPE_FIELD_SUBJECT;
		if (strcasecmp(name, "Sender") == 0)
			return ENVELOPE_FIELD_SENDER;
		break;
	case 'T':
	case 't':
		if (strcasecmp(name, "To") == 0)
			return ENVELOPE_FIELD_TO;
		break;
	}

	return ENVELOPE_FIELD_UNKNOWN;
}

void message_part_envelope_parse_from_header(pool_t pool,
	struct message_part_envelope **data,
	struct message_header_line *hdr)
{
	struct message_part_envelope *d;
	enum envelope_field field;
	struct message_address **addr_p;
	const char **str_p;

	if (*data == NULL) {
		*data = p_new(pool, struct message_part_envelope, 1);
	}

	if (hdr == NULL)
		return;
	field = envelope_get_field(hdr->name);
	if (field == ENVELOPE_FIELD_UNKNOWN)
		return;

	if (hdr->continues) {
		/* wait for full value */
		hdr->use_full_value = TRUE;
		return;
	}

	d = *data;
	addr_p = NULL; str_p = NULL;
	switch (field) {
	case ENVELOPE_FIELD_DATE:
		str_p = &d->date;
		break;
	case ENVELOPE_FIELD_SUBJECT:
		str_p = &d->subject;
		break;
	case ENVELOPE_FIELD_MESSAGE_ID:
		str_p = &d->message_id;
		break;
	case ENVELOPE_FIELD_IN_REPLY_TO:
		str_p = &d->in_reply_to;
		break;

	case ENVELOPE_FIELD_CC:
		addr_p = &d->cc;
		break;
	case ENVELOPE_FIELD_BCC:
		addr_p = &d->bcc;
		break;
	case ENVELOPE_FIELD_FROM:
		addr_p = &d->from;
		break;
	case ENVELOPE_FIELD_SENDER:
		addr_p = &d->sender;
		break;
	case ENVELOPE_FIELD_TO:
		addr_p = &d->to;
		break;
	case ENVELOPE_FIELD_REPLY_TO:
		addr_p = &d->reply_to;
		break;
	case ENVELOPE_FIELD_UNKNOWN:
		i_unreached();
	}

	if (addr_p != NULL) {
		*addr_p = message_address_parse(pool, hdr->full_value,
						hdr->full_value_len,
						UINT_MAX,
						MESSAGE_ADDRESS_PARSE_FLAG_FILL_MISSING);
	} else if (str_p != NULL) {
		*str_p = message_header_strdup(pool, hdr->full_value,
					       hdr->full_value_len);
	}
}

/* Message part data */

static void
parse_mime_parameters(struct rfc822_parser_context *parser,
	pool_t pool, const struct message_part_param **params_r,
	unsigned int *params_count_r)
{
	const char *const *results;
	struct message_part_param *params;
	unsigned int params_count, i;

	rfc2231_parse(parser, &results);

	params_count = str_array_length(results);
	i_assert((params_count % 2) == 0);
	params_count /= 2;

	if (params_count > 0) {
		params = p_new(pool, struct message_part_param, params_count);
		for (i = 0; i < params_count; i++) {
			params[i].name = p_strdup(pool, results[i*2+0]);
			params[i].value = p_strdup(pool, results[i*2+1]);
		}
		*params_r = params;
	}

	*params_count_r = params_count;
}

static void
parse_content_type(struct message_part_data *data,
	pool_t pool, struct message_header_line *hdr)
{
	struct rfc822_parser_context parser;
	string_t *str;
	const char *value;
	unsigned int i;
	int ret;

	rfc822_parser_init(&parser, hdr->full_value, hdr->full_value_len, NULL);
	rfc822_skip_lwsp(&parser);

	str = t_str_new(256);
	ret = rfc822_parse_content_type(&parser, str);

	/* Save content type and subtype */
	value = str_c(str);
	for (i = 0; value[i] != '\0'; i++) {
		if (value[i] == '/') {
			data->content_subtype = p_strdup(pool, value + i+1);
			break;
		}
	}
	str_truncate(str, i);
	data->content_type = p_strdup(pool, str_c(str));
	if (data->content_subtype == NULL) {
		/* The Content-Type is invalid. Don't leave it NULL so that
		   callers can assume that if content_type != NULL,
		   content_subtype != NULL also. */
		data->content_subtype = p_strdup(pool, "");
	}

	if (ret < 0) {
		/* Content-Type is broken, but we wanted to get it as well as
		   we could. Don't try to read the parameters anymore though.

		   We don't completely ignore a broken Content-Type, because
		   then it would be written as text/plain. This would cause a
		   mismatch with the message_part's MESSAGE_PART_FLAG_TEXT. */
		return;
	}

	parse_mime_parameters(&parser, pool,
		&data->content_type_params,
		&data->content_type_params_count);
	rfc822_parser_deinit(&parser);
}

static void
parse_content_transfer_encoding(struct message_part_data *data,
	pool_t pool, struct message_header_line *hdr)
{
	struct rfc822_parser_context parser;
	string_t *str;

	rfc822_parser_init(&parser, hdr->full_value, hdr->full_value_len, NULL);
	rfc822_skip_lwsp(&parser);

	str = t_str_new(256);
	if (rfc822_parse_mime_token(&parser, str) >= 0 &&
	    rfc822_skip_lwsp(&parser) == 0 && str_len(str) > 0) {
		data->content_transfer_encoding =
			p_strdup(pool, str_c(str));
	}
	rfc822_parser_deinit(&parser);
}

static void
parse_content_disposition(struct message_part_data *data,
	pool_t pool, struct message_header_line *hdr)
{
	struct rfc822_parser_context parser;
	string_t *str;

	rfc822_parser_init(&parser, hdr->full_value, hdr->full_value_len, NULL);
	rfc822_skip_lwsp(&parser);

	str = t_str_new(256);
	if (rfc822_parse_mime_token(&parser, str) < 0) {
		rfc822_parser_deinit(&parser);
		return;
	}
	data->content_disposition = p_strdup(pool, str_c(str));

	parse_mime_parameters(&parser, pool,
		&data->content_disposition_params,
		&data->content_disposition_params_count);
	rfc822_parser_deinit(&parser);
}

static void
parse_content_language(struct message_part_data *data,
	pool_t pool, const unsigned char *value, size_t value_len)
{
	struct rfc822_parser_context parser;
	ARRAY_TYPE(const_string) langs;
	string_t *str;

	/* Language-Header = "Content-Language" ":" 1#Language-tag
	   Language-Tag = Primary-tag *( "-" Subtag )
	   Primary-tag = 1*8ALPHA
	   Subtag = 1*8ALPHA */

	rfc822_parser_init(&parser, value, value_len, NULL);

	t_array_init(&langs, 16);
	str = t_str_new(128);

	rfc822_skip_lwsp(&parser);
	while (rfc822_parse_atom(&parser, str) >= 0) {
		const char *lang = p_strdup(pool, str_c(str));

		array_append(&langs, &lang, 1);
		str_truncate(str, 0);

		if (parser.data >= parser.end || *parser.data != ',')
			break;
		parser.data++;
		rfc822_skip_lwsp(&parser);
	}
	rfc822_parser_deinit(&parser);

	if (array_count(&langs) > 0) {
		array_append_zero(&langs);
		data->content_language =
			p_strarray_dup(pool, array_first(&langs));
	}
}

static void
parse_content_header(struct message_part_data *data,
	pool_t pool, struct message_header_line *hdr)
{
	const char *name = hdr->name + strlen("Content-");

	if (hdr->continues) {
		hdr->use_full_value = TRUE;
		return;
	}

	switch (*name) {
	case 'i':
	case 'I':
		if (strcasecmp(name, "ID") == 0 && data->content_id == NULL)
			data->content_id =
				message_header_strdup(pool, hdr->full_value,
						      hdr->full_value_len);
		break;

	case 'm':
	case 'M':
		if (strcasecmp(name, "MD5") == 0 && data->content_md5 == NULL)
			data->content_md5 =
				message_header_strdup(pool, hdr->full_value,
						      hdr->full_value_len);
		break;

	case 't':
	case 'T':
		if (strcasecmp(name, "Type") == 0 && data->content_type == NULL)
			parse_content_type(data, pool, hdr);
		else if (strcasecmp(name, "Transfer-Encoding") == 0 &&
			 data->content_transfer_encoding == NULL)
			parse_content_transfer_encoding(data, pool, hdr);
		break;

	case 'l':
	case 'L':
		if (strcasecmp(name, "Language") == 0 &&
		    data->content_language == NULL) {
			parse_content_language(data, pool,
				hdr->full_value, hdr->full_value_len);
		} else if (strcasecmp(name, "Location") == 0 &&
			   data->content_location == NULL) {
			data->content_location =
				message_header_strdup(pool, hdr->full_value,
						      hdr->full_value_len);
		}
		break;

	case 'd':
	case 'D':
		if (strcasecmp(name, "Description") == 0 &&
		    data->content_description == NULL)
			data->content_description =
				message_header_strdup(pool, hdr->full_value,
						      hdr->full_value_len);
		else if (strcasecmp(name, "Disposition") == 0 &&
			 data->content_disposition_params == NULL)
			parse_content_disposition(data, pool, hdr);
		break;
	}
}

void message_part_data_parse_from_header(pool_t pool,
	struct message_part *part,
	struct message_header_line *hdr)
{
	struct message_part_data *part_data;
	struct message_part_envelope *envelope;
	bool parent_rfc822;

	if (hdr == NULL) {
		if (part->data == NULL) {
			/* no Content-* headers. add an empty context
			   structure anyway. */
			part->data = part_data =
				p_new(pool, struct message_part_data, 1);
		} else if ((part->flags & MESSAGE_PART_FLAG_IS_MIME) == 0) {
			/* If there was no Mime-Version, forget all
			   the Content-stuff */
			part_data = part->data;
			envelope = part_data->envelope;

			i_zero(part_data);
			part_data->envelope = envelope;
		}
		return;
	}

	if (hdr->eoh)
		return;

	parent_rfc822 = part->parent != NULL &&
		(part->parent->flags & MESSAGE_PART_FLAG_MESSAGE_RFC822) != 0;
	if (!parent_rfc822 && strncasecmp(hdr->name, "Content-", 8) != 0)
		return;

	if (part->data == NULL) {
		/* initialize message part data */
		part->data = part_data =
			p_new(pool, struct message_part_data, 1);
	}
	part_data = part->data;

	if (strncasecmp(hdr->name, "Content-", 8) == 0) {
		T_BEGIN {
			parse_content_header(part_data, pool, hdr);
		} T_END;
	}

	if (parent_rfc822) {
		/* message/rfc822, we need the envelope */
		message_part_envelope_parse_from_header(pool, &part_data->envelope, hdr);
	}
}

bool message_part_has_content_types(struct message_part *part,
				    const char *const *types)
{
	struct message_part_data *data = part->data;
	bool ret = TRUE;
	const char *const *ptr;
	const char *content_type;

	i_assert(data != NULL);

	if (data->content_type == NULL)
		return FALSE;
	else if (data->content_subtype == NULL)
		content_type = t_strdup_printf("%s/", data->content_type);
	else
		content_type = t_strdup_printf("%s/%s", data->content_type,
							data->content_subtype);
	for(ptr = types; *ptr != NULL; ptr++) {
		bool exclude = (**ptr == '!');
		if (wildcard_match_icase(content_type, (*ptr)+(exclude?1:0)))
			ret = !exclude;
	}

	return ret;
}

bool message_part_has_parameter(struct message_part *part, const char *parameter,
				bool has_value)
{
	struct message_part_data *data = part->data;

	i_assert(data != NULL);

	for (unsigned int i = 0; i < data->content_disposition_params_count; i++) {
		const struct message_part_param *param =
			&data->content_disposition_params[i];
		if (strcasecmp(param->name, parameter) == 0 &&
		    (!has_value || *param->value != '\0')) {
			return TRUE;
		}
	}
	return FALSE;
}

bool message_part_is_attachment(struct message_part *part,
				const struct message_part_attachment_settings *set)
{
	struct message_part_data *data = part->data;

	i_assert(data != NULL);

	/* see if the content-type is excluded */
	if (set->content_type_filter != NULL &&
	    !message_part_has_content_types(part, set->content_type_filter))
		return FALSE;

	/* accept any attachment, or any inlined attachment with filename,
	   unless inlined ones are excluded */
	if (null_strcasecmp(data->content_disposition, "attachment") == 0 ||
	    (!set->exclude_inlined &&
	     null_strcasecmp(data->content_disposition, "inline") == 0 &&
	     message_part_has_parameter(part, "filename", FALSE)))
		return TRUE;
	return FALSE;
}
