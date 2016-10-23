/* Copyright (c) 2002-2017 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "istream.h"
#include "str.h"
#include "message-parser.h"
#include "rfc822-parser.h"
#include "rfc2231-parser.h"
#include "imap-parser.h"
#include "imap-quote.h"
#include "imap-envelope.h"
#include "imap-bodystructure.h"

#define DEFAULT_CHARSET "us-ascii"

#define EMPTY_BODYSTRUCTURE \
        "(\"text\" \"plain\" (\"charset\" \""DEFAULT_CHARSET"\") NIL NIL \"7bit\" 0 0)"

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
	if (rfc822_parse_mime_token(&parser, str) < 0)
		return;
	data->content_disposition = p_strdup(pool, str_c(str));

	parse_mime_parameters(&parser, pool,
		&data->content_disposition_params,
		&data->content_disposition_params_count);
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

		if (parser.data == parser.end || *parser.data != ',')
			break;
		parser.data++;
		rfc822_skip_lwsp(&parser);
	}

	if (array_count(&langs) > 0) {
		array_append_zero(&langs);
		data->content_language =
			p_strarray_dup(pool, array_idx(&langs, 0));
	}
}

static void
parse_content_header(struct message_part_data *data,
	pool_t pool, struct message_header_line *hdr)
{
	const char *name = hdr->name + strlen("Content-");
	const char *value;

	if (hdr->continues) {
		hdr->use_full_value = TRUE;
		return;
	}

	value = t_strndup(hdr->full_value, hdr->full_value_len);

	switch (*name) {
	case 'i':
	case 'I':
		if (strcasecmp(name, "ID") == 0 && data->content_id == NULL)
			data->content_id = p_strdup(pool, value);
		break;

	case 'm':
	case 'M':
		if (strcasecmp(name, "MD5") == 0 && data->content_md5 == NULL)
			data->content_md5 = p_strdup(pool, value);
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
			data->content_location = p_strdup(pool, value);
		}
		break;

	case 'd':
	case 'D':
		if (strcasecmp(name, "Description") == 0 &&
		    data->content_description == NULL)
			data->content_description = p_strdup(pool, value);
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
	struct message_part_envelope_data *envelope;
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

static void
params_write(const struct message_part_param *params,
	unsigned int params_count, string_t *str,
	bool default_charset)
{
	unsigned int i;
	bool seen_charset;

	if (!default_charset && params_count == 0) {
		str_append(str, "NIL");
		return;
	}
	str_append_c(str, '(');

	seen_charset = FALSE;
	for (i = 0; i < params_count; i++) {
		if (i > 0)
			str_append_c(str, ' ');
		if (default_charset &&
			strcasecmp(params[i].name, "charset") == 0)
			seen_charset = TRUE;
		imap_append_string(str, params[i].name);
		str_append_c(str, ' ');
		imap_append_string(str, params[i].value);
	}
	if (default_charset && !seen_charset) {
		if (i > 0)
			str_append_c(str, ' ');
		str_append(str, "\"charset\" \""DEFAULT_CHARSET"\"");
	}
	str_append_c(str, ')');
}

static void
part_write_bodystructure_siblings(const struct message_part *part,
				  string_t *dest, bool extended)
{
	for (; part != NULL; part = part->next) {
		str_append_c(dest, '(');
		imap_bodystructure_write(part, dest, extended);
		str_append_c(dest, ')');
	}
}

static void
part_write_bodystructure_common(const struct message_part_data *data,
				     string_t *str)
{
	str_append_c(str, ' ');
	if (data->content_disposition == NULL)
		str_append(str, "NIL");
	else {
		str_append_c(str, '(');
		imap_append_string(str, data->content_disposition);

		str_append_c(str, ' ');
		params_write(data->content_disposition_params,
			data->content_disposition_params_count, str, FALSE);

		str_append_c(str, ')');
	}

	str_append_c(str, ' ');
	if (data->content_language == NULL)
		str_append(str, "NIL");
	else {
		const char *const *lang = data->content_language;

		i_assert(*lang != NULL);
		str_append_c(str, '(');
		imap_append_string(str, *lang);
		lang++;
		while (*lang != NULL) {
			str_append_c(str, ' ');
			imap_append_string(str, *lang);
			lang++;
		}
		str_append_c(str, ')');
	}

	str_append_c(str, ' ');
	imap_append_nstring(str, data->content_location);
}

static void part_write_body_multipart(const struct message_part *part,
				      string_t *str, bool extended)
{
	const struct message_part_data *data = part->data;

	i_assert(part->data != NULL);

	if (part->children != NULL)
		part_write_bodystructure_siblings(part->children, str, extended);
	else {
		/* no parts in multipart message,
		   that's not allowed. write a single
		   0-length text/plain structure */
		str_append(str, EMPTY_BODYSTRUCTURE);
	}

	str_append_c(str, ' ');
	if (data->content_subtype != NULL)
		imap_append_string(str, data->content_subtype);
	else
		str_append(str, "\"x-unknown\"");

	if (!extended)
		return;

	/* BODYSTRUCTURE data */

	str_append_c(str, ' ');
	params_write(data->content_type_params,
		data->content_type_params_count, str, FALSE);

	part_write_bodystructure_common(data, str);
}

static void part_write_body(const struct message_part *part,
			    string_t *str, bool extended)
{
	const struct message_part_data *data = part->data;
	bool text;

	i_assert(part->data != NULL);

	if ((part->flags & MESSAGE_PART_FLAG_MESSAGE_RFC822) != 0) {
		str_append(str, "\"message\" \"rfc822\"");
		text = FALSE;
	} else {
		/* "content type" "subtype" */
		if (data->content_type == NULL) {
			text = TRUE;
			str_append(str, "\"text\"");
		} else {
			text = (strcasecmp(data->content_type, "text") == 0);
			imap_append_string(str, data->content_type);
		}
		str_append_c(str, ' ');

		if (data->content_subtype != NULL)
			imap_append_string(str, data->content_subtype);
		else {
			if (text)
				str_append(str, "\"plain\"");
			else
				str_append(str, "\"unknown\"");
		}
	}

	/* ("content type param key" "value" ...) */
	str_append_c(str, ' ');
	params_write(data->content_type_params,
		data->content_type_params_count, str, text);

	str_append_c(str, ' ');
	imap_append_nstring(str, data->content_id);
	str_append_c(str, ' ');
	imap_append_nstring(str, data->content_description);
	str_append_c(str, ' ');
	if (data->content_transfer_encoding != NULL)
		imap_append_string(str, data->content_transfer_encoding);
	else
		str_append(str, "\"7bit\"");
	str_printfa(str, " %"PRIuUOFF_T, part->body_size.virtual_size);

	if (text) {
		/* text/.. contains line count */
		str_printfa(str, " %u", part->body_size.lines);
	} else if ((part->flags & MESSAGE_PART_FLAG_MESSAGE_RFC822) != 0) {
		/* message/rfc822 contains envelope + body + line count */
		const struct message_part_data *child_data;

		i_assert(part->children != NULL);
		i_assert(part->children->next == NULL);

		child_data = part->children->data;

		str_append(str, " (");
		imap_envelope_write_part_data(child_data->envelope, str);
		str_append(str, ") ");

		part_write_bodystructure_siblings(part->children, str, extended);
		str_printfa(str, " %u", part->body_size.lines);
	}

	if (!extended)
		return;

	/* BODYSTRUCTURE data */

	/* "md5" ("content disposition" ("disposition" "params"))
	   ("body" "language" "params") "location" */
	str_append_c(str, ' ');
	imap_append_nstring(str, data->content_md5);
	part_write_bodystructure_common(data, str);
}

bool imap_bodystructure_is_plain_7bit(const struct message_part *part)
{
	const struct message_part_data *data = part->data;

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
	if (data->content_type_params_count > 0 &&
	    (strcasecmp(data->content_type_params[0].name, "charset") != 0 ||
	     strcasecmp(data->content_type_params[0].value, DEFAULT_CHARSET) != 0))
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

void imap_bodystructure_write(const struct message_part *part,
			      string_t *dest, bool extended)
{
	if ((part->flags & MESSAGE_PART_FLAG_MULTIPART) != 0)
		part_write_body_multipart(part, dest, extended);
	else
		part_write_body(part, dest, extended);
}

static int
imap_bodystructure_strlist_parse(const struct imap_arg *arg,
	pool_t pool, const char *const **list_r)
{
	const char *item, **list;
	const struct imap_arg *list_args;
	unsigned int list_count, i;

	if (arg->type == IMAP_ARG_NIL) {
		*list_r = NULL;
		return 0;
	}
	if (imap_arg_get_nstring(arg, &item)) {
		list = p_new(pool, const char *, 2);
		list[0] = p_strdup(pool, item);
	} else {
		if (!imap_arg_get_list_full(arg, &list_args, &list_count))
			return -1;

		list = p_new(pool, const char *, list_count+1);
		for (i = 0; i < list_count; i++) {
			if (!imap_arg_get_nstring(&list_args[i], &item))
				return -1;
			list[i] = p_strdup(pool, item);
		}
	}
	*list_r = list;
	return 0;
}

static int
imap_bodystructure_params_parse(const struct imap_arg *arg,
	pool_t pool, const struct message_part_param **params_r,
	unsigned int *count_r)
{
	struct message_part_param *params;
	const struct imap_arg *list_args;
	unsigned int list_count, params_count, i;

	if (arg->type == IMAP_ARG_NIL) {
		*params_r = NULL;
		return 0;
	}
	if (!imap_arg_get_list_full(arg, &list_args, &list_count))
		return -1;
	if ((list_count % 2) != 0)
		return -1;

	params_count = list_count/2;
	params = p_new(pool, struct message_part_param, params_count+1);
	for (i = 0; i < params_count; i++) {
		const char *name, *value;

		if (!imap_arg_get_nstring(&list_args[i*2+0], &name))
			return -1;
		if (!imap_arg_get_nstring(&list_args[i*2+1], &value))
			return -1;
		params[i].name = p_strdup(pool, name);
		params[i].value = p_strdup(pool, value);
	}
	*params_r = params;
	*count_r = params_count;
	return 0;
}

static int
imap_bodystructure_parse_args_common(struct message_part *part,
				     pool_t pool, const struct imap_arg *args,
				     const char **error_r)
{
	struct message_part_data *data = part->data;
	const struct imap_arg *list_args;

	if (args->type == IMAP_ARG_EOL)
		return 0;
	if (args->type == IMAP_ARG_NIL)
		args++;
	else if (!imap_arg_get_list(args, &list_args)) {
		*error_r = "Invalid content-disposition list";
		return -1;
	} else {
		if (!imap_arg_get_nstring
			(list_args++, &data->content_disposition)) {
			*error_r = "Invalid content-disposition";
			return -1;
		}
		data->content_disposition = p_strdup(pool, data->content_disposition);
		if (imap_bodystructure_params_parse(list_args, pool,
			&data->content_disposition_params,
			&data->content_disposition_params_count) < 0) {
			*error_r = "Invalid content-disposition params";
			return -1;
		}
		args++;
	}
	if (args->type == IMAP_ARG_EOL)
		return 0;
	if (imap_bodystructure_strlist_parse
		(args++, pool, &data->content_language) < 0) {
		*error_r = "Invalid content-language";
		return -1;
	}
	if (args->type == IMAP_ARG_EOL)
		return 0;
	if (!imap_arg_get_nstring
		(args++, &data->content_location)) {
		*error_r = "Invalid content-location";
		return -1;
	}
	data->content_location = p_strdup(pool, data->content_location);
	return 0;
}

static int
imap_bodystructure_parse_args(const struct imap_arg *args, pool_t pool,
			      struct message_part *part,
			      const char **error_r)
{
	struct message_part_data *data;
	struct message_part *child_part;
	const struct imap_arg *list_args;
	const char *value, *content_type, *subtype, *error;
	bool multipart, text, message_rfc822, has_lines;
	unsigned int lines;
	uoff_t vsize;

	i_assert(part->data == NULL);
	part->data = data = p_new(pool, struct message_part_data, 1);

	multipart = FALSE;
	child_part = part->children;
	while (args->type == IMAP_ARG_LIST) {
		if ((part->flags & MESSAGE_PART_FLAG_MULTIPART) == 0 ||
		    child_part == NULL) {
			*error_r = "message_part hierarchy doesn't match BODYSTRUCTURE";
			return -1;
		}

		list_args = imap_arg_as_list(args);
		if (imap_bodystructure_parse_args(list_args, pool,
						  child_part, error_r) < 0)
			return -1;
		child_part = child_part->next;

		multipart = TRUE;
		args++;
	}

	if (multipart) {
		if (child_part != NULL) {
			*error_r = "message_part hierarchy doesn't match BODYSTRUCTURE";
			return -1;
		}
		data->content_type = "multipart";
		if (!imap_arg_get_nstring(args++, &data->content_subtype)) {
			*error_r = "Invalid multipart content-type";
			return -1;
		}
		data->content_subtype = p_strdup(pool, data->content_subtype);
		if (args->type == IMAP_ARG_EOL)
			return 0;
		if (imap_bodystructure_params_parse(args++, pool,
			&data->content_type_params,
			&data->content_type_params_count) < 0) {
			*error_r = "Invalid content params";
			return -1;
		}
		return imap_bodystructure_parse_args_common
			(part, pool, args, error_r);
	}
	if ((part->flags & MESSAGE_PART_FLAG_MULTIPART) != 0) {
		*error_r = "message_part multipart flag doesn't match BODYSTRUCTURE";
		return -1;
	}

	/* "content type" "subtype" */
	if (!imap_arg_get_astring(&args[0], &content_type) ||
	    !imap_arg_get_astring(&args[1], &subtype)) {
		*error_r = "Invalid content-type";
		return -1;
	}
	data->content_type = p_strdup(pool, content_type);
	data->content_subtype = p_strdup(pool, subtype);
	args += 2;

	text = strcasecmp(content_type, "text") == 0;
	message_rfc822 = strcasecmp(content_type, "message") == 0 &&
		strcasecmp(subtype, "rfc822") == 0;

#if 0
	/* Disabled for now. Earlier Dovecot versions handled broken
	   Content-Type headers by writing them as "text" "plain" to
	   BODYSTRUCTURE reply, but the message_part didn't have
	   MESSAGE_PART_FLAG_TEXT. */
	if (text != ((part->flags & MESSAGE_PART_FLAG_TEXT) != 0)) {
		*error_r = "message_part text flag doesn't match BODYSTRUCTURE";
		return -1;
	}
#endif
	if (message_rfc822 != ((part->flags & MESSAGE_PART_FLAG_MESSAGE_RFC822) != 0)) {
		*error_r = "message_part message/rfc822 flag doesn't match BODYSTRUCTURE";
		return -1;
	}

	/* ("content type param key" "value" ...) | NIL */
	if (imap_bodystructure_params_parse(args++, pool,
		&data->content_type_params,
		&data->content_type_params_count) < 0) {
		*error_r = "Invalid content params";
		return -1;
	}

	/* "content id" "content description" "transfer encoding" size */
	if (!imap_arg_get_nstring(args++, &data->content_id)) {
		*error_r = "Invalid content-id";
		return -1;
	}
	if (!imap_arg_get_nstring(args++, &data->content_description)) {
		*error_r = "Invalid content-description";
		return -1;
	}
	if (!imap_arg_get_nstring(args++, &data->content_transfer_encoding)) {
		*error_r = "Invalid content-transfer-encoding";
		return -1;
	}
	data->content_id = p_strdup(pool, data->content_id);
	data->content_description = p_strdup(pool, data->content_description);
	data->content_transfer_encoding =
		p_strdup(pool, data->content_transfer_encoding);
	if (!imap_arg_get_atom(args++, &value) ||
	    str_to_uoff(value, &vsize) < 0) {
		*error_r = "Invalid size field";
		return -1;
	}
	if (vsize != part->body_size.virtual_size) {
		*error_r = "message_part virtual_size doesn't match "
			"size in BODYSTRUCTURE";
		return -1;
	}

	if (text) {
		/* text/xxx - text lines */
		if (!imap_arg_get_atom(args++, &value) ||
		    str_to_uint(value, &lines) < 0) {
			*error_r = "Invalid lines field";
			return -1;
		}
		i_assert(part->children == NULL);
		has_lines = TRUE;
	} else if (message_rfc822) {
		/* message/rfc822 - envelope + bodystructure + text lines */

		i_assert(part->children != NULL &&
			 part->children->next == NULL);

		if (!imap_arg_get_list(&args[1], &list_args)) {
			*error_r = "Child bodystructure list expected";
			return -1;
		}
		if (imap_bodystructure_parse_args
			(list_args, pool, part->children, error_r) < 0)
			return -1;

		if (!imap_arg_get_list(&args[0], &list_args)) {
			*error_r = "Envelope list expected";
			return -1;
		}
		if (!imap_envelope_parse_args(list_args, pool,
			&part->children->data->envelope, &error)) {
			*error_r = t_strdup_printf
				("Invalid envelope list: %s", error);
			return -1;
		}
		args += 2;
		if (!imap_arg_get_atom(args++, &value) ||
		    str_to_uint(value, &lines) < 0) {
			*error_r = "Invalid lines field";
			return -1;
		}
		has_lines = TRUE;
	} else {
		i_assert(part->children == NULL);
		has_lines = FALSE;
	}
	if (has_lines && lines != part->body_size.lines) {
		*error_r = "message_part lines "
			"doesn't match lines in BODYSTRUCTURE";
		return -1;
	}
	if (args->type == IMAP_ARG_EOL)
		return 0;
	if (!imap_arg_get_nstring(args++, &data->content_md5)) {
		*error_r = "Invalid content-md5";
		return -1;
	}
	data->content_md5 = p_strdup(pool, data->content_md5);
	return imap_bodystructure_parse_args_common
		(part, pool, args, error_r);
}

int imap_bodystructure_parse(const char *bodystructure,
	pool_t pool, struct message_part *parts,
	const char **error_r)
{
	struct istream *input;
	struct imap_parser *parser;
	const struct imap_arg *args;
	char *error;
	int ret;

	i_assert(parts != NULL);
	i_assert(parts->next == NULL);

	input = i_stream_create_from_data(bodystructure, strlen(bodystructure));
	(void)i_stream_read(input);

	parser = imap_parser_create(input, NULL, (size_t)-1);
	ret = imap_parser_finish_line(parser, 0,
				      IMAP_PARSE_FLAG_LITERAL_TYPE, &args);
	if (ret < 0) {
		*error_r = t_strdup_printf("IMAP parser failed: %s",
					   imap_parser_get_error(parser, NULL));
	} else if (ret == 0) {
		*error_r = "Empty bodystructure";
		ret = -1;
	} else {
		T_BEGIN {
			ret = imap_bodystructure_parse_args
				(args, pool, parts, error_r);
			if (ret < 0)
				error = i_strdup(*error_r);
		} T_END;

		if (ret < 0) {
			*error_r = t_strdup(error);
			i_free(error);
		}
	}

	imap_parser_unref(&parser);
	i_stream_destroy(&input);
	return ret;
}

static bool str_append_nstring(string_t *str, const struct imap_arg *arg)
{
	const char *cstr;

	if (!imap_arg_get_nstring(arg, &cstr))
		return FALSE;

	switch (arg->type) {
	case IMAP_ARG_NIL:
		str_append(str, "NIL");
		break;
	case IMAP_ARG_ATOM:
		str_append(str, cstr);
		break;
	case IMAP_ARG_STRING:
		str_append_c(str, '"');
		/* NOTE: we're parsing with no-unescape flag,
		   so don't double-escape it here */
		str_append(str, cstr);
		str_append_c(str, '"');
		break;
	case IMAP_ARG_LITERAL: {
		str_printfa(str, "{%"PRIuSIZE_T"}\r\n", strlen(cstr));
		str_append(str, cstr);
		break;
	}
	default:
		i_unreached();
		return FALSE;
	}
	return TRUE;
}

static void
imap_write_envelope_list(const struct imap_arg *args, string_t *str,
	bool toplevel)
{
	const struct imap_arg *children;

	/* don't do any typechecking, just write it out */
	while (!IMAP_ARG_IS_EOL(args)) {
		bool list = FALSE;

		if (!str_append_nstring(str, args)) {
			if (!imap_arg_get_list(args, &children)) {
				/* everything is either nstring or list */
				i_unreached();
			}

			str_append_c(str, '(');
			imap_write_envelope_list(children, str, FALSE);
			str_append_c(str, ')');

			list = TRUE;
		}
		args++;

		if ((toplevel || !list) && !IMAP_ARG_IS_EOL(args))
			str_append_c(str, ' ');
	}
}

static void
imap_write_envelope(const struct imap_arg *args, string_t *str)
{
	imap_write_envelope_list(args, str, TRUE);
}

static int imap_parse_bodystructure_args(const struct imap_arg *args,
					 string_t *str, const char **error_r)
{
	const struct imap_arg *subargs;
	const struct imap_arg *list_args;
	const char *value, *content_type, *subtype;
	bool multipart, text, message_rfc822;
	int i;

	multipart = FALSE;
	while (args->type == IMAP_ARG_LIST) {
		str_append_c(str, '(');
		list_args = imap_arg_as_list(args);
		if (imap_parse_bodystructure_args(list_args, str, error_r) < 0)
			return -1;
		str_append_c(str, ')');

		multipart = TRUE;
		args++;
	}

	if (multipart) {
		/* next is subtype of Content-Type. rest is skipped. */
		str_append_c(str, ' ');
		if (!str_append_nstring(str, args)) {
			*error_r = "Invalid multipart content-type";
			return -1;
		}
		return 0;
	}

	/* "content type" "subtype" */
	if (!imap_arg_get_astring(&args[0], &content_type) ||
	    !imap_arg_get_astring(&args[1], &subtype)) {
		*error_r = "Invalid content-type";
		return -1;
	}

	if (!str_append_nstring(str, &args[0]))
		i_unreached();
	str_append_c(str, ' ');
	if (!str_append_nstring(str, &args[1]))
		i_unreached();

	text = strcasecmp(content_type, "text") == 0;
	message_rfc822 = strcasecmp(content_type, "message") == 0 &&
		strcasecmp(subtype, "rfc822") == 0;

	args += 2;

	/* ("content type param key" "value" ...) | NIL */
	if (imap_arg_get_list(args, &subargs)) {
		str_append(str, " (");
		while (!IMAP_ARG_IS_EOL(subargs)) {
			if (!str_append_nstring(str, &subargs[0])) {
				*error_r = "Invalid content param key";
				return -1;
			}
			str_append_c(str, ' ');
			if (!str_append_nstring(str, &subargs[1])) {
				*error_r = "Invalid content param value";
				return -1;
			}

			subargs += 2;
			if (IMAP_ARG_IS_EOL(subargs))
				break;
			str_append_c(str, ' ');
		}
		str_append(str, ")");
	} else if (args->type == IMAP_ARG_NIL) {
		str_append(str, " NIL");
	} else {
		*error_r = "list/NIL expected";
		return -1;
	}
	args++;

	/* "content id" "content description" "transfer encoding" size */
	for (i = 0; i < 4; i++, args++) {
		str_append_c(str, ' ');

		if (!str_append_nstring(str, args)) {
			*error_r = "nstring expected";
			return -1;
		}
	}

	if (text) {
		/* text/xxx - text lines */
		if (!imap_arg_get_atom(args, &value)) {
			*error_r = "Text lines expected";
			return -1;
		}

		str_append_c(str, ' ');
		str_append(str, value);
	} else if (message_rfc822) {
		/* message/rfc822 - envelope + bodystructure + text lines */
		str_append_c(str, ' ');

		if (!imap_arg_get_list(&args[0], &list_args)) {
			*error_r = "Envelope list expected";
			return -1;
		}
		str_append_c(str, '(');
		imap_write_envelope(list_args, str);
		str_append(str, ") (");

		if (!imap_arg_get_list(&args[1], &list_args)) {
			*error_r = "Child bodystructure list expected";
			return -1;
		}
		if (imap_parse_bodystructure_args(list_args, str, error_r) < 0)
			return -1;

		str_append(str, ") ");
		if (!imap_arg_get_atom(&args[2], &value)) {
			*error_r = "Text lines expected";
			return -1;
		}
		str_append(str, value);
	}
	return 0;
}

int imap_body_parse_from_bodystructure(const char *bodystructure,
				       string_t *dest, const char **error_r)
{
	struct istream *input;
	struct imap_parser *parser;
	const struct imap_arg *args;
	int ret;

	input = i_stream_create_from_data(bodystructure, strlen(bodystructure));
	(void)i_stream_read(input);

	parser = imap_parser_create(input, NULL, (size_t)-1);
	ret = imap_parser_finish_line(parser, 0, IMAP_PARSE_FLAG_NO_UNESCAPE |
				      IMAP_PARSE_FLAG_LITERAL_TYPE, &args);
	if (ret < 0) {
		*error_r = t_strdup_printf("IMAP parser failed: %s",
					   imap_parser_get_error(parser, NULL));
	} else if (ret == 0) {
		*error_r = "Empty bodystructure";
		ret = -1;
	} else {
		ret = imap_parse_bodystructure_args(args, dest, error_r);
	}

	imap_parser_unref(&parser);
	i_stream_destroy(&input);
	return ret;
}
