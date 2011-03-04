/* Copyright (c) 2002-2011 Dovecot authors, see the included COPYING file */

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

#define DEFAULT_CHARSET \
	"\"charset\" \"us-ascii\""

#define EMPTY_BODYSTRUCTURE \
        "(\"text\" \"plain\" ("DEFAULT_CHARSET") NIL NIL \"7bit\" 0 0)"

struct message_part_body_data {
	pool_t pool;
	const char *content_type, *content_subtype;
	const char *content_type_params;
	const char *content_transfer_encoding;
	const char *content_id;
	const char *content_description;
	const char *content_disposition;
	const char *content_disposition_params;
	const char *content_md5;
	const char *content_language;
	const char *content_location;

	struct message_part_envelope_data *envelope;
};

static void parse_content_type(struct message_part_body_data *data,
			       struct message_header_line *hdr)
{
	struct rfc822_parser_context parser;
	const char *value, *const *results;
	string_t *str;
	unsigned int i;
	bool charset_found = FALSE;

	rfc822_parser_init(&parser, hdr->full_value, hdr->full_value_len, NULL);
	(void)rfc822_skip_lwsp(&parser);

	str = t_str_new(256);
	if (rfc822_parse_content_type(&parser, str) < 0)
		return;

	/* Save content type and subtype */
	value = str_c(str);
	for (i = 0; value[i] != '\0'; i++) {
		if (value[i] == '/') {
			data->content_subtype =
				imap_quote(data->pool, str_data(str) + i + 1,
					   str_len(str) - (i + 1), TRUE);
			break;
		}
	}
	data->content_type = imap_quote(data->pool, str_data(str), i, TRUE);

	/* parse parameters and save them */
	str_truncate(str, 0);
	(void)rfc2231_parse(&parser, &results);
	for (; *results != NULL; results += 2) {
		if (strcasecmp(results[0], "charset") == 0)
			charset_found = TRUE;

		str_append_c(str, ' ');
		imap_quote_append_string(str, results[0], TRUE);
		str_append_c(str, ' ');
		imap_quote_append_string(str, results[1], TRUE);
	}

	if (!charset_found &&
	    strcasecmp(data->content_type, "\"text\"") == 0) {
		/* set a default charset */
		str_append_c(str, ' ');
		str_append(str, DEFAULT_CHARSET);
	}
	if (str_len(str) > 0) {
		data->content_type_params =
			p_strdup(data->pool, str_c(str) + 1);
	}
}

static void parse_content_transfer_encoding(struct message_part_body_data *data,
					    struct message_header_line *hdr)
{
	struct rfc822_parser_context parser;
	string_t *str;

	rfc822_parser_init(&parser, hdr->full_value, hdr->full_value_len, NULL);
	(void)rfc822_skip_lwsp(&parser);

	str = t_str_new(256);
	if (rfc822_parse_mime_token(&parser, str) >= 0) {
		data->content_transfer_encoding =
			imap_quote(data->pool, str_data(str),
				   str_len(str), TRUE);
	}
}

static void parse_content_disposition(struct message_part_body_data *data,
				      struct message_header_line *hdr)
{
	struct rfc822_parser_context parser;
	const char *const *results;
	string_t *str;

	rfc822_parser_init(&parser, hdr->full_value, hdr->full_value_len, NULL);
	(void)rfc822_skip_lwsp(&parser);

	str = t_str_new(256);
	if (rfc822_parse_mime_token(&parser, str) < 0)
		return;
	data->content_disposition =
		imap_quote(data->pool, str_data(str), str_len(str), TRUE);

	/* parse parameters and save them */
	str_truncate(str, 0);
	(void)rfc2231_parse(&parser, &results);
	for (; *results != NULL; results += 2) {
		str_append_c(str, ' ');
		imap_quote_append_string(str, results[0], TRUE);
		str_append_c(str, ' ');
		imap_quote_append_string(str, results[1], TRUE);
	}
	if (str_len(str) > 0) {
		data->content_disposition_params =
			p_strdup(data->pool, str_c(str) + 1);
	}
}

static void parse_content_language(const unsigned char *value, size_t value_len,
				   struct message_part_body_data *data)
{
	struct rfc822_parser_context parser;
	string_t *str;

	/* Language-Header = "Content-Language" ":" 1#Language-tag
	   Language-Tag = Primary-tag *( "-" Subtag )
	   Primary-tag = 1*8ALPHA
	   Subtag = 1*8ALPHA */

	rfc822_parser_init(&parser, value, value_len, NULL);

	str = t_str_new(128);
	str_append_c(str, '"');

	(void)rfc822_skip_lwsp(&parser);
	while (rfc822_parse_atom(&parser, str) >= 0) {
		str_append(str, "\" \"");

		if (parser.data == parser.end || *parser.data != ',')
			break;
		parser.data++;
		(void)rfc822_skip_lwsp(&parser);
	}

	if (str_len(str) > 1) {
		str_truncate(str, str_len(str) - 2);
		data->content_language = p_strdup(data->pool, str_c(str));
	}
}

static void parse_content_header(struct message_part_body_data *d,
				 struct message_header_line *hdr,
				 pool_t pool)
{
	const char *name = hdr->name + strlen("Content-");
	const unsigned char *value;
	size_t value_len;

	if (hdr->continues) {
		hdr->use_full_value = TRUE;
		return;
	}

	value = hdr->full_value;
	value_len = hdr->full_value_len;

	switch (*name) {
	case 'i':
	case 'I':
		if (strcasecmp(name, "ID") == 0 && d->content_id == NULL) {
			d->content_id =
				imap_quote(pool, value, value_len, TRUE);
		}
		break;

	case 'm':
	case 'M':
		if (strcasecmp(name, "MD5") == 0 && d->content_md5 == NULL) {
			d->content_md5 =
				imap_quote(pool, value, value_len, TRUE);
		}
		break;

	case 't':
	case 'T':
		if (strcasecmp(name, "Type") == 0 && d->content_type == NULL)
			parse_content_type(d, hdr);
		else if (strcasecmp(name, "Transfer-Encoding") == 0 &&
			 d->content_transfer_encoding == NULL)
			parse_content_transfer_encoding(d, hdr);
		break;

	case 'l':
	case 'L':
		if (strcasecmp(name, "Language") == 0 &&
		    d->content_language == NULL)
			parse_content_language(value, value_len, d);
		else if (strcasecmp(name, "Location") == 0 &&
			 d->content_location == NULL) {
			d->content_location =
				imap_quote(pool, value, value_len, TRUE);
		}
		break;

	case 'd':
	case 'D':
		if (strcasecmp(name, "Description") == 0 &&
		    d->content_description == NULL) {
			d->content_description =
				imap_quote(pool, value, value_len, TRUE);
		} else if (strcasecmp(name, "Disposition") == 0 &&
			   d->content_disposition_params == NULL) {
			parse_content_disposition(d, hdr);
		}
		break;
	}
}

void imap_bodystructure_parse_header(pool_t pool, struct message_part *part,
				     struct message_header_line *hdr)
{
	struct message_part_body_data *part_data;
	struct message_part_envelope_data *envelope;
	bool parent_rfc822;

	if (hdr == NULL) {
		if (part->context == NULL) {
			/* no Content-* headers. add an empty context
			   structure anyway. */
			part->context = part_data =
				p_new(pool, struct message_part_body_data, 1);
			part_data->pool = pool;
		} else if ((part->flags & MESSAGE_PART_FLAG_IS_MIME) == 0) {
			/* If there was no Mime-Version, forget all
			   the Content-stuff */
			part_data = part->context;
			envelope = part_data->envelope;

			memset(part_data, 0, sizeof(*part_data));
			part_data->pool = pool;
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

	if (part->context == NULL) {
		/* initialize message part data */
		part->context = part_data =
			p_new(pool, struct message_part_body_data, 1);
		part_data->pool = pool;
	}
	part_data = part->context;

	if (strncasecmp(hdr->name, "Content-", 8) == 0) {
		T_BEGIN {
			parse_content_header(part_data, hdr, pool);
		} T_END;
	}

	if (parent_rfc822) {
		/* message/rfc822, we need the envelope */
		imap_envelope_parse_header(pool, &part_data->envelope, hdr);
	}
}

static void part_write_body_multipart(const struct message_part *part,
				      string_t *str, bool extended)
{
	struct message_part_body_data *data = part->context;

	if (part->children != NULL)
		imap_bodystructure_write(part->children, str, extended);
	else {
		/* no parts in multipart message,
		   that's not allowed. write a single
		   0-length text/plain structure */
		str_append(str, EMPTY_BODYSTRUCTURE);
	}

	str_append_c(str, ' ');
	if (data->content_subtype != NULL)
		str_append(str, data->content_subtype);
	else
		str_append(str, "\"x-unknown\"");

	if (!extended)
		return;

	/* BODYSTRUCTURE data */
	str_append_c(str, ' ');
	if (data->content_type_params == NULL)
		str_append(str, "NIL");
	else {
		str_append_c(str, '(');
		str_append(str, data->content_type_params);
		str_append_c(str, ')');
	}

	str_append_c(str, ' ');
	if (data->content_disposition == NULL)
		str_append(str, "NIL");
	else {
		str_append_c(str, '(');
		str_append(str, data->content_disposition);
		str_append_c(str, ' ');

		if (data->content_disposition_params == NULL)
			str_append(str, "NIL");
		else {
			str_append_c(str, '(');
			str_append(str, data->content_disposition_params);
			str_append_c(str, ')');
		}
		str_append_c(str, ')');
	}

	str_append_c(str, ' ');
	if (data->content_language == NULL)
		str_append(str, "NIL");
	else {
		str_append_c(str, '(');
		str_append(str, data->content_language);
		str_append_c(str, ')');
	}

	str_append_c(str, ' ');
	if (data->content_location == NULL)
		str_append(str, "NIL");
	else
		str_append(str, data->content_location);
}

static void part_write_body(const struct message_part *part,
			    string_t *str, bool extended)
{
	struct message_part_body_data *data = part->context;
	bool text;

	if (part->flags & MESSAGE_PART_FLAG_MESSAGE_RFC822) {
		str_append(str, "\"message\" \"rfc822\"");
		text = FALSE;
	} else {
		/* "content type" "subtype" */
		text = data->content_type == NULL ||
			strcasecmp(data->content_type, "\"text\"") == 0;
		str_append(str, NVL(data->content_type, "\"text\""));
		str_append_c(str, ' ');

		if (data->content_subtype != NULL)
			str_append(str, data->content_subtype);
		else {
			if (text)
				str_append(str, "\"plain\"");
			else
				str_append(str, "\"unknown\"");

		}
	}

	/* ("content type param key" "value" ...) */
	str_append_c(str, ' ');
	if (data->content_type_params == NULL) {
		if (!text)
			str_append(str, "NIL");
		else
			str_append(str, "("DEFAULT_CHARSET")");
	} else {
		str_append_c(str, '(');
		str_append(str, data->content_type_params);
		str_append_c(str, ')');
	}

	str_printfa(str, " %s %s %s %"PRIuUOFF_T,
		    NVL(data->content_id, "NIL"),
		    NVL(data->content_description, "NIL"),
		    NVL(data->content_transfer_encoding, "\"7bit\""),
		    part->body_size.virtual_size);

	if (text) {
		/* text/.. contains line count */
		str_printfa(str, " %u", part->body_size.lines);
	} else if (part->flags & MESSAGE_PART_FLAG_MESSAGE_RFC822) {
		/* message/rfc822 contains envelope + body + line count */
		struct message_part_body_data *child_data;
                struct message_part_envelope_data *env_data;

		i_assert(part->children != NULL);
		i_assert(part->children->next == NULL);

                child_data = part->children->context;
		env_data = child_data->envelope;

		str_append(str, " (");
		imap_envelope_write_part_data(env_data, str);
		str_append(str, ") ");

		imap_bodystructure_write(part->children, str, extended);
		str_printfa(str, " %u", part->body_size.lines);
	}

	if (!extended)
		return;

	/* BODYSTRUCTURE data */

	/* "md5" ("content disposition" ("disposition" "params"))
	   ("body" "language" "params") "location" */
	str_append_c(str, ' ');
	str_append(str, NVL(data->content_md5, "NIL"));

	str_append_c(str, ' ');
	if (data->content_disposition == NULL)
		str_append(str, "NIL");
	else {
		str_append_c(str, '(');
		str_append(str, data->content_disposition);
		str_append_c(str, ' ');

		if (data->content_disposition_params == NULL)
			str_append(str, "NIL");
		else {
			str_append_c(str, '(');
			str_append(str, data->content_disposition_params);
			str_append_c(str, ')');
		}

		str_append_c(str, ')');
	}

	str_append_c(str, ' ');
	if (data->content_language == NULL)
		str_append(str, "NIL");
	else {
		str_append_c(str, '(');
		str_append(str, data->content_language);
		str_append_c(str, ')');
	}

	str_append_c(str, ' ');
	if (data->content_location == NULL)
		str_append(str, "NIL");
	else
		str_append(str, data->content_location);
}

bool imap_bodystructure_is_plain_7bit(const struct message_part *part)
{
	const struct message_part_body_data *data = part->context;

	i_assert(part->parent == NULL);

	/* if content-type is text/xxx we don't have to check any
	   multipart stuff */
	if ((part->flags & MESSAGE_PART_FLAG_TEXT) == 0)
		return FALSE;
	if (part->next != NULL || part->children != NULL)
		return FALSE; /* shouldn't happen normally.. */

	/* must be text/plain */
	if (data->content_subtype != NULL &&
	    strcasecmp(data->content_subtype, "\"plain\"") != 0)
		return FALSE;

	/* only allowed parameter is charset=us-ascii, which is also default */
	if (data->content_type_params != NULL &&
	    strcasecmp(data->content_type_params, DEFAULT_CHARSET) != 0)
		return FALSE;

	if (data->content_id != NULL ||
	    data->content_description != NULL)
		return FALSE;

	if (data->content_transfer_encoding != NULL &&
	    strcasecmp(data->content_transfer_encoding, "\"7bit\"") != 0)
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
	i_assert(part->parent != NULL || part->next == NULL);

	while (part != NULL) {
		if (part->parent != NULL)
			str_append_c(dest, '(');

		if (part->flags & MESSAGE_PART_FLAG_MULTIPART)
			part_write_body_multipart(part, dest, extended);
		else
			part_write_body(part, dest, extended);

		if (part->parent != NULL)
			str_append_c(dest, ')');

		part = part->next;
	}
}

static bool str_append_imap_arg(string_t *str, const struct imap_arg *arg)
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

static bool imap_write_list(const struct imap_arg *args, string_t *str)
{
	const struct imap_arg *children;

	/* don't do any typechecking, just write it out */
	str_append_c(str, '(');
	while (!IMAP_ARG_IS_EOL(args)) {
		if (!str_append_imap_arg(str, args)) {
			if (!imap_arg_get_list(args, &children))
				return FALSE;

			if (!imap_write_list(children, str))
				return FALSE;
		}
		args++;

		if (!IMAP_ARG_IS_EOL(args))
			str_append_c(str, ' ');
	}
	str_append_c(str, ')');
	return TRUE;
}

static bool imap_parse_bodystructure_args(const struct imap_arg *args,
					  string_t *str)
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
		if (!imap_parse_bodystructure_args(list_args, str))
			return FALSE;
		str_append_c(str, ')');

		multipart = TRUE;
		args++;
	}

	if (multipart) {
		/* next is subtype of Content-Type. rest is skipped. */
		str_append_c(str, ' ');
		return str_append_imap_arg(str, args);
	}

	/* "content type" "subtype" */
	if (!imap_arg_get_astring(&args[0], &content_type) ||
	    !imap_arg_get_astring(&args[1], &subtype))
		return FALSE;

	if (!str_append_imap_arg(str, &args[0]))
		return FALSE;
	str_append_c(str, ' ');
	if (!str_append_imap_arg(str, &args[1]))
		return FALSE;

	text = strcasecmp(content_type, "text") == 0;
	message_rfc822 = strcasecmp(content_type, "message") == 0 &&
		strcasecmp(subtype, "rfc822") == 0;

	args += 2;

	/* ("content type param key" "value" ...) | NIL */
	if (imap_arg_get_list(args, &subargs)) {
		str_append(str, " (");
		while (!IMAP_ARG_IS_EOL(subargs)) {
			if (!str_append_imap_arg(str, &subargs[0]))
				return FALSE;
			str_append_c(str, ' ');
			if (!str_append_imap_arg(str, &subargs[1]))
				return FALSE;

			subargs += 2;
			if (IMAP_ARG_IS_EOL(subargs))
				break;
			str_append_c(str, ' ');
		}
		str_append(str, ")");
	} else if (args->type == IMAP_ARG_NIL) {
		str_append(str, " NIL");
	} else {
		return FALSE;
	}
	args++;

	/* "content id" "content description" "transfer encoding" size */
	for (i = 0; i < 4; i++, args++) {
		str_append_c(str, ' ');

		if (!str_append_imap_arg(str, args))
			return FALSE;
	}

	if (text) {
		/* text/xxx - text lines */
		if (!imap_arg_get_atom(args, &value))
			return FALSE;

		str_append_c(str, ' ');
		str_append(str, value);
	} else if (message_rfc822) {
		/* message/rfc822 - envelope + bodystructure + text lines */
		str_append_c(str, ' ');

		if (!imap_arg_get_list(&args[0], &list_args))
			return FALSE;
		if (!imap_write_list(list_args, str))
			return FALSE;

		str_append(str, " (");

		if (!imap_arg_get_list(&args[1], &list_args))
			return FALSE;
		if (!imap_parse_bodystructure_args(list_args, str))
			return FALSE;

		str_append(str, ") ");
		if (!imap_arg_get_atom(&args[2], &value))
			return FALSE;
		str_append(str, value);
	}

	return TRUE;
}

bool imap_body_parse_from_bodystructure(const char *bodystructure,
					string_t *dest)
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
	ret = ret > 0 && imap_parse_bodystructure_args(args, dest);

	if (!ret)
		i_error("Error parsing IMAP bodystructure: %s", bodystructure);

	imap_parser_destroy(&parser);
	i_stream_destroy(&input);
	return ret;
}
