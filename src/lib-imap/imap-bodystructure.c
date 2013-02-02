/* Copyright (c) 2002-2013 Dovecot authors, see the included COPYING file */

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

#define NVL(str, nullstr) ((str) != NULL ? (str) : (nullstr))

static char *imap_get_string(pool_t pool, const char *value)
{
	string_t *str = t_str_new(64);

	imap_append_string(str, value);
	return p_strdup(pool, str_c(str));
}

static void parse_content_type(struct message_part_body_data *data,
			       struct message_header_line *hdr)
{
	struct rfc822_parser_context parser;
	const char *value, *const *results;
	string_t *str;
	unsigned int i;
	bool charset_found = FALSE;

	rfc822_parser_init(&parser, hdr->full_value, hdr->full_value_len, NULL);
	rfc822_skip_lwsp(&parser);

	str = t_str_new(256);
	if (rfc822_parse_content_type(&parser, str) < 0)
		return;

	/* Save content type and subtype */
	value = str_c(str);
	for (i = 0; value[i] != '\0'; i++) {
		if (value[i] == '/') {
			data->content_subtype =
				imap_get_string(data->pool, value + i+1);
			break;
		}
	}
	str_truncate(str, i);
	data->content_type = imap_get_string(data->pool, str_c(str));

	/* parse parameters and save them */
	str_truncate(str, 0);
	rfc2231_parse(&parser, &results);
	for (; *results != NULL; results += 2) {
		if (strcasecmp(results[0], "charset") == 0)
			charset_found = TRUE;

		str_append_c(str, ' ');
		imap_append_string(str, results[0]);
		str_append_c(str, ' ');
		imap_append_string(str, results[1]);
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
	rfc822_skip_lwsp(&parser);

	str = t_str_new(256);
	if (rfc822_parse_mime_token(&parser, str) >= 0) {
		data->content_transfer_encoding =
			imap_get_string(data->pool, str_c(str));
	}
}

static void parse_content_disposition(struct message_part_body_data *data,
				      struct message_header_line *hdr)
{
	struct rfc822_parser_context parser;
	const char *const *results;
	string_t *str;

	rfc822_parser_init(&parser, hdr->full_value, hdr->full_value_len, NULL);
	rfc822_skip_lwsp(&parser);

	str = t_str_new(256);
	if (rfc822_parse_mime_token(&parser, str) < 0)
		return;
	data->content_disposition = imap_get_string(data->pool, str_c(str));

	/* parse parameters and save them */
	str_truncate(str, 0);
	rfc2231_parse(&parser, &results);
	for (; *results != NULL; results += 2) {
		str_append_c(str, ' ');
		imap_append_string(str, results[0]);
		str_append_c(str, ' ');
		imap_append_string(str, results[1]);
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

	rfc822_skip_lwsp(&parser);
	while (rfc822_parse_atom(&parser, str) >= 0) {
		str_append(str, "\" \"");

		if (parser.data == parser.end || *parser.data != ',')
			break;
		parser.data++;
		rfc822_skip_lwsp(&parser);
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
	const char *value;

	if (hdr->continues) {
		hdr->use_full_value = TRUE;
		return;
	}

	value = t_strndup(hdr->full_value, hdr->full_value_len);

	switch (*name) {
	case 'i':
	case 'I':
		if (strcasecmp(name, "ID") == 0 && d->content_id == NULL)
			d->content_id = imap_get_string(pool, value);
		break;

	case 'm':
	case 'M':
		if (strcasecmp(name, "MD5") == 0 && d->content_md5 == NULL)
			d->content_md5 = imap_get_string(pool, value);
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
		    d->content_language == NULL) {
			parse_content_language(hdr->full_value,
					       hdr->full_value_len, d);
		} else if (strcasecmp(name, "Location") == 0 &&
			   d->content_location == NULL) {
			d->content_location = imap_get_string(pool, value);
		}
		break;

	case 'd':
	case 'D':
		if (strcasecmp(name, "Description") == 0 &&
		    d->content_description == NULL)
			d->content_description = imap_get_string(pool, value);
		else if (strcasecmp(name, "Disposition") == 0 &&
			 d->content_disposition_params == NULL)
			parse_content_disposition(d, hdr);
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

static void
imap_bodystructure_write_siblings(const struct message_part *part,
				  string_t *dest, bool extended)
{
	for (; part != NULL; part = part->next) {
		str_append_c(dest, '(');
		imap_bodystructure_write(part, dest, extended);
		str_append_c(dest, ')');
	}
}

static void
part_write_bodystructure_data_common(struct message_part_body_data *data,
				     string_t *str)
{
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
	str_append(str, NVL(data->content_location, "NIL"));
}

static void part_write_body_multipart(const struct message_part *part,
				      string_t *str, bool extended)
{
	struct message_part_body_data *data = part->context;

	if (part->children != NULL)
		imap_bodystructure_write_siblings(part->children, str, extended);
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

	part_write_bodystructure_data_common(data, str);
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

		i_assert(part->children != NULL);
		i_assert(part->children->next == NULL);

                child_data = part->children->context;

		str_append(str, " (");
		if (child_data->envelope_str != NULL)
			str_append(str, child_data->envelope_str);
		else
			imap_envelope_write_part_data(child_data->envelope, str);
		str_append(str, ") ");

		imap_bodystructure_write_siblings(part->children, str, extended);
		str_printfa(str, " %u", part->body_size.lines);
	}

	if (!extended)
		return;

	/* BODYSTRUCTURE data */

	/* "md5" ("content disposition" ("disposition" "params"))
	   ("body" "language" "params") "location" */
	str_append_c(str, ' ');
	str_append(str, NVL(data->content_md5, "NIL"));
	part_write_bodystructure_data_common(data, str);
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
	if (part->flags & MESSAGE_PART_FLAG_MULTIPART)
		part_write_body_multipart(part, dest, extended);
	else
		part_write_body(part, dest, extended);
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

static bool
get_nstring(const struct imap_arg *arg, pool_t pool, string_t *tmpstr,
	    const char **value_r)
{
	if (arg->type == IMAP_ARG_NIL) {
		*value_r = NULL;
		return TRUE;
	}

	str_truncate(tmpstr, 0);
	if (!str_append_nstring(tmpstr, arg))
		return FALSE;
	*value_r = p_strdup(pool, str_c(tmpstr));
	return TRUE;
}

static void imap_write_list(const struct imap_arg *args, string_t *str)
{
	const struct imap_arg *children;

	/* don't do any typechecking, just write it out */
	while (!IMAP_ARG_IS_EOL(args)) {
		if (!str_append_nstring(str, args)) {
			if (!imap_arg_get_list(args, &children)) {
				/* everything is either nstring or list */
				i_unreached();
			}

			str_append_c(str, '(');
			imap_write_list(children, str);
			str_append_c(str, ')');
		}
		args++;

		if (!IMAP_ARG_IS_EOL(args))
			str_append_c(str, ' ');
	}
}

static int imap_write_nstring_list(const struct imap_arg *args, string_t *str)
{
	str_truncate(str, 0);
	while (!IMAP_ARG_IS_EOL(args)) {
		if (!str_append_nstring(str, &args[0]))
			return -1;
		args++;
		if (IMAP_ARG_IS_EOL(args))
			break;
		str_append_c(str, ' ');
	}
	return 0;
}

static int imap_write_params(const struct imap_arg *arg, pool_t pool,
			     string_t *tmpstr, unsigned int divisible,
			     const char **value_r)
{
	const struct imap_arg *list_args;
	unsigned int list_count;

	if (arg->type == IMAP_ARG_NIL) {
		*value_r = NULL;
		return 0;
	}
	if (!imap_arg_get_list_full(arg, &list_args, &list_count))
		return -1;
	if ((list_count % divisible) != 0)
		return -1;

	if (imap_write_nstring_list(list_args, tmpstr) < 0)
		return -1;
	*value_r = p_strdup(pool, str_c(tmpstr));
	return 0;
}

static int
imap_bodystructure_parse_lines(const struct imap_arg *arg,
			       const struct message_part *part,
			       const char **error_r)
{
	const char *value;
	unsigned int lines;
	
	if (!imap_arg_get_atom(arg, &value) ||
	    str_to_uint(value, &lines) < 0) {
		*error_r = "Invalid lines field";
		return -1;
	}
	if (lines != part->body_size.lines) {
		*error_r = "message_part lines doesn't match lines in BODYSTRUCTURE";
		return -1;
	}
	return 0;
}

static int
imap_bodystructure_parse_args_common(struct message_part_body_data *data,
				     pool_t pool, string_t *tmpstr,
				     const struct imap_arg *args,
				     const char **error_r)
{
	const struct imap_arg *list_args;

	if (args->type == IMAP_ARG_NIL)
		args++;
	else if (!imap_arg_get_list(args, &list_args)) {
		*error_r = "Invalid content-disposition list";
		return -1;
	} else {
		if (!get_nstring(list_args++, pool, tmpstr,
				 &data->content_disposition)) {
			*error_r = "Invalid content-disposition";
			return -1;
		}
		if (imap_write_params(list_args, pool, tmpstr, 2,
				      &data->content_disposition_params) < 0) {
			*error_r = "Invalid content-disposition params";
			return -1;
		}
		args++;
	}
	if (imap_write_params(args++, pool, tmpstr, 1,
			      &data->content_language) < 0) {
		*error_r = "Invalid content-language";
		return -1;
	}
	if (!get_nstring(args++, pool, tmpstr, &data->content_location)) {
		*error_r = "Invalid content-location";
		return -1;
	}
	return 0;
}

static int
imap_bodystructure_parse_args(const struct imap_arg *args, pool_t pool,
			      struct message_part *part, string_t *tmpstr,
			      const char **error_r)
{
	struct message_part_body_data *data;
	struct message_part *child_part;
	const struct imap_arg *list_args;
	const char *value, *content_type, *subtype;
	uoff_t vsize;
	bool multipart, text, message_rfc822;

	i_assert(part->context == NULL);

	part->context = data = p_new(pool, struct message_part_body_data, 1);
	data->pool = pool;

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
						  child_part, tmpstr,
						  error_r) < 0)
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

		data->content_type = "\"multipart\"";
		if (!get_nstring(args++, pool, tmpstr, &data->content_subtype)) {
			*error_r = "Invalid multipart content-type";
			return -1;
		}
		if (imap_write_params(args++, pool, tmpstr, 2,
				      &data->content_type_params) < 0) {
			*error_r = "Invalid content params";
			return -1;
		}
		return imap_bodystructure_parse_args_common(data, pool, tmpstr,
							    args, error_r);
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

	if (!get_nstring(&args[0], pool, tmpstr, &data->content_type) ||
	    !get_nstring(&args[1], pool, tmpstr, &data->content_subtype))
		i_unreached();
	args += 2;

	text = strcasecmp(content_type, "text") == 0;
	message_rfc822 = strcasecmp(content_type, "message") == 0 &&
		strcasecmp(subtype, "rfc822") == 0;
	if (text != ((part->flags & MESSAGE_PART_FLAG_TEXT) != 0)) {
		*error_r = "message_part text flag doesn't match BODYSTRUCTURE";
		return -1;
	}
	if (message_rfc822 != ((part->flags & MESSAGE_PART_FLAG_MESSAGE_RFC822) != 0)) {
		*error_r = "message_part message/rfc822 flag doesn't match BODYSTRUCTURE";
		return -1;
	}

	/* ("content type param key" "value" ...) | NIL */
	if (imap_write_params(args++, pool, tmpstr, 2,
			      &data->content_type_params) < 0) {
		*error_r = "Invalid content params";
		return -1;
	}

	/* "content id" "content description" "transfer encoding" size */
	if (!get_nstring(args++, pool, tmpstr, &data->content_id)) {
		*error_r = "Invalid content-id";
		return -1;
	}
	if (!get_nstring(args++, pool, tmpstr, &data->content_description)) {
		*error_r = "Invalid content-description";
		return -1;
	}
	if (!get_nstring(args++, pool, tmpstr, &data->content_transfer_encoding)) {
		*error_r = "Invalid content-transfer-encoding";
		return -1;
	}
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
		if (imap_bodystructure_parse_lines(args, part, error_r) < 0)
			return -1;
		args++;
		i_assert(part->children == NULL);
	} else if (message_rfc822) {
		/* message/rfc822 - envelope + bodystructure + text lines */
		struct message_part_body_data *child_data;

		i_assert(part->children != NULL &&
			 part->children->next == NULL);

		if (!imap_arg_get_list(&args[1], &list_args)) {
			*error_r = "Child bodystructure list expected";
			return -1;
		}
		if (imap_bodystructure_parse_args(list_args, pool,
						  part->children,
						  tmpstr, error_r) < 0)
			return -1;

		/* save envelope to the child's context data */
		if (!imap_arg_get_list(&args[0], &list_args)) {
			*error_r = "Envelope list expected";
			return -1;
		}
		str_truncate(tmpstr, 0);
		imap_write_list(list_args, tmpstr);
		child_data = part->children->context;
		child_data->envelope_str = p_strdup(pool, str_c(tmpstr));

		args += 2;
		if (imap_bodystructure_parse_lines(args, part, error_r) < 0)
			return -1;
		args++;
	} else {
		i_assert(part->children == NULL);
	}

	if (!get_nstring(args++, pool, tmpstr, &data->content_md5)) {
		*error_r = "Invalid content-description";
		return -1;
	}
	return imap_bodystructure_parse_args_common(data, pool, tmpstr,
						    args, error_r);
}

int imap_bodystructure_parse(const char *bodystructure, pool_t pool,
			     struct message_part *parts, const char **error_r)
{
	struct istream *input;
	struct imap_parser *parser;
	const struct imap_arg *args;
	int ret;
	bool fatal;

	i_assert(parts != NULL);
	i_assert(parts->next == NULL);

	input = i_stream_create_from_data(bodystructure, strlen(bodystructure));
	(void)i_stream_read(input);

	parser = imap_parser_create(input, NULL, (size_t)-1);
	ret = imap_parser_finish_line(parser, 0, IMAP_PARSE_FLAG_NO_UNESCAPE |
				      IMAP_PARSE_FLAG_LITERAL_TYPE, &args);
	if (ret < 0) {
		*error_r = t_strdup_printf("IMAP parser failed: %s",
					   imap_parser_get_error(parser, &fatal));
	} else if (ret == 0) {
		*error_r = "Empty bodystructure";
		ret = -1;
	} else T_BEGIN {
		string_t *tmpstr = t_str_new(256);
		ret = imap_bodystructure_parse_args(args, pool, parts,
						    tmpstr, error_r);
	} T_END;

	imap_parser_unref(&parser);
	i_stream_destroy(&input);
	return ret;
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
		imap_write_list(list_args, str);
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
	bool fatal;
	int ret;

	input = i_stream_create_from_data(bodystructure, strlen(bodystructure));
	(void)i_stream_read(input);

	parser = imap_parser_create(input, NULL, (size_t)-1);
	ret = imap_parser_finish_line(parser, 0, IMAP_PARSE_FLAG_NO_UNESCAPE |
				      IMAP_PARSE_FLAG_LITERAL_TYPE, &args);
	if (ret < 0) {
		*error_r = t_strdup_printf("IMAP parser failed: %s",
					   imap_parser_get_error(parser, &fatal));
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
