/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "buffer.h"
#include "istream.h"
#include "str.h"
#include "message-parser.h"
#include "message-content-parser.h"
#include "message-tokenize.h"
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
	string_t *str;
	char *content_type, *content_subtype;
	char *content_type_params;
	char *content_transfer_encoding;
	char *content_id;
	char *content_description;
	char *content_disposition;
	char *content_disposition_params;
	char *content_md5;
	char *content_language;

	struct message_part_envelope_data *envelope;

	unsigned int charset_found:1;
};

static void part_write_bodystructure(struct message_part *part,
				     string_t *str, int extended);

static void parse_content_type(const unsigned char *value, size_t value_len,
			       void *context)
{
        struct message_part_body_data *data = context;
	size_t i;

	for (i = 0; i < value_len; i++) {
		if (value[i] == '/')
			break;
	}

	if (i == value_len)
		data->content_type = imap_quote(data->pool, value, value_len);
	else {
		data->content_type = imap_quote(data->pool, value, i);

		i++;
		data->content_subtype =
			imap_quote(data->pool, value+i, value_len-i);
	}
}

static void parse_save_params_list(const unsigned char *name, size_t name_len,
				   const unsigned char *value, size_t value_len,
				   int value_quoted __attr_unused__,
				   void *context)
{
        struct message_part_body_data *data = context;

	if (str_len(data->str) != 0)
		str_append_c(data->str, ' ');

	if (name_len == 7 && memcasecmp(name, "charset", 7) == 0)
		data->charset_found = TRUE;

	imap_quote_append(data->str, name, name_len, TRUE);
	str_append_c(data->str, ' ');
	imap_quote_append(data->str, value, value_len, TRUE);
}

static void parse_content_transfer_encoding(const unsigned char *value,
					    size_t value_len, void *context)
{
        struct message_part_body_data *data = context;

	data->content_transfer_encoding =
		imap_quote(data->pool, value, value_len);
}

static void parse_content_disposition(const unsigned char *value,
				      size_t value_len, void *context)
{
        struct message_part_body_data *data = context;

	data->content_disposition = imap_quote(data->pool, value, value_len);
}

static void parse_content_language(const unsigned char *value, size_t value_len,
				   struct message_part_body_data *data)
{
	struct message_tokenizer *tok;
        enum message_token token;
	string_t *str;
	int quoted;

	/* Content-Language: en-US, az-arabic (comments allowed) */

	tok = message_tokenize_init(value, value_len, NULL, NULL);

	t_push();
	str = t_str_new(256);

	quoted = FALSE;
	while ((token = message_tokenize_next(tok)) != TOKEN_LAST) {
		if (token == ',') {
			/* list separator */
			if (quoted) {
				str_append_c(str, '"');
				quoted = FALSE;
			}
		} else {
			/* anything else goes as-is. only alphabetic characters
			   and '-' is allowed, so anything else is error
			   which we can deal with however we want. */
			if (!quoted) {
				if (str_len(str) > 0)
					str_append_c(str, ' ');
				str_append_c(str, '"');
				quoted = TRUE;
			}

			if (!IS_TOKEN_STRING(token))
				str_append_c(str, token);
			else {
				value = message_tokenize_get_value(tok,
								   &value_len);
				str_append_n(str, value, value_len);
			}
		}
	}

	if (quoted)
		str_append_c(str, '"');

	data->content_language = p_strdup(data->pool, str_c(str));

	t_pop();

	message_tokenize_deinit(tok);
}

static void parse_content_header(struct message_part_body_data *d,
				 struct message_header_line *hdr,
				 pool_t pool)
{
	const char *name = hdr->name;
	const unsigned char *value;
	size_t value_len;

	if (strncasecmp(name, "Content-", 8) != 0)
		return;
	name += 8;

	if (hdr->continues) {
		hdr->use_full_value = TRUE;
		return;
	}

	value = hdr->full_value;
	value_len = hdr->full_value_len;

	switch (*name) {
	case 'i':
	case 'I':
		if (strcasecmp(name, "ID") == 0 && d->content_id == NULL)
			d->content_id = imap_quote(pool, value, value_len);
		break;

	case 'm':
	case 'M':
		if (strcasecmp(name, "MD5") == 0 && d->content_md5 == NULL)
			d->content_md5 = imap_quote(pool, value, value_len);
		break;

	case 't':
	case 'T':
		if (strcasecmp(name, "Type") == 0 && d->content_type == NULL) {
			d->str = t_str_new(256);
			message_content_parse_header(value, value_len,
						     parse_content_type,
						     parse_save_params_list, d);
			if (!d->charset_found &&
			    strncasecmp(d->content_type, "\"text\"", 6) == 0) {
				/* set a default charset */
				if (str_len(d->str) != 0)
					str_append_c(d->str, ' ');
				str_append(d->str, DEFAULT_CHARSET);
			}
			d->content_type_params =
				p_strdup_empty(pool, str_c(d->str));
		}
		if (strcasecmp(name, "Transfer-Encoding") == 0 &&
		    d->content_transfer_encoding == NULL) {
			message_content_parse_header(value, value_len,
				parse_content_transfer_encoding,
				NULL, d);
		}
		break;

	case 'l':
	case 'L':
		if (strcasecmp(name, "Language") == 0 &&
		    d->content_language == NULL)
			parse_content_language(value, value_len, d);
		break;

	case 'd':
	case 'D':
		if (strcasecmp(name, "Description") == 0 &&
		    d->content_description == NULL) {
			d->content_description =
				imap_quote(pool, value, value_len);
		}
		if (strcasecmp(name, "Disposition") == 0 &&
		    d->content_disposition_params == NULL) {
			d->str = t_str_new(256);
			message_content_parse_header(value, value_len,
						     parse_content_disposition,
						     parse_save_params_list, d);
			d->content_disposition_params =
				p_strdup_empty(pool, str_c(d->str));
		}
		break;
	}
}

static void parse_header(struct message_part *part,
                         struct message_header_line *hdr, void *context)
{
	pool_t pool = context;
	struct message_part_body_data *part_data;
	struct message_part_envelope_data *envelope;
	int parent_rfc822;

	if (hdr == NULL) {
		/* If there was no Mime-Version, forget all the Content-stuff */
		if ((part->flags & MESSAGE_PART_FLAG_IS_MIME) == 0 &&
		    part->context != NULL) {
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

	t_push();

	parse_content_header(part_data, hdr, pool);

	if (parent_rfc822) {
		/* message/rfc822, we need the envelope */
		imap_envelope_parse_header(pool, &part_data->envelope, hdr);
	}
	t_pop();
}

static void part_parse_headers(struct message_part *part, struct istream *input,
			       uoff_t start_offset, pool_t pool)
{
	while (part != NULL) {
		/* note that we want to parse the header of all
		   the message parts, multiparts too. */
		i_assert(part->physical_pos >= input->v_offset - start_offset);
		i_stream_skip(input, part->physical_pos -
			      (input->v_offset - start_offset));

		message_parse_header(part, input, NULL, parse_header, pool);
		if (part->children != NULL) {
			part_parse_headers(part->children, input,
					   start_offset, pool);
		}

		part = part->next;
	}
}

static void part_write_body_multipart(struct message_part *part,
				      string_t *str, int extended)
{
	struct message_part_body_data *data = part->context;

	if (data == NULL) {
		/* there was no content headers, use an empty structure */
		data = t_new(struct message_part_body_data, 1);
	}

	if (part->children != NULL)
		part_write_bodystructure(part->children, str, extended);
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
}

static void part_write_body(struct message_part *part,
			    string_t *str, int extended)
{
	struct message_part_body_data *data = part->context;

	if (data == NULL) {
		/* there was no content headers, use an empty structure */
		data = t_new(struct message_part_body_data, 1);
	}

	if (part->flags & MESSAGE_PART_FLAG_MESSAGE_RFC822)
		str_append(str, "\"message\" \"rfc822\"");
	else {
		/* "content type" "subtype" */
		str_append(str, NVL(data->content_type, "\"text\""));
		str_append_c(str, ' ');

		if (data->content_subtype != NULL)
			str_append(str, data->content_subtype);
		else {
			if (data->content_type == NULL ||
			    strcasecmp(data->content_type, "\"text\"") == 0)
				str_append(str, "\"plain\"");
			else
				str_append(str, "\"unknown\"");

		}
	}

	/* ("content type param key" "value" ...) */
	str_append_c(str, ' ');
	if (data->content_type_params == NULL) {
		if (data->content_type != NULL &&
		    strncasecmp(data->content_type, "\"text\"", 6) != 0)
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

	if (part->flags & MESSAGE_PART_FLAG_TEXT) {
		/* text/.. contains line count */
		str_printfa(str, " %u", part->body_size.lines);
	} else if (part->flags & MESSAGE_PART_FLAG_MESSAGE_RFC822) {
		/* message/rfc822 contains envelope + body + line count */
		struct message_part_body_data *child_data;
                struct message_part_envelope_data *env_data;

		i_assert(part->children != NULL);
		i_assert(part->children->next == NULL);

                child_data = part->children->context;
		env_data = child_data != NULL ? child_data->envelope : NULL;

		str_append(str, " (");
		imap_envelope_write_part_data(env_data, str);
		str_append(str, ") ");

		part_write_bodystructure(part->children, str, extended);
		str_printfa(str, " %u", part->body_size.lines);
	}

	if (!extended)
		return;

	/* BODYSTRUCTURE data */

	/* "md5" ("content disposition" ("disposition" "params"))
	   ("body" "language" "params") */
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
}

static void part_write_bodystructure(struct message_part *part,
				     string_t *str, int extended)
{
	i_assert(part->parent != NULL || part->next == NULL);

	while (part != NULL) {
		if (part->parent != NULL)
			str_append_c(str, '(');

		if (part->flags & MESSAGE_PART_FLAG_MULTIPART)
			part_write_body_multipart(part, str, extended);
		else
			part_write_body(part, str, extended);

		if (part->parent != NULL)
			str_append_c(str, ')');

		part = part->next;
	}
}

const char *imap_part_get_bodystructure(pool_t pool, struct message_part **part,
					struct istream *input, int extended)
{
	string_t *str;
	uoff_t start_offset;

	if (*part == NULL)
		*part = message_parse(pool, input, parse_header, pool);
	else {
		start_offset = input->v_offset;
		part_parse_headers(*part, input, start_offset, pool);
	}

	str = t_str_new(2048);
	part_write_bodystructure(*part, str, extended);
	return str_c(str);
}

static int str_append_imap_arg(string_t *str, const struct imap_arg *arg)
{
	switch (arg->type) {
	case IMAP_ARG_NIL:
		str_append(str, "NIL");
		break;
	case IMAP_ARG_ATOM:
		str_append(str, IMAP_ARG_STR(arg));
		break;
	case IMAP_ARG_STRING:
		str_append_c(str, '"');
		str_append(str, IMAP_ARG_STR(arg));
		str_append_c(str, '"');
		break;
	case IMAP_ARG_LITERAL: {
		const char *argstr = IMAP_ARG_STR(arg);

		str_printfa(str, "{%"PRIuSIZE_T"}", strlen(argstr));
		str_append(str, argstr);
		break;
	}
	default:
		return FALSE;
	}

	return TRUE;
}

static int imap_write_list(const struct imap_arg *args, string_t *str)
{
	/* don't do any typechecking, just write it out */
	str_append_c(str, '(');
	while (args->type != IMAP_ARG_EOL) {
		if (!str_append_imap_arg(str, args)) {
			if (args->type != IMAP_ARG_LIST)
				return FALSE;

			if (!imap_write_list(IMAP_ARG_LIST(args)->args, str))
				return FALSE;
		}
		args++;

		if (args->type != IMAP_ARG_EOL)
			str_append_c(str, ' ');
	}
	str_append_c(str, ')');
	return TRUE;
}

static int imap_parse_bodystructure_args(const struct imap_arg *args,
					 string_t *str)
{
	struct imap_arg *subargs;
	struct imap_arg_list *list;
	int i, multipart, text, message_rfc822;

	multipart = FALSE;
	while (args->type == IMAP_ARG_LIST) {
		str_append_c(str, '(');
		list = IMAP_ARG_LIST(args);
		if (!imap_parse_bodystructure_args(list->args, str))
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
	if (args[0].type == IMAP_ARG_NIL || args[1].type == IMAP_ARG_NIL)
		return FALSE;

	if (!str_append_imap_arg(str, &args[0]))
		return FALSE;
	str_append_c(str, ' ');
	if (!str_append_imap_arg(str, &args[1]))
		return FALSE;

	text = strcasecmp(IMAP_ARG_STR(&args[0]), "text") == 0;
	message_rfc822 = strcasecmp(IMAP_ARG_STR(&args[0]), "message") == 0 &&
		strcasecmp(IMAP_ARG_STR(&args[1]), "rfc822") == 0;

	args += 2;

	/* ("content type param key" "value" ...) | NIL */
	if (args->type == IMAP_ARG_LIST) {
		str_append(str, " (");
                subargs = IMAP_ARG_LIST(args)->args;
		for (; subargs->type != IMAP_ARG_EOL; ) {
			if (!str_append_imap_arg(str, &subargs[0]))
				return FALSE;
			str_append_c(str, ' ');
			if (!str_append_imap_arg(str, &subargs[1]))
				return FALSE;

			subargs += 2;
			if (subargs->type == IMAP_ARG_EOL)
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
		if (args->type != IMAP_ARG_ATOM)
			return FALSE;

		str_append_c(str, ' ');
		str_append(str, IMAP_ARG_STR(args));
	} else if (message_rfc822) {
		/* message/rfc822 - envelope + bodystructure + text lines */
		if (args[0].type != IMAP_ARG_LIST ||
		    args[1].type != IMAP_ARG_LIST ||
		    args[2].type != IMAP_ARG_ATOM)
			return FALSE;

		str_append_c(str, ' ');

		list = IMAP_ARG_LIST(&args[0]);
		if (!imap_write_list(list->args, str))
			return FALSE;

		str_append_c(str, ' ');

		list = IMAP_ARG_LIST(&args[1]);
		if (!imap_parse_bodystructure_args(list->args, str))
			return FALSE;

		str_append_c(str, ' ');
		str_append(str, IMAP_ARG_STR(&args[2]));
	}

	return TRUE;
}

const char *imap_body_parse_from_bodystructure(const char *bodystructure)
{
	struct istream *input;
	struct imap_parser *parser;
	struct imap_arg *args;
	string_t *str;
	const char *value;
	size_t len;
	int ret;

	len = strlen(bodystructure);
	str = t_str_new(len);

	input = i_stream_create_from_data(data_stack_pool, bodystructure, len);
	(void)i_stream_read(input);

	parser = imap_parser_create(input, NULL, (size_t)-1);
	ret = imap_parser_finish_line(parser, 0, IMAP_PARSE_FLAG_NO_UNESCAPE |
				      IMAP_PARSE_FLAG_LITERAL_TYPE, &args);
	if (ret <= 0 || !imap_parse_bodystructure_args(args, str))
		value = NULL;
	else
		value = str_c(str);

	if (value == NULL)
		i_error("Error parsing IMAP bodystructure: %s", bodystructure);

	imap_parser_destroy(parser);
	i_stream_unref(input);
	return value;
}
