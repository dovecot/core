/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "istream.h"
#include "str.h"
#include "rfc822-tokenize.h"
#include "message-parser.h"
#include "message-content-parser.h"
#include "imap-parser.h"
#include "imap-quote.h"
#include "imap-envelope.h"
#include "imap-bodystructure.h"

#define EMPTY_BODYSTRUCTURE \
        "(\"text\" \"plain\" (\"charset\" \"us-ascii\") NIL NIL \"7bit\" 0 0)"

typedef struct {
	Pool pool;
	String *str;
	char *content_type, *content_subtype;
	char *content_type_params;
	char *content_transfer_encoding;
	char *content_id;
	char *content_description;
	char *content_disposition;
	char *content_disposition_params;
	char *content_md5;
	char *content_language;

	MessagePartEnvelopeData *envelope;
} MessagePartBodyData;

static void part_write_bodystructure(MessagePart *part, String *str,
				     int extended);

static void parse_content_type(const Rfc822Token *tokens,
			       int count, void *context)
{
        MessagePartBodyData *data = context;
	const char *value;
	int i;

	/* find the content type separator */
	for (i = 0; i < count; i++) {
		if (tokens[i].token == '/')
			break;
	}

	value = rfc822_tokens_get_value_quoted(tokens, i);
	data->content_type = p_strdup(data->pool, value);

	value = rfc822_tokens_get_value_quoted(tokens+i+1, count-i-1);
	data->content_subtype = p_strdup(data->pool, value);
}

static void parse_save_params_list(const Rfc822Token *name,
				   const Rfc822Token *value, int value_count,
				   void *context)
{
        MessagePartBodyData *data = context;
	const char *str;

	if (str_len(data->str) != 0)
		str_append_c(data->str, ' ');

	str_append_c(data->str, '"');
	str_append_n(data->str, name->ptr, name->len);
	str_append(data->str, "\" ");

        str = rfc822_tokens_get_value_quoted(value, value_count);
	str_append(data->str, str);
}

static void parse_content_transfer_encoding(const Rfc822Token *tokens,
					    int count, void *context)
{
        MessagePartBodyData *data = context;
	const char *value;

	value = rfc822_tokens_get_value_quoted(tokens, count);
	data->content_transfer_encoding = p_strdup(data->pool, value);
}

static void parse_content_disposition(const Rfc822Token *tokens,
				      int count, void *context)
{
        MessagePartBodyData *data = context;
	const char *value;

	value = rfc822_tokens_get_value_quoted(tokens, count);
	data->content_disposition = p_strdup(data->pool, value);
}

static void parse_content_language(const Rfc822Token *tokens,
				   int count, void *context)
{
        MessagePartBodyData *data = context;
	String *str;
	int quoted;

	/* Content-Language: en-US, az-arabic (comments allowed) */

	if (count <= 0)
		return;

	str = t_str_new(256);

	quoted = FALSE;
	for (; count > 0; count--, tokens++) {
		switch (tokens->token) {
		case '(':
			/* ignore comment */
			break;
		case ',':
			/* list separator */
			if (quoted) {
				str_append_c(str, '"');
				quoted = FALSE;
			}
			break;
		default:
			/* anything else goes as-is. only alphabetic characters
			   and '-' is allowed, so anything else is error
			   which we can deal with however we want. */
			if (!quoted) {
				if (str_len(str) > 0)
					str_append_c(str, ' ');
				str_append_c(str, '"');
				quoted = TRUE;
			}

			if (IS_TOKEN_STRING(tokens->token))
				str_append_n(str, tokens->ptr, tokens->len);
			else
				str_append_c(str, tokens->token);
			break;
		}
	}

	if (quoted)
		str_append_c(str, '"');

	data->content_language = p_strdup(data->pool, str_c(str));
}

static void parse_header(MessagePart *part,
			 const char *name, size_t name_len,
			 const char *value, size_t value_len,
			 void *context)
{
	Pool pool = context;
	MessagePartBodyData *part_data;
	int parent_rfc822;

	parent_rfc822 = part->parent != NULL &&
		(part->parent->flags & MESSAGE_PART_FLAG_MESSAGE_RFC822);
	if (!parent_rfc822 && (name_len <= 8 ||
			       strncasecmp(name, "Content-", 8) != 0))
		return;

	if (part->context == NULL) {
		/* initialize message part data */
		part->context = part_data =
			p_new(pool, MessagePartBodyData, 1);
		part_data->pool = pool;
	}
	part_data = part->context;

	t_push();

	/* fix the name to be \0-terminated */
	name = t_strndup(name, name_len);

	if (strcasecmp(name, "Content-Type") == 0 &&
	    part_data->content_type == NULL) {
		part_data->str = t_str_new(256);
		(void)message_content_parse_header(t_strndup(value, value_len),
						   parse_content_type,
						   parse_save_params_list,
						   part_data);
		part_data->content_type_params =
			p_strdup(pool, str_c(part_data->str));
	} else if (strcasecmp(name, "Content-Transfer-Encoding") == 0 &&
		   part_data->content_transfer_encoding == NULL) {
		(void)message_content_parse_header(t_strndup(value, value_len),
						parse_content_transfer_encoding,
						NULL, part_data);
	} else if (strcasecmp(name, "Content-ID") == 0 &&
		   part_data->content_id == NULL) {
		part_data->content_id =
			imap_quote_value(pool, value, value_len);
	} else if (strcasecmp(name, "Content-Description") == 0 &&
		   part_data->content_description == NULL) {
		part_data->content_description =
			imap_quote_value(pool, value, value_len);
	} else if (strcasecmp(name, "Content-Disposition") == 0 &&
		   part_data->content_disposition_params == NULL) {
		part_data->str = t_str_new(256);
		(void)message_content_parse_header(t_strndup(value, value_len),
						   parse_content_disposition,
						   parse_save_params_list,
						   part_data);
		part_data->content_disposition_params =
			p_strdup(pool, str_c(part_data->str));
	} else if (strcasecmp(name, "Content-Language") == 0) {
		(void)message_content_parse_header(t_strndup(value, value_len),
						   parse_content_language, NULL,
						   part_data);
	} else if (strcasecmp(name, "Content-MD5") == 0 &&
		   part_data->content_md5 == NULL) {
		part_data->content_md5 =
			imap_quote_value(pool, value, value_len);
	} else if (parent_rfc822) {
		/* message/rfc822, we need the envelope */
		imap_envelope_parse_header(pool, &part_data->envelope,
					   name, value, value_len);
	}
	t_pop();
}

static void part_parse_headers(MessagePart *part, IStream *input,
			       uoff_t start_offset, Pool pool)
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

static void part_write_body_multipart(MessagePart *part, String *str,
				      int extended)
{
	MessagePartBodyData *data = part->context;

	if (data == NULL) {
		/* there was no content headers, use an empty structure */
		data = t_new(MessagePartBodyData, 1);
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
		str_append(str, "x-unknown");

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
		if (data->content_disposition_params != NULL) {
			str_append(str, " (");
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

static void part_write_body(MessagePart *part, String *str, int extended)
{
	MessagePartBodyData *data = part->context;

	if (data == NULL) {
		/* there was no content headers, use an empty structure */
		data = t_new(MessagePartBodyData, 1);
	}

	/* "content type" "subtype" */
	str_append(str, NVL(data->content_type, "\"text\""));
	str_append_c(str, ' ');
	str_append(str, NVL(data->content_subtype, "\"plain\""));

	/* ("content type param key" "value" ...) */
	str_append_c(str, ' ');
	if (data->content_type_params == NULL)
		str_append(str, "NIL");
	else {
		str_append_c(str, '(');
		str_append(str, data->content_type_params);
		str_append_c(str, ')');
	}

	str_printfa(str, " %s %s %s %"PRIuUOFF_T,
		    NVL(data->content_id, "NIL"),
		    NVL(data->content_description, "NIL"),
		    NVL(data->content_transfer_encoding, "\"8bit\""),
		    part->body_size.virtual_size);

	if (part->flags & MESSAGE_PART_FLAG_TEXT) {
		/* text/.. contains line count */
		str_printfa(str, " %u", part->body_size.lines);
	} else if (part->flags & MESSAGE_PART_FLAG_MESSAGE_RFC822) {
		/* message/rfc822 contains envelope + body + line count */
		MessagePartBodyData *child_data;

		i_assert(part->children != NULL);
		i_assert(part->children->next == NULL);

                child_data = part->children->context;

		str_append_c(str, ' ');
		if (child_data != NULL && child_data->envelope != NULL) {
			str_append_c(str, '(');
			imap_envelope_write_part_data(child_data->envelope,
						      str);
			str_append_c(str, ')');
		} else {
			/* buggy message */
			str_append(str, "NIL");
		}
		str_append_c(str, ' ');
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
		str_append_c(str, ')');

		if (data->content_disposition_params != NULL) {
			str_append(str, " (");
			str_append(str, data->content_disposition_params);
			str_append_c(str, ')');
		}
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

static void part_write_bodystructure(MessagePart *part, String *str,
				     int extended)
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

static const char *part_get_bodystructure(MessagePart *part, int extended)
{
	String *str;

	str = t_str_new(2048);
	part_write_bodystructure(part, str, extended);
	return str_c(str);
}

const char *imap_part_get_bodystructure(Pool pool, MessagePart **part,
					IStream *input, int extended)
{
	uoff_t start_offset;

	if (*part == NULL)
		*part = message_parse(pool, input, parse_header, pool);
	else {
		start_offset = input->v_offset;
		part_parse_headers(*part, input, start_offset, pool);
	}

	return part_get_bodystructure(*part, extended);
}

static int imap_write_list(ImapArg *args, String *str)
{
	/* don't do any typechecking, just write it out */
	str_append_c(str, '(');
	while (args->type != IMAP_ARG_EOL) {
		switch (args->type) {
		case IMAP_ARG_NIL:
			str_append(str, "NIL");
			break;
		case IMAP_ARG_ATOM:
			str_append(str, args->data.str);
			break;
		case IMAP_ARG_STRING:
			str_append_c(str, '"');
			str_append(str, args->data.str);
			str_append_c(str, '"');
			break;
		case IMAP_ARG_LIST:
			if (!imap_write_list(args->data.list->args, str))
				return FALSE;
			break;
		default:
			return FALSE;
		}
		args++;

		if (args->type != IMAP_ARG_EOL)
			str_append_c(str, ' ');
	}
	str_append_c(str, ')');
	return TRUE;
}

static int imap_parse_bodystructure_args(ImapArg *args, String *str)
{
	ImapArg *subargs;
	int i, multipart, text, message_rfc822;

	multipart = FALSE;
	while (args->type == IMAP_ARG_LIST) {
		str_append_c(str, '(');
		if (!imap_parse_bodystructure_args(args->data.list->args, str))
			return FALSE;
		str_append_c(str, ')');

		multipart = TRUE;
		args++;
	}

	if (multipart) {
		/* next is subtype of Content-Type. rest is skipped. */
		if (args->type != IMAP_ARG_STRING)
			return FALSE;

		str_printfa(str, " \"%s\"", args->data.str);
		return TRUE;
	}

	/* "content type" "subtype" */
	if (args[0].type != IMAP_ARG_STRING || args[1].type != IMAP_ARG_STRING)
		return FALSE;

	text = strcasecmp(args[0].data.str, "text") == 0;
	message_rfc822 = strcasecmp(args[0].data.str, "message") == 0 &&
		strcasecmp(args[1].data.str, "rfc822") == 0;

	str_printfa(str, "\"%s\" \"%s\"", args[0].data.str, args[1].data.str);
	args += 2;

	/* ("content type param key" "value" ...) | NIL */
	if (args->type == IMAP_ARG_LIST) {
		str_append(str, " (");
                subargs = args->data.list->args;
		for (; subargs->type != IMAP_ARG_EOL; ) {
			if (subargs[0].type != IMAP_ARG_STRING ||
			    subargs[1].type != IMAP_ARG_STRING)
				return FALSE;

			str_printfa(str, "\"%s\" \"%s\"",
				    subargs[0].data.str, subargs[1].data.str);

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
		if (args->type == IMAP_ARG_NIL) {
			str_append(str, " NIL");
		} else if (args->type == IMAP_ARG_ATOM) {
			str_append_c(str, ' ');
			str_append(str, args->data.str);
		} else if (args->type == IMAP_ARG_STRING) {
			str_printfa(str, " \"%s\"", args->data.str);
		} else {
			return FALSE;
		}
	}

	if (text) {
		/* text/xxx - text lines */
		if (args->type != IMAP_ARG_ATOM)
			return FALSE;

		str_append_c(str, ' ');
		str_append(str, args->data.str);
	} else if (message_rfc822) {
		/* message/rfc822 - envelope + bodystructure + text lines */
		if (args[0].type != IMAP_ARG_LIST ||
		    args[1].type != IMAP_ARG_LIST ||
		    args[2].type != IMAP_ARG_ATOM)
			return FALSE;

		str_append_c(str, ' ');

		if (!imap_write_list(args[0].data.list->args, str))
			return FALSE;

		str_append_c(str, ' ');

		if (!imap_parse_bodystructure_args(args[1].data.list->args,
						   str))
			return FALSE;

		str_append_c(str, ' ');
		str_append(str, args[2].data.str);
	}

	return TRUE;
}

const char *imap_body_parse_from_bodystructure(const char *bodystructure)
{
	IStream *input;
	ImapParser *parser;
	ImapArg *args;
	String *str;
	const char *value;
	size_t len;
	int ret;

	len = strlen(bodystructure);
	str = t_str_new(len);

	input = i_stream_create_from_data(data_stack_pool, bodystructure, len);
	(void)i_stream_read(input);

	parser = imap_parser_create(input, NULL, 0, (size_t)-1);
	ret = imap_parser_read_args(parser, 0, IMAP_PARSE_FLAG_NO_UNESCAPE,
				    &args);

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
