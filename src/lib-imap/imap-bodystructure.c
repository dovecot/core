/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "istream.h"
#include "str.h"
#include "message-part-data.h"
#include "message-parser.h"
#include "rfc822-parser.h"
#include "rfc2231-parser.h"
#include "imap-parser.h"
#include "imap-quote.h"
#include "imap-envelope.h"
#include "imap-bodystructure.h"

#define EMPTY_BODY "(\"text\" \"plain\" " \
	"(\"charset\" \""MESSAGE_PART_DEFAULT_CHARSET"\") NIL NIL \"7bit\" 0 0)"
#define EMPTY_BODYSTRUCTURE "(\"text\" \"plain\" " \
	"(\"charset\" \""MESSAGE_PART_DEFAULT_CHARSET"\") NIL NIL \"7bit\" 0 0 " \
		"NIL NIL NIL NIL)"

/*
 * IMAP BODY/BODYSTRUCTURE write
 */

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
		str_append(str, "\"charset\" "
			"\""MESSAGE_PART_DEFAULT_CHARSET"\"");
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
	imap_append_nstring_nolf(str, data->content_location);
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
		if (!extended)
			str_append(str, EMPTY_BODY);
		else
			str_append(str, EMPTY_BODYSTRUCTURE);
	}

	str_append_c(str, ' ');
	imap_append_string(str, data->content_subtype);

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
			str_append(str, "\"text\" \"plain\"");
		} else {
			text = (strcasecmp(data->content_type, "text") == 0);
			imap_append_string(str, data->content_type);
			str_append_c(str, ' ');
			imap_append_string(str, data->content_subtype);
		}
	}

	/* ("content type param key" "value" ...) */
	str_append_c(str, ' ');
	params_write(data->content_type_params,
		data->content_type_params_count, str, text);

	str_append_c(str, ' ');
	imap_append_nstring_nolf(str, data->content_id);
	str_append_c(str, ' ');
	imap_append_nstring_nolf(str, data->content_description);
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
		imap_envelope_write(child_data->envelope, str);
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
	imap_append_nstring_nolf(str, data->content_md5);
	part_write_bodystructure_common(data, str);
}

void imap_bodystructure_write(const struct message_part *part,
			      string_t *dest, bool extended)
{
	if ((part->flags & MESSAGE_PART_FLAG_MULTIPART) != 0)
		part_write_body_multipart(part, dest, extended);
	else
		part_write_body(part, dest, extended);
}

/*
 * IMAP BODYSTRUCTURE parsing
 */

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

int
imap_bodystructure_parse_args(const struct imap_arg *args, pool_t pool,
			      struct message_part **_part,
			      const char **error_r)
{
	struct message_part *part = *_part, *child_part;;
	struct message_part **child_part_p;
	struct message_part_data *data;
	const struct imap_arg *list_args;
	const char *value, *content_type, *subtype, *error;
	bool multipart, text, message_rfc822, parsing_tree, has_lines;
	unsigned int lines;
	uoff_t vsize;

	if (part != NULL) {
		/* parsing with pre-existing message_part tree */
		parsing_tree = FALSE;
	} else {
		/* parsing message_part tree from BODYSTRUCTURE as well */
		part = *_part = p_new(pool, struct message_part, 1);
		parsing_tree = TRUE;
	}
	part->data = data = p_new(pool, struct message_part_data, 1);

	multipart = FALSE;
	if (!parsing_tree) {
		if ((part->flags & MESSAGE_PART_FLAG_MULTIPART) != 0 &&
			part->children == NULL) {
			struct message_part_data dummy_part_data = {
				.content_type = "text",
				.content_subtype = "plain",
				.content_transfer_encoding = "7bit"
			};
			struct message_part dummy_part = {
				.parent = part,
				.data = &dummy_part_data,
				.flags = MESSAGE_PART_FLAG_TEXT
			};
			struct message_part *dummy_partp = &dummy_part;

			/* no parts in multipart message,
			   that's not allowed. expect a single
			   0-length text/plain structure */
			if (args->type != IMAP_ARG_LIST ||
				(args+1)->type == IMAP_ARG_LIST) {
				*error_r = "message_part hierarchy "
					"doesn't match BODYSTRUCTURE";
				return -1;
			}

			list_args = imap_arg_as_list(args);
			if (imap_bodystructure_parse_args(list_args, pool,
								&dummy_partp, error_r) < 0)
				return -1;
			child_part = NULL;

			multipart = TRUE;
			args++;

		} else {
			child_part = part->children;
			while (args->type == IMAP_ARG_LIST) {
				if ((part->flags & MESSAGE_PART_FLAG_MULTIPART) == 0 ||
						child_part == NULL) {
					*error_r = "message_part hierarchy "
						"doesn't match BODYSTRUCTURE";
					return -1;
				}

				list_args = imap_arg_as_list(args);
				if (imap_bodystructure_parse_args(list_args, pool,
									&child_part, error_r) < 0)
					return -1;
				child_part = child_part->next;

				multipart = TRUE;
				args++;
			}
		}
		if (multipart) {
			if (child_part != NULL) {
				*error_r = "message_part hierarchy "
					"doesn't match BODYSTRUCTURE";
				return -1;
			}
		} else 	if ((part->flags & MESSAGE_PART_FLAG_MULTIPART) != 0) {
			*error_r = "message_part multipart flag "
				"doesn't match BODYSTRUCTURE";
			return -1;
		}
	} else {
		child_part_p = &part->children;
		while (args->type == IMAP_ARG_LIST) {
			list_args = imap_arg_as_list(args);
			if (imap_bodystructure_parse_args(list_args, pool,
								child_part_p, error_r) < 0)
				return -1;
			(*child_part_p)->parent = part;
			child_part_p = &(*child_part_p)->next;

			multipart = TRUE;
			args++;
		}
		if (multipart) {
			part->flags |= MESSAGE_PART_FLAG_MULTIPART;
		}
	}

	if (multipart) {
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

	if (!parsing_tree) {
#if 0
		/* Disabled for now. Earlier Dovecot versions handled broken
		   Content-Type headers by writing them as "text" "plain" to
		   BODYSTRUCTURE reply, but the message_part didn't have
		   MESSAGE_PART_FLAG_TEXT. */
		if (text != ((part->flags & MESSAGE_PART_FLAG_TEXT) != 0)) {
			*error_r = "message_part text flag "
				"doesn't match BODYSTRUCTURE";
			return -1;
		}
#endif
		if (message_rfc822 !=
			((part->flags & MESSAGE_PART_FLAG_MESSAGE_RFC822) != 0)) {
			*error_r = "message_part message/rfc822 flag "
				"doesn't match BODYSTRUCTURE";
			return -1;
		}
	} else {
		if (text)
			part->flags |= MESSAGE_PART_FLAG_TEXT;
		if (message_rfc822)
			part->flags |= MESSAGE_PART_FLAG_MESSAGE_RFC822;
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
	if (!parsing_tree) {
		if (vsize != part->body_size.virtual_size) {
			*error_r = "message_part virtual_size doesn't match "
				"size in BODYSTRUCTURE";
			return -1;
		}
	} else {
		part->body_size.virtual_size = vsize;
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

		if (!parsing_tree) {
			i_assert(part->children != NULL &&
				 part->children->next == NULL);
		}

		if (!imap_arg_get_list(&args[1], &list_args)) {
			*error_r = "Child bodystructure list expected";
			return -1;
		}
		if (imap_bodystructure_parse_args
			(list_args, pool, &part->children, error_r) < 0)
			return -1;
		if (parsing_tree) {
			i_assert(part->children != NULL &&
				 part->children->next == NULL);
			part->children->parent = part;
		}

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
		lines = 0;
		has_lines = FALSE;
	}
	if (!parsing_tree) {
		if (has_lines && lines != part->body_size.lines) {
			*error_r = "message_part lines "
				"doesn't match lines in BODYSTRUCTURE";
			return -1;
		}
	} else {
		part->body_size.lines = lines;
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

int imap_bodystructure_parse_full(const char *bodystructure,
	pool_t pool, struct message_part **parts,
	const char **error_r)
{
	struct istream *input;
	struct imap_parser *parser;
	const struct imap_arg *args;
	char *error = NULL;
	int ret;

	i_assert(*parts == NULL || (*parts)->next == NULL);

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

int imap_bodystructure_parse(const char *bodystructure,
	pool_t pool, struct message_part *parts,
	const char **error_r)
{
	i_assert(parts != NULL);

	return imap_bodystructure_parse_full(bodystructure,
		pool, &parts, error_r);
}

/*
 * IMAP BODYSTRUCTURE to BODY conversion
 */

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
		str_printfa(str, "{%zu}\r\n", strlen(cstr));
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
