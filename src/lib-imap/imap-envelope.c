/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "istream.h"
#include "str.h"
#include "message-address.h"
#include "imap-parser.h"
#include "imap-envelope.h"
#include "imap-quote.h"

struct message_part_envelope_data {
	pool_t pool;

	char *date, *subject;
	struct message_address *from, *sender, *reply_to;
	struct message_address *to, *cc, *bcc;

	char *in_reply_to, *message_id;
};

void imap_envelope_parse_header(pool_t pool,
				struct message_part_envelope_data **data,
				const unsigned char *name, size_t name_len,
				const unsigned char *value, size_t value_len)
{
	struct message_part_envelope_data *d;

	if (*data == NULL) {
		*data = p_new(pool, struct message_part_envelope_data, 1);
		(*data)->pool = pool;
	}
	d = *data;

	t_push();

	switch (name_len) {
	case 2:
		if (memcasecmp(name, "To", 2) == 0 && d->to == NULL) {
			d->to = message_address_parse(pool, value,
						      value_len, 0);
		} else if (memcasecmp(name, "Cc", 2) == 0 && d->cc == NULL) {
			d->cc = message_address_parse(pool, value,
						      value_len, 0);
		}
		break;
	case 3:
		if (memcasecmp(name, "Bcc", 3) == 0 && d->bcc == NULL) {
			d->bcc = message_address_parse(pool, value,
						       value_len, 0);
		}
		break;
	case 4:
		if (memcasecmp(name, "From", 4) == 0 && d->from == NULL) {
			d->from = message_address_parse(pool, value,
							value_len, 0);
		} else if (memcasecmp(name, "Date", 4) == 0 && d->date == NULL)
			d->date = imap_quote(pool, value, value_len);
		break;
	case 6:
		if (memcasecmp(name, "Sender", 6) == 0 && d->sender == NULL) {
			d->sender = message_address_parse(pool, value,
							  value_len, 0);
		}
		break;
	case 7:
		if (memcasecmp(name, "Subject", 7) == 0 && d->subject == NULL)
			d->subject = imap_quote(pool, value, value_len);
		break;
	case 8:
		if (memcasecmp(name, "Reply-To", 8) == 0 &&
		    d->reply_to == NULL) {
			d->reply_to = message_address_parse(pool, value,
							    value_len, 0);
		}
		break;
	case 10:
		if (memcasecmp(name, "Message-Id", 10) == 0 &&
		    d->message_id == NULL)
			d->message_id = imap_quote(pool, value, value_len);
		break;
	case 11:
		if (memcasecmp(name, "In-Reply-To", 11) == 0 &&
		    d->in_reply_to == NULL)
			d->in_reply_to = imap_quote(pool, value, value_len);
		break;
	}

	t_pop();
}

static void imap_write_address(string_t *str, struct message_address *addr)
{
	if (addr == NULL) {
		str_append(str, "NIL");
		return;
	}

	str_append_c(str, '(');
	while (addr != NULL) {
		str_append_c(str, '(');
		str_append(str, imap_quote_str_nil(addr->name));
		str_append_c(str, ' ');
		str_append(str, imap_quote_str_nil(addr->route));
		str_append_c(str, ' ');
		str_append(str, imap_quote_str_nil(addr->mailbox));
		str_append_c(str, ' ');
		str_append(str, imap_quote_str_nil(addr->domain));
		str_append_c(str, ')');

		addr = addr->next;
	}
	str_append_c(str, ')');
}

void imap_envelope_write_part_data(struct message_part_envelope_data *data,
				   string_t *str)
{
	str_append(str, NVL(data->date, "NIL"));
	str_append_c(str, ' ');
	str_append(str, NVL(data->subject, "NIL"));

	str_append_c(str, ' ');
	imap_write_address(str, data->from);
	str_append_c(str, ' ');
	imap_write_address(str, NVL(data->sender, data->from));
	str_append_c(str, ' ');
	imap_write_address(str, NVL(data->reply_to, data->from));
	str_append_c(str, ' ');
	imap_write_address(str, data->to);
	str_append_c(str, ' ');
	imap_write_address(str, data->cc);
	str_append_c(str, ' ');
	imap_write_address(str, data->bcc);

	str_append_c(str, ' ');
	str_append(str, NVL(data->in_reply_to, "NIL"));
	str_append_c(str, ' ');
	str_append(str, NVL(data->message_id, "NIL"));
}

const char *
imap_envelope_get_part_data(struct message_part_envelope_data *data)
{
	string_t *str;

	str = t_str_new(2048);
        imap_envelope_write_part_data(data, str);
	return str_c(str);
}

static int imap_address_arg_append(struct imap_arg *arg, string_t *str,
				   int *in_group)
{
	struct imap_arg_list *list;
	const char *args[4];
	int i;

	if (arg->type != IMAP_ARG_LIST)
		return FALSE;
	list = IMAP_ARG_LIST(arg);

	/* we require 4 arguments, strings or NILs */
	if (list->size < 4)
		return FALSE;

	for (i = 0; i < 4; i++) {
		if (list->args[i].type == IMAP_ARG_NIL)
			args[i] = NULL;
		else if (list->args[i].type == IMAP_ARG_STRING ||
			 list->args[i].type == IMAP_ARG_ATOM)
			args[i] = IMAP_ARG_STR(&list->args[i]);
		else
			return FALSE;
	}

	if (*in_group && args[0] == NULL && args[1] == NULL &&
	    args[2] == NULL && args[3] == NULL) {
		/* end of group */
		str_append_c(str, ';');
		*in_group = FALSE;
		return TRUE;
	}

	if (str_len(str) > 0)
		str_append(str, ", ");

	if (!*in_group && args[0] == NULL && args[1] == NULL &&
	    args[2] != NULL && args[3] == NULL) {
		/* beginning of group */
		str_append(str, args[2]);
		str_append(str, ": ");
		*in_group = TRUE;
		return TRUE;
	}

	/* a) mailbox@domain
	   b) name <@route:mailbox@domain> */
	if (args[0] == NULL && args[1] == NULL) {
		if (args[2] != NULL)
			str_append(str, args[2]);
		if (args[3] != NULL) {
			str_append_c(str, '@');
			str_append(str, args[3]);
		}
	} else {
		if (args[0] != NULL) {
			str_append(str, args[0]);
			str_append_c(str, ' ');
		}

		str_append_c(str, '<');
		if (args[1] != NULL) {
			str_append_c(str, '@');
			str_append(str, args[1]);
			str_append_c(str, ':');
		}
		if (args[2] != NULL)
			str_append(str, args[2]);
		if (args[3] != NULL) {
			str_append_c(str, '@');
			str_append(str, args[3]);
		}
		str_append_c(str, '>');
	}
	return TRUE;
}

static const char *imap_envelope_parse_address(struct imap_arg *arg)
{
	struct imap_arg_list *list;
	string_t *str;
	size_t i;
	int in_group;

	if (arg->type != IMAP_ARG_LIST)
		return NULL;

	in_group = FALSE;
	str = t_str_new(128);

        list = IMAP_ARG_LIST(arg);
	for (i = 0; i < list->size; i++) {
		if (!imap_address_arg_append(&list->args[i], str, &in_group))
			return NULL;
	}

	return str_c(str);
}

static const char *imap_envelope_parse_first_mailbox(struct imap_arg *arg)
{
	struct imap_arg_list *list;

	/* ((name route mailbox domain) ...) */
	if (arg->type != IMAP_ARG_LIST)
		return NULL;

	list = IMAP_ARG_LIST(arg);
	if (list->size == 0)
		return "";

	arg = IMAP_ARG_LIST(arg)->args;
	if (arg->type != IMAP_ARG_LIST)
		return NULL;

	list = IMAP_ARG_LIST(arg);
	if (list->size != 4)
		return NULL;

	return t_strdup(imap_arg_string(&list->args[2]));
}

static int imap_envelope_parse_arg(struct imap_arg *arg,
				   enum imap_envelope_field field,
				   const char *envelope,
				   enum imap_envelope_result_type result_type,
				   const char **result)
{
	const char *value = NULL;

	if (arg->type == IMAP_ARG_NIL) {
		*result = NULL;
		return TRUE;
	}

	switch (result_type) {
	case IMAP_ENVELOPE_RESULT_TYPE_STRING:
		if (field >= IMAP_ENVELOPE_FROM && field <= IMAP_ENVELOPE_BCC)
			value = imap_envelope_parse_address(arg);
		else
			value = t_strdup(imap_arg_string(arg));
		break;
	case IMAP_ENVELOPE_RESULT_TYPE_FIRST_MAILBOX:
		i_assert(field >= IMAP_ENVELOPE_FROM &&
			 field <= IMAP_ENVELOPE_BCC);
		value = imap_envelope_parse_first_mailbox(arg);
		break;
	}

	*result = value;
	if (value != NULL)
		return TRUE;
	else {
		i_error("Invalid field %u in IMAP envelope: %s",
			field, envelope);
		return FALSE;
	}
}

int imap_envelope_parse(const char *envelope, enum imap_envelope_field field,
			enum imap_envelope_result_type result_type,
			const char **result)
{
	struct istream *input;
	struct imap_parser *parser;
	struct imap_arg *args;
	int ret;

	i_assert(field < IMAP_ENVELOPE_FIELDS);

	input = i_stream_create_from_data(data_stack_pool, envelope,
					  strlen(envelope));
	parser = imap_parser_create(input, NULL, 0, (size_t)-1);

	(void)i_stream_read(input);
	ret = imap_parser_read_args(parser, field+1, 0, &args);
	if (ret > (int)field) {
		ret = imap_envelope_parse_arg(&args[field], field,
					      envelope, result_type, result);
	} else {
		i_error("Error parsing IMAP envelope: %s", envelope);
		*result = NULL;
		ret = FALSE;
	}

	imap_parser_destroy(parser);
	i_stream_unref(input);
	return ret;
}
