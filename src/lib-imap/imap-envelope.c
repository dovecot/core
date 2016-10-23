/* Copyright (c) 2002-2017 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "istream.h"
#include "str.h"
#include "message-address.h"
#include "message-parser.h"
#include "imap-parser.h"
#include "imap-envelope.h"
#include "imap-quote.h"

struct message_part_envelope_data {
	const char *date, *subject;
	struct message_address *from, *sender, *reply_to;
	struct message_address *to, *cc, *bcc;

	const char *in_reply_to, *message_id;
};

const char *imap_envelope_headers[] = {
	"Date", "Subject", "From", "Sender", "Reply-To",
	"To", "Cc", "Bcc", "In-Reply-To", "Message-ID",
	NULL
};

bool imap_envelope_get_field(const char *name, enum imap_envelope_field *ret)
{
	*ret = (enum imap_envelope_field)-1;

	switch (*name) {
	case 'B':
	case 'b':
		if (strcasecmp(name, "Bcc") == 0)
			*ret = IMAP_ENVELOPE_BCC;
		break;
	case 'C':
	case 'c':
		if (strcasecmp(name, "Cc") == 0)
			*ret = IMAP_ENVELOPE_CC;
		break;
	case 'D':
	case 'd':
		if (strcasecmp(name, "Date") == 0)
			*ret = IMAP_ENVELOPE_DATE;
		break;
	case 'F':
	case 'f':
		if (strcasecmp(name, "From") == 0)
			*ret = IMAP_ENVELOPE_FROM;
		break;
	case 'I':
	case 'i':
		if (strcasecmp(name, "In-reply-to") == 0)
			*ret = IMAP_ENVELOPE_IN_REPLY_TO;
		break;
	case 'M':
	case 'm':
		if (strcasecmp(name, "Message-id") == 0)
			*ret = IMAP_ENVELOPE_MESSAGE_ID;
		break;
	case 'R':
	case 'r':
		if (strcasecmp(name, "Reply-to") == 0)
			*ret = IMAP_ENVELOPE_REPLY_TO;
		break;
	case 'S':
	case 's':
		if (strcasecmp(name, "Subject") == 0)
			*ret = IMAP_ENVELOPE_SUBJECT;
		if (strcasecmp(name, "Sender") == 0)
			*ret = IMAP_ENVELOPE_SENDER;
		break;
	case 'T':
	case 't':
		if (strcasecmp(name, "To") == 0)
			*ret = IMAP_ENVELOPE_TO;
		break;
	}

	return *ret != (enum imap_envelope_field)-1;
}

void imap_envelope_parse_header(pool_t pool,
				struct message_part_envelope_data **data,
				struct message_header_line *hdr)
{
	struct message_part_envelope_data *d;
	enum imap_envelope_field field;
	struct message_address **addr_p;
	const char **str_p;

	if (*data == NULL) {
		*data = p_new(pool, struct message_part_envelope_data, 1);
	}

	if (hdr == NULL || !imap_envelope_get_field(hdr->name, &field))
		return;

	if (hdr->continues) {
		/* wait for full value */
		hdr->use_full_value = TRUE;
		return;
	}

	d = *data;
	addr_p = NULL; str_p = NULL;
	switch (field) {
	case IMAP_ENVELOPE_DATE:
		str_p = &d->date;
		break;
	case IMAP_ENVELOPE_SUBJECT:
		str_p = &d->subject;
		break;
	case IMAP_ENVELOPE_MESSAGE_ID:
		str_p = &d->message_id;
		break;
	case IMAP_ENVELOPE_IN_REPLY_TO:
		str_p = &d->in_reply_to;
		break;

	case IMAP_ENVELOPE_CC:
		addr_p = &d->cc;
		break;
	case IMAP_ENVELOPE_BCC:
		addr_p = &d->bcc;
		break;
	case IMAP_ENVELOPE_FROM:
		addr_p = &d->from;
		break;
	case IMAP_ENVELOPE_SENDER:
		addr_p = &d->sender;
		break;
	case IMAP_ENVELOPE_TO:
		addr_p = &d->to;
		break;
	case IMAP_ENVELOPE_REPLY_TO:
		addr_p = &d->reply_to;
		break;
	case IMAP_ENVELOPE_FIELDS:
		break;
	}

	if (addr_p != NULL) {
		*addr_p = message_address_parse(pool, hdr->full_value,
						hdr->full_value_len,
						UINT_MAX, TRUE);
	} else if (str_p != NULL) T_BEGIN {
		string_t *str = t_str_new(128);

		if (str_p != &d->subject) {
			imap_append_string(str,
				t_strndup(hdr->full_value, hdr->full_value_len));
		} else {
			imap_append_string_for_humans(str,
				hdr->full_value, hdr->full_value_len);
		}
		*str_p = p_strdup(pool, str_c(str));
	} T_END;
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
		if (addr->name == NULL)
			str_append(str, "NIL");
		else {
			imap_append_string_for_humans(str,
				(const void *)addr->name, strlen(addr->name));
		}
		str_append_c(str, ' ');
		imap_append_nstring(str, addr->route);
		str_append_c(str, ' ');
		imap_append_nstring(str, addr->mailbox);
		str_append_c(str, ' ');
		imap_append_nstring(str, addr->domain);
		str_append_c(str, ')');

		addr = addr->next;
	}
	str_append_c(str, ')');
}

void imap_envelope_write_part_data(struct message_part_envelope_data *data,
				   string_t *str)
{
#define NVL(str, nullstr) ((str) != NULL ? (str) : (nullstr))
	static const char *empty_envelope =
		"NIL NIL NIL NIL NIL NIL NIL NIL NIL NIL";

	if (data == NULL) {
		str_append(str, empty_envelope);
		return;
	}

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

static bool
imap_envelope_parse_address(const struct imap_arg *arg,
	pool_t pool, struct message_address **addr_r)
{
	struct message_address *addr;
	const struct imap_arg *list_args;
	const char *name, *route, *mailbox, *domain;
	unsigned int list_count;

	if (!imap_arg_get_list_full(arg, &list_args, &list_count))
		return FALSE;

	/* we require 4 arguments, strings or NILs */
	if (list_count < 4)
		return FALSE;

	if (!imap_arg_get_nstring(&list_args[0], &name))
		return FALSE;
	if (!imap_arg_get_nstring(&list_args[1], &route))
		return FALSE;
	if (!imap_arg_get_nstring(&list_args[2], &mailbox))
		return FALSE;
	if (!imap_arg_get_nstring(&list_args[3], &domain))
		return FALSE;

	addr = p_new(pool, struct message_address, 1);
	addr->name = p_strdup(pool, name);
	addr->route = p_strdup(pool, route);
	addr->mailbox = p_strdup(pool, mailbox);
	addr->domain = p_strdup(pool, domain);

	*addr_r = addr;
	return TRUE;
}

static bool
imap_envelope_parse_addresses(const struct imap_arg *arg,
	pool_t pool, struct message_address **addrs_r)
{
	struct message_address *first, *addr, *prev;
	const struct imap_arg *list_args;

	if (arg->type == IMAP_ARG_NIL) {
		*addrs_r = NULL;
		return TRUE;
	}

	if (!imap_arg_get_list(arg, &list_args))
		return FALSE;

	first = addr = prev = NULL;
	for (; !IMAP_ARG_IS_EOL(list_args); list_args++) {
		if (!imap_envelope_parse_address
			(list_args, pool, &addr))
			return FALSE;
		if (first == NULL)
			first = addr;
		if (prev != NULL)
			prev->next = addr;
		prev = addr;
	}

	*addrs_r = first;
	return TRUE;
}

bool imap_envelope_parse_args(const struct imap_arg *args,
	pool_t pool, struct message_part_envelope_data **envlp_r,
	const char **error_r)
{
	struct message_part_envelope_data *envlp;

	envlp = p_new(pool, struct message_part_envelope_data, 1);

	if (!imap_arg_get_nstring(args++, &envlp->date)) {
		*error_r = "Invalid date field";
		return FALSE;
	}
	envlp->date = p_strdup(pool, envlp->date);

	if (!imap_arg_get_nstring(args++, &envlp->subject)) {
		*error_r = "Invalid subject field";
		return FALSE;
	}
	envlp->subject = p_strdup(pool, envlp->subject);

	if (!imap_envelope_parse_addresses(args++, pool, &envlp->from)) {
		*error_r = "Invalid from field";
		return FALSE;
	}
	if (!imap_envelope_parse_addresses(args++, pool, &envlp->sender)) {
		*error_r = "Invalid sender field";
		return FALSE;
	}
	if (!imap_envelope_parse_addresses(args++, pool, &envlp->reply_to)) {
		*error_r = "Invalid reply_to field";
		return FALSE;
	}
	if (!imap_envelope_parse_addresses(args++, pool, &envlp->to)) {
		*error_r = "Invalid to field";
		return FALSE;
	}
	if (!imap_envelope_parse_addresses(args++, pool, &envlp->cc)) {
		*error_r = "Invalid cc field";
		return FALSE;
	}
	if (!imap_envelope_parse_addresses(args++, pool, &envlp->bcc)) {
		*error_r = "Invalid bcc field";
		return FALSE;
	}

	if (!imap_arg_get_nstring(args++, &envlp->in_reply_to)) {
		*error_r = "Invalid in_reply_to field";
		return FALSE;
	}
	envlp->in_reply_to = p_strdup(pool, envlp->in_reply_to);

	if (!imap_arg_get_nstring(args++, &envlp->message_id)) {
		*error_r = "Invalid message_id field";
		return FALSE;
	}
	envlp->message_id = p_strdup(pool, envlp->message_id);

	*envlp_r = envlp;
	return TRUE;
}