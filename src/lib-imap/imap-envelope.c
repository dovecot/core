/* Copyright (c) 2002-2017 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "istream.h"
#include "str.h"
#include "message-address.h"
#include "message-part-data.h"
#include "message-parser.h"
#include "imap-parser.h"
#include "imap-envelope.h"
#include "imap-quote.h"

/*
 * Envelope write
 */

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

void imap_envelope_write(struct message_part_envelope *data,
				   string_t *str)
{
#define NVL(str, nullstr) ((str) != NULL ? (str) : (nullstr))
	static const char *empty_envelope =
		"NIL NIL NIL NIL NIL NIL NIL NIL NIL NIL";

	if (data == NULL) {
		str_append(str, empty_envelope);
		return;
	}

	imap_append_nstring(str, data->date);
	str_append_c(str, ' ');
	if (data->subject == NULL)
		str_append(str, "NIL");
	else {
		imap_append_string_for_humans(str,
			(const unsigned char *)data->subject,
			strlen(data->subject));
	}

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
	imap_append_nstring(str, data->in_reply_to);
	str_append_c(str, ' ');
	imap_append_nstring(str, data->message_id);
}

/*
 * ENVELOPE parsing
 */

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
	pool_t pool, struct message_part_envelope **envlp_r,
	const char **error_r)
{
	struct message_part_envelope *envlp;

	envlp = p_new(pool, struct message_part_envelope, 1);

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

bool imap_envelope_parse(const char *envelope,
	pool_t pool, struct message_part_envelope **envlp_r,
	const char **error_r)
{
	struct istream *input;
	struct imap_parser *parser;
	const struct imap_arg *args;
	char *error;
	int ret;

	input = i_stream_create_from_data(envelope, strlen(envelope));
	(void)i_stream_read(input);

	parser = imap_parser_create(input, NULL, (size_t)-1);
	ret = imap_parser_finish_line(parser, 0,
				      IMAP_PARSE_FLAG_LITERAL_TYPE, &args);
	if (ret < 0) {
		*error_r = t_strdup_printf("IMAP parser failed: %s",
					   imap_parser_get_error(parser, NULL));
	} else if (ret == 0) {
		*error_r = "Empty envelope";
		ret = -1;
	} else {
		T_BEGIN {
			if (!imap_envelope_parse_args
				(args, pool, envlp_r, error_r)) {
				error = i_strdup(*error_r);
				ret = -1;
			}
		} T_END;

		if (ret < 0) {
			*error_r = t_strdup(error);
			i_free(error);
		}
	}

	imap_parser_unref(&parser);
	i_stream_destroy(&input);
	return (ret >= 0);
}
