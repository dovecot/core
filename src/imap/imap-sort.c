/* Copyright (c) 2002-2008 Dovecot authors, see the included COPYING file */

/* Implementation of draft-ietf-imapext-sort-10 sorting algorithm.
   Pretty messy code actually, adding any sort types requires care.
   This is pretty fast however and takes only as much memory as needed to be
   reasonably fast. */

#include "common.h"
#include "array.h"
#include "hash.h"
#include "ostream.h"
#include "str.h"
#include "imap-base-subject.h"
#include "mail-storage.h"
#include "message-address.h"
#include "imap-sort.h"

#include <stdlib.h>

#define MAX_WANTED_HEADERS 10
#define STRBUF_SIZE 1024

#define IS_SORT_STRING(type) \
	((type) == MAIL_SORT_CC || (type) == MAIL_SORT_FROM || \
	 (type) == MAIL_SORT_SUBJECT || (type) == MAIL_SORT_TO)

#define IS_SORT_TIME(type) \
	((type) == MAIL_SORT_ARRIVAL || (type) == MAIL_SORT_DATE)

struct sort_context {
	enum mail_sort_type sort_program[MAX_SORT_PROGRAM_SIZE];

	struct mailbox *box;
	struct ostream *output;
	string_t *str;

	bool written;
};

int imap_sort(struct client_command_context *cmd, const char *charset,
	      struct mail_search_arg *args,
	      const enum mail_sort_type *sort_program)
{
	struct client *client = cmd->client;
	const char *wanted_headers[2];
	enum mail_fetch_field wanted_fields;
	struct mail_search_context *search_ctx;
	struct mailbox_transaction_context *t;
	struct mailbox_header_lookup_ctx *headers_ctx;
	struct mail *mail;
	string_t *str;
	bool written = FALSE;
	int ret;

	wanted_fields = 0;
	wanted_headers[0] = wanted_headers[1] = NULL;
	switch (*sort_program & MAIL_SORT_MASK) {
	case MAIL_SORT_ARRIVAL:
		wanted_fields = MAIL_FETCH_RECEIVED_DATE;
		break;
	case MAIL_SORT_CC:
		wanted_headers[0] = "Cc";
		break;
	case MAIL_SORT_DATE:
		wanted_fields = MAIL_FETCH_DATE;
		break;
	case MAIL_SORT_FROM:
		wanted_headers[0] = "From";
		break;
	case MAIL_SORT_SIZE:
		wanted_fields = MAIL_FETCH_VIRTUAL_SIZE;
		break;
	case MAIL_SORT_SUBJECT:
		wanted_headers[0] = "Subject";
		break;
	case MAIL_SORT_TO:
		wanted_headers[0] = "To";
		break;
	}

	headers_ctx = wanted_headers[0] == NULL ? NULL :
		mailbox_header_lookup_init(client->mailbox, wanted_headers);

	t = mailbox_transaction_begin(client->mailbox, 0);
	search_ctx = mailbox_search_init(t, charset, args, sort_program);

	str = t_str_new(STRBUF_SIZE);
	str_append(str, "* SORT");

	mail = mail_alloc(t, wanted_fields, headers_ctx);
	while (mailbox_search_next(search_ctx, mail) > 0) {
		if (str_len(str) >= STRBUF_SIZE-MAX_INT_STRLEN) {
			o_stream_send(client->output, str_data(str),
				      str_len(str));
			str_truncate(str, 0);
			written = TRUE;
		}
		str_printfa(str, " %u", cmd->uid ? mail->uid : mail->seq);
	}
	ret = mailbox_search_deinit(&search_ctx);
	mail_free(&mail);

	if (mailbox_transaction_commit(&t) < 0)
		ret = -1;

	if (written || ret == 0) {
		str_append(str, "\r\n");
		o_stream_send(client->output, str_data(str), str_len(str));
	}

	if (headers_ctx != NULL)
		mailbox_header_lookup_deinit(&headers_ctx);
	return ret;
}
