/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "ostream.h"
#include "str.h"
#include "commands.h"
#include "imap-search.h"

#define STRBUF_SIZE 1024

static int imap_search(struct client *client, const char *charset,
		       struct mail_search_arg *sargs)
{
        struct mail_search_context *ctx;
	const struct mail *mail;
	string_t *str;
	int ret, uid, first = TRUE;

	str = t_str_new(STRBUF_SIZE);
	uid = client->cmd_uid;

	ctx = client->mailbox->search_init(client->mailbox, charset, sargs,
					   NULL, 0, NULL);
	if (ctx == NULL)
		return FALSE;

	str_append(str, "* SEARCH");
	while ((mail = client->mailbox->search_next(ctx)) != NULL) {
		if (str_len(str) >= STRBUF_SIZE-MAX_INT_STRLEN) {
			/* flush */
			o_stream_send(client->output,
				      str_data(str), str_len(str));
			str_truncate(str, 0);
			first = FALSE;
		}

		str_printfa(str, " %u", uid ? mail->uid : mail->seq);
	}

	ret = client->mailbox->search_deinit(ctx);

	if (!first || ret) {
		str_append(str, "\r\n");
		o_stream_send(client->output, str_data(str), str_len(str));
	}
	return ret;
}

int cmd_search(struct client *client)
{
	struct mail_search_arg *sargs;
	struct imap_arg *args;
	int args_count;
	pool_t pool;
	const char *error, *charset;

	args_count = imap_parser_read_args(client->parser, 0, 0, &args);
	if (args_count < 1) {
		if (args_count == -2)
			return FALSE;

		client_send_command_error(client, args_count < 0 ? NULL :
					  "Missing SEARCH arguments.");
		return TRUE;
	}

	if (!client_verify_open_mailbox(client))
		return TRUE;

	if (args->type == IMAP_ARG_ATOM &&
	    strcasecmp(IMAP_ARG_STR(args), "CHARSET") == 0) {
		/* CHARSET specified */
		args++;
		if (args->type != IMAP_ARG_ATOM &&
		    args->type != IMAP_ARG_STRING) {
			client_send_command_error(client,
						  "Invalid charset argument.");
			return TRUE;
		}

		charset = IMAP_ARG_STR(args);
		args++;
	} else {
		charset = NULL;
	}

	pool = pool_alloconly_create("mail_search_args", 2048);

	sargs = imap_search_args_build(pool, args, &error);
	if (sargs == NULL) {
		/* error in search arguments */
		client_send_tagline(client, t_strconcat("NO ", error, NULL));
	} else if (imap_search(client, charset, sargs)) {
		if (client->cmd_uid)
			client_sync_full(client);
		else
			client_sync_without_expunges(client);
		client_send_tagline(client, "OK Search completed.");
	} else {
		client_send_storage_error(client);
	}

	pool_unref(pool);
	return TRUE;
}
