/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "istream.h"
#include "ostream.h"
#include "str.h"
#include "message-size.h"
#include "mail-storage.h"
#include "mail-search.h"
#include "capability.h"
#include "commands.h"

#define MSGS_BITMASK_SIZE(client) \
	((client->messages_count + (CHAR_BIT-1)) / CHAR_BIT)

static const char *get_msgnum(struct client *client, const char *args,
			      unsigned int *msgnum)
{
	unsigned int num, last_num;

	num = 0;
	while (*args != '\0' && *args != ' ') {
		if (*args < '0' || *args > '9') {
			client_send_line(client,
				"-ERR Invalid message number: %s", args);
			return NULL;
		}

		last_num = num;
		num = num*10 + (*args - '0');
		if (num < last_num) {
			client_send_line(client,
				"-ERR Message number too large: %s", args);
			return NULL;
		}
		args++;
	}

	if (num == 0 || num > client->messages_count) {
		client_send_line(client,
				 "-ERR There's no message %u.", num);
		return NULL;
	}
	num--;

	if (client->deleted) {
		if (client->deleted_bitmask[num / CHAR_BIT] &
		    (1 << (num % CHAR_BIT))) {
			client_send_line(client, "-ERR Message is deleted.");
			return NULL;
		}
	}

	while (*args == ' ') args++;

	*msgnum = num;
	return args;
}

static const char *get_size(struct client *client, const char *args,
			    uoff_t *size)
{
	uoff_t num, last_num;

	num = 0;
	while (*args != '\0' && *args != ' ') {
		if (*args < '0' || *args > '9') {
			client_send_line(client, "-ERR Invalid size: %s",
					 args);
			return NULL;
		}

		last_num = num;
		num = num*10 + (*args - '0');
		if (num < last_num) {
			client_send_line(client, "-ERR Size too large: %s",
					 args);
			return NULL;
		}
		args++;
	}

	while (*args == ' ') args++;

	*size = num;
	return args;
}

static int cmd_capa(struct client *client, const char *args __attr_unused__)
{
	client_send_line(client, "+OK\r\n"POP3_CAPABILITY_REPLY".");
	return TRUE;
}

static int cmd_dele(struct client *client, const char *args)
{
	unsigned int msgnum;

	if (get_msgnum(client, args, &msgnum) == NULL)
		return FALSE;

	if (!client->deleted) {
		client->deleted_bitmask = i_malloc(MSGS_BITMASK_SIZE(client));
		client->deleted = TRUE;
	}

	client->deleted_bitmask[msgnum / CHAR_BIT] |= 1 << (msgnum % CHAR_BIT);
	client->deleted_count++;
	client->deleted_size += client->message_sizes[msgnum];
	client_send_line(client, "+OK Marked to be deleted.");
	return TRUE;
}

struct cmd_list_context {
	unsigned int msgnum;
};

static void cmd_list_callback(struct client *client)
{
	struct cmd_list_context *ctx = client->cmd_context;
	int ret;

	for (; ctx->msgnum != client->messages_count; ctx->msgnum++) {
		if (client->deleted) {
			if (client->deleted_bitmask[ctx->msgnum / CHAR_BIT] &
			    (1 << (ctx->msgnum % CHAR_BIT)))
				continue;
		}
		ret = client_send_line(client, "%u %"PRIuUOFF_T,
				       ctx->msgnum+1,
				       client->message_sizes[ctx->msgnum]);
		if (ret < 0)
			break;
		if (ret == 0)
			return;
	}

	client_send_line(client, ".");

	i_free(ctx);
	client->cmd = NULL;
}

static int cmd_list(struct client *client, const char *args)
{
        struct cmd_list_context *ctx;

	if (*args == '\0') {
		ctx = i_new(struct cmd_list_context, 1);
		client_send_line(client, "+OK %u messages:",
				 client->messages_count - client->deleted_count);

		client->cmd = cmd_list_callback;
		client->cmd_context = ctx;
		cmd_list_callback(client);
	} else {
		unsigned int msgnum;

		if (get_msgnum(client, args, &msgnum) == NULL)
			return FALSE;

		client_send_line(client, "+OK %u %"PRIuUOFF_T, msgnum+1,
				 client->message_sizes[msgnum]);
	}

	return TRUE;
}

static int cmd_last(struct client *client, const char *args __attr_unused__)
{
	client_send_line(client, "+OK %u", client->last_seen);
	return TRUE;
}

static int cmd_noop(struct client *client, const char *args __attr_unused__)
{
	client_send_line(client, "+OK");
	return TRUE;
}

static int cmd_quit(struct client *client, const char *args __attr_unused__)
{
	if (client->deleted) {
		if (!client_update_mailbox(client, client->mailbox, TRUE)) {
			client_send_storage_error(client);
			client_disconnect(client);
			return TRUE;
		}

		/* don't sync them again at client_destroy() */
		i_free(client->seen_bitmask);
                client->seen_bitmask = NULL;
	}

	if (!client->deleted)
		client_send_line(client, "+OK Logging out.");
	else
		client_send_line(client, "+OK Logging out, messages deleted.");

	client_disconnect(client);
	return TRUE;
}

struct fetch_context {
        struct mailbox_transaction_context *t;
	struct mail_search_context *search_ctx;
	struct istream *stream;
	uoff_t body_lines;

	struct mail_search_arg search_arg;
        struct mail_search_seqset seqset;

	unsigned char last;
	int cr_skipped, in_body;
};

static void fetch_deinit(struct fetch_context *ctx)
{
	(void)mailbox_search_deinit(ctx->search_ctx);
	(void)mailbox_transaction_commit(ctx->t, 0);
	i_free(ctx);
}

static void fetch_callback(struct client *client)
{
	struct fetch_context *ctx = client->cmd_context;
	const unsigned char *data;
	unsigned char add;
	size_t i, size;

	o_stream_uncork(client->output);

	while ((ctx->body_lines > 0 || !ctx->in_body) &&
	       i_stream_read_data(ctx->stream, &data, &size, 0) > 0) {
		if (size > 4096)
			size = 4096;

		add = '\0';
		for (i = 0; i < size; i++) {
			if ((data[i] == '\r' || data[i] == '\n') &&
			    !ctx->in_body) {
				if (i == 0 && (ctx->last == '\0' ||
					       ctx->last == '\n'))
					ctx->in_body = TRUE;
				else if (i > 0 && data[i-1] == '\n')
					ctx->in_body = TRUE;
			}

			if (data[i] == '\n') {
				if ((i == 0 && ctx->last != '\r') ||
				    (i > 0 && data[i-1] != '\r')) {
					/* missing CR */
					add = '\r';
					break;
				}

				if (ctx->in_body) {
					if (--ctx->body_lines == 0) {
						i++;
						break;
					}
				}
			} else if (data[i] == '.' &&
				   ((i == 0 && ctx->last == '\n') ||
				    (i > 0 && data[i-1] == '\n'))) {
				/* escape the dot */
				add = '.';
				break;
			} else if (data[i] == '\0' &&
				   (client_workarounds &
				    WORKAROUND_OUTLOOK_NO_NULS) != 0) {
				add = 0x80;
				break;
			}
		}

		if (i > 0) {
			if (o_stream_send(client->output, data, i) < 0)
				break;
			ctx->last = data[i-1];
			i_stream_skip(ctx->stream, i);
		}

		if (o_stream_get_buffer_used_size(client->output) > 0) {
			if (client->output->closed)
				break;

			/* continue later */
			return;
		}

		if (add != '\0') {
			if (o_stream_send(client->output, &add, 1) < 0)
				break;

			ctx->last = add;
			if (add == 0x80)
				i_stream_skip(ctx->stream, 1);
		}
	}

	if (ctx->last != '\n') {
		/* didn't end with CRLF */
		(void)o_stream_send(client->output, "\r\n", 2);
	}

	client_send_line(client, ".");
	fetch_deinit(ctx);
	client->cmd = NULL;
}

static void fetch(struct client *client, unsigned int msgnum, uoff_t body_lines)
{
        struct fetch_context *ctx;
	struct mail *mail;

	ctx = i_new(struct fetch_context, 1);

	ctx->seqset.seq1 = ctx->seqset.seq2 = msgnum+1;
	ctx->search_arg.type = SEARCH_SEQSET;
	ctx->search_arg.value.seqset = &ctx->seqset;

	ctx->t = mailbox_transaction_begin(client->mailbox, FALSE);
	ctx->search_ctx = mailbox_search_init(ctx->t, NULL, &ctx->search_arg,
					      NULL, MAIL_FETCH_STREAM_HEADER |
					      MAIL_FETCH_STREAM_BODY, NULL);
	mail = mailbox_search_next(ctx->search_ctx);
	ctx->stream = mail == NULL ? NULL : mail->get_stream(mail, NULL, NULL);
	if (ctx->stream == NULL) {
		client_send_line(client, "-ERR Message not found.");
		fetch_deinit(ctx);
		return;
	}

	if (body_lines == (uoff_t)-1) {
		/* mark the message seen with RETR command */
		if (client->seen_bitmask == NULL) {
			client->seen_bitmask =
				i_malloc(MSGS_BITMASK_SIZE(client));
		}
		client->seen_bitmask[msgnum / CHAR_BIT] |=
			1 << (msgnum % CHAR_BIT);
	}

	ctx->body_lines = body_lines;
	if (body_lines == (uoff_t)-1) {
		client_send_line(client, "+OK %"PRIuUOFF_T" octets",
				 client->message_sizes[msgnum]);
	} else {
		client_send_line(client, "+OK");
		ctx->body_lines++; /* internally we count the empty line too */
	}

	client->cmd = fetch_callback;
	client->cmd_context = ctx;
	fetch_callback(client);
}

static int cmd_retr(struct client *client, const char *args)
{
	unsigned int msgnum;

	if (get_msgnum(client, args, &msgnum) == NULL)
		return FALSE;

	if (client->last_seen <= msgnum)
		client->last_seen = msgnum+1;

	fetch(client, msgnum, (uoff_t)-1);
	return TRUE;
}

static int cmd_rset(struct client *client, const char *args __attr_unused__)
{
	struct mailbox_transaction_context *t;
	struct mail_search_context *search_ctx;
	struct mail *mail;
	struct mail_search_arg search_arg;
	struct mail_full_flags seen_flag;

	client->last_seen = 0;

	if (client->deleted) {
		client->deleted = FALSE;
		memset(client->deleted_bitmask, 0, MSGS_BITMASK_SIZE(client));
		client->deleted_count = 0;
		client->deleted_size = 0;
	}

	if (enable_last_command) {
		/* remove all \Seen flags */
		memset(&search_arg, 0, sizeof(search_arg));
		search_arg.type = SEARCH_ALL;

		memset(&seen_flag, 0, sizeof(seen_flag));
		seen_flag.flags = MAIL_SEEN;

		t = mailbox_transaction_begin(client->mailbox, FALSE);
		search_ctx = mailbox_search_init(t, NULL, &search_arg,
						 NULL, 0, NULL);
		while ((mail = mailbox_search_next(search_ctx)) != NULL) {
			if (mail->update_flags(mail, &seen_flag,
					       MODIFY_REMOVE) < 0)
				break;
		}
		(void)mailbox_search_deinit(search_ctx);
		(void)mailbox_transaction_commit(t, 0);
	}

	client_send_line(client, "+OK");
	return TRUE;
}

static int cmd_stat(struct client *client, const char *args __attr_unused__)
{
	client_send_line(client, "+OK %u %"PRIuUOFF_T, client->
			 messages_count - client->deleted_count,
			 client->total_size - client->deleted_size);
	return TRUE;
}

static int cmd_top(struct client *client, const char *args)
{
	unsigned int msgnum;
	uoff_t max_lines;

	args = get_msgnum(client, args, &msgnum);
	if (args == NULL)
		return FALSE;
	if (get_size(client, args, &max_lines) == NULL)
		return FALSE;

	fetch(client, msgnum, max_lines);
	return TRUE;
}

struct cmd_uidl_context {
        struct mailbox_transaction_context *t;
	struct mail_search_context *search_ctx;
	unsigned int message;

	struct mail_search_arg search_arg;
	struct mail_search_seqset seqset;
};

static int list_uids_iter(struct client *client, struct cmd_uidl_context *ctx)
{
	struct mail *mail;
	const char *uid_str;
	int ret, found = FALSE;

	while ((mail = mailbox_search_next(ctx->search_ctx)) != NULL) {
		if (client->deleted) {
			uint32_t idx = mail->seq - 1;
			if (client->deleted_bitmask[idx / CHAR_BIT] &
			    (1 << (idx % CHAR_BIT)))
				continue;
		}

		uid_str = mail->get_special(mail, MAIL_FETCH_UID_STRING);
		found = TRUE;

		ret = client_send_line(client, ctx->message == 0 ?
				       "%u %s" : "+OK %u %s",
				       mail->seq, uid_str);
		if (ret < 0)
			break;
		if (ret == 0 && ctx->message == 0) {
			/* output is being buffered, continue when there's
			   more space */
			return 0;
		}
	}

	/* finished */
	(void)mailbox_search_deinit(ctx->search_ctx);
	(void)mailbox_transaction_commit(ctx->t, 0);

	client->cmd = NULL;

	if (ctx->message == 0)
		client_send_line(client, ".");
	i_free(ctx);
	return found;
}

static void cmd_uidl_callback(struct client *client)
{
	struct cmd_uidl_context *ctx = client->cmd_context;

        (void)list_uids_iter(client, ctx);
}

static struct cmd_uidl_context *
cmd_uidl_init(struct client *client, unsigned int message)
{
        struct cmd_uidl_context *ctx;

	ctx = i_new(struct cmd_uidl_context, 1);

	if (message == 0)
		ctx->search_arg.type = SEARCH_ALL;
	else {
		ctx->message = message;
		ctx->seqset.seq1 = ctx->seqset.seq2 = message;
		ctx->search_arg.type = SEARCH_SEQSET;
		ctx->search_arg.value.seqset = &ctx->seqset;
	}

	ctx->t = mailbox_transaction_begin(client->mailbox, FALSE);
	ctx->search_ctx = mailbox_search_init(ctx->t, NULL, &ctx->search_arg,
					      NULL, 0, NULL);
	if (message == 0) {
		client->cmd = cmd_uidl_callback;
		client->cmd_context = ctx;
	}
	return ctx;
}

static int cmd_uidl(struct client *client, const char *args)
{
        struct cmd_uidl_context *ctx;

	if (*args == '\0') {
		client_send_line(client, "+OK");
		ctx = cmd_uidl_init(client, 0);
		list_uids_iter(client, ctx);
	} else {
		unsigned int msgnum;

		if (get_msgnum(client, args, &msgnum) == NULL)
			return FALSE;

		ctx = cmd_uidl_init(client, msgnum+1);
		if (!list_uids_iter(client, ctx))
			client_send_line(client, "-ERR Message not found.");
	}

	return TRUE;
}

int client_command_execute(struct client *client,
			    const char *name, const char *args)
{
	/* keep the command uppercased */
	name = t_str_ucase(name);

	while (*args == ' ') args++;

	switch (*name) {
	case 'C':
		if (strcmp(name, "CAPA") == 0)
			return cmd_capa(client, args);
		break;
	case 'D':
		if (strcmp(name, "DELE") == 0)
			return cmd_dele(client, args);
		break;
	case 'L':
		if (strcmp(name, "LIST") == 0)
			return cmd_list(client, args);
		if (strcmp(name, "LAST") == 0 && enable_last_command)
			return cmd_last(client, args);
		break;
	case 'N':
		if (strcmp(name, "NOOP") == 0)
			return cmd_noop(client, args);
		break;
	case 'Q':
		if (strcmp(name, "QUIT") == 0)
			return cmd_quit(client, args);
		break;
	case 'R':
		if (strcmp(name, "RETR") == 0)
			return cmd_retr(client, args);
		if (strcmp(name, "RSET") == 0)
			return cmd_rset(client, args);
		break;
	case 'S':
		if (strcmp(name, "STAT") == 0)
			return cmd_stat(client, args);
		break;
	case 'T':
		if (strcmp(name, "TOP") == 0)
			return cmd_top(client, args);
		break;
	case 'U':
		if (strcmp(name, "UIDL") == 0)
			return cmd_uidl(client, args);
		break;
	}

	client_send_line(client, "-ERR Unknown command: %s", name);
	return FALSE;
}
