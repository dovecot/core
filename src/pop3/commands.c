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

static int cmd_list(struct client *client, const char *args)
{
	unsigned int i;

	if (*args == '\0') {
		client_send_line(client, "+OK %u messages:",
				 client->messages_count - client->deleted_count);
		for (i = 0; i < client->messages_count; i++) {
			if (client->deleted) {
				if (client->deleted_bitmask[i / CHAR_BIT] &
				    (1 << (i % CHAR_BIT)))
					continue;
			}
			client_send_line(client, "%u %"PRIuUOFF_T,
					 i+1, client->message_sizes[i]);
		}
		client_send_line(client, ".");
	} else {
		unsigned int msgnum;

		if (get_msgnum(client, args, &msgnum) == NULL)
			return FALSE;

		client_send_line(client, "+OK %u %"PRIuUOFF_T, msgnum+1,
				 client->message_sizes[msgnum]);
	}

	return TRUE;
}

static int cmd_noop(struct client *client, const char *args __attr_unused__)
{
	client_send_line(client, "+OK");
	return TRUE;
}

static int expunge_mails(struct client *client, struct mailbox *box)
{
	struct mail_search_arg search_arg;
        struct mailbox_transaction_context *t;
	struct mail_search_context *ctx;
	struct mail *mail;
	uint32_t i;
	int failed = FALSE;

	memset(&search_arg, 0, sizeof(search_arg));
	search_arg.type = SEARCH_ALL;

	t = mailbox_transaction_begin(box, FALSE);
	ctx = mailbox_search_init(t, NULL, &search_arg, NULL,
				  MAIL_FETCH_SIZE, NULL);
	if (ctx == NULL) {
		mailbox_transaction_rollback(t);
		return FALSE;
	}

	while ((mail = mailbox_search_next(ctx)) != NULL) {
		i = mail->seq-1;
		if ((client->deleted_bitmask[i / CHAR_BIT] &
		     (1 << (i % CHAR_BIT))) != 0) {
			if (mail->expunge(mail) < 0) {
				failed = TRUE;
				break;
			}
		}
	}

	if (mailbox_search_deinit(ctx) < 0)
		return FALSE;

	mailbox_transaction_commit(t);
	return !failed;
}

static int cmd_quit(struct client *client, const char *args __attr_unused__)
{
	if (!client->deleted)
		client_send_line(client, "+OK Logging out.");
	else if (expunge_mails(client, client->mailbox))
		client_send_line(client, "+OK Logging out, messages deleted.");
	else
		client_send_storage_error(client);

	client_disconnect(client);
	return TRUE;
}

static void stream_send_escaped(struct ostream *output, struct istream *input,
				uoff_t body_lines)
{
	const unsigned char *data;
	unsigned char last, add;
	size_t i, size;
	int cr_skipped, in_header;

	if (body_lines != (uoff_t)-1)
		body_lines++; /* internally we count the empty line too */

	cr_skipped = FALSE; in_header = TRUE; last = '\0';
	while ((body_lines > 0 || in_header) &&
	       i_stream_read_data(input, &data, &size, 0) > 0) {
		add = '\0';
		for (i = 0; i < size; i++) {
			if (in_header && (data[i] == '\r' || data[i] == '\n')) {
				if (i == 0 && (last == '\0' || last == '\n'))
					in_header = FALSE;
				else if (i > 0 && data[i-1] == '\n')
					in_header = FALSE;
			}

			if (data[i] == '\n') {
				if ((i == 0 && last != '\r') ||
				    (i > 0 && data[i-1] != '\r')) {
					/* missing CR */
					add = '\r';
					break;
				}

				if (!in_header) {
					if (--body_lines == 0) {
						i++;
						break;
					}
				}
			} else if (data[i] == '.' &&
				   ((i == 0 && last == '\n') ||
				    (i > 0 && data[i-1] == '\n'))) {
				/* escape the dot */
				add = '.';
				i++;
				break;
			}
		}

		if (o_stream_send(output, data, i) < 0)
			return;

		if (add != '\0') {
			if (o_stream_send(output, &add, 1) < 0)
				return;
			last = add;
		} else {
			last = data[i-1];
		}

		i_stream_skip(input, i);
	}

	if (last != '\n') {
		/* didn't end with CRLF */
		(void)o_stream_send(output, "\r\n", 2);
	}
}

static void fetch(struct client *client, unsigned int msgnum,
		  uoff_t body_lines)
{
	struct mail_search_arg search_arg;
        struct mail_search_seqset seqset;
        struct mailbox_transaction_context *t;
	struct mail_search_context *ctx;
	struct mail *mail;
	struct istream *stream;

	memset(&seqset, 0, sizeof(seqset));
	seqset.seq1 = seqset.seq2 = msgnum+1;

	memset(&search_arg, 0, sizeof(search_arg));
	search_arg.type = SEARCH_SEQSET;
	search_arg.value.seqset = &seqset;

	t = mailbox_transaction_begin(client->mailbox, FALSE);
	ctx = mailbox_search_init(t, NULL, &search_arg, NULL,
				  MAIL_FETCH_STREAM_HEADER |
				  MAIL_FETCH_STREAM_BODY, NULL);
	if (ctx == NULL) {
		mailbox_transaction_rollback(t);
		client_send_storage_error(client);
		return;
	}

	mail = mailbox_search_next(ctx);
	stream = mail == NULL ? NULL : mail->get_stream(mail, NULL, NULL);
	if (stream == NULL)
		client_send_line(client, "-ERR Message not found.");
	else {
		if (body_lines == (uoff_t)-1) {
			client_send_line(client, "+OK %"PRIuUOFF_T" octets",
					 client->message_sizes[msgnum]);
		} else {
			client_send_line(client, "+OK");
		}

		stream_send_escaped(client->output, stream, body_lines);
		client_send_line(client, ".");
	}

	(void)mailbox_search_deinit(ctx);
	(void)mailbox_transaction_commit(t);
}

static int cmd_retr(struct client *client, const char *args)
{
	unsigned int msgnum;

	if (get_msgnum(client, args, &msgnum) == NULL)
		return FALSE;

	fetch(client, msgnum, (uoff_t)-1);
	return TRUE;
}

static int cmd_rset(struct client *client, const char *args __attr_unused__)
{
	if (client->deleted) {
		client->deleted = FALSE;
		memset(client->deleted_bitmask, 0, MSGS_BITMASK_SIZE(client));
		client->deleted_count = 0;
		client->deleted_size = 0;
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

static void list_uids(struct client *client, unsigned int message)
{
	struct mail_search_arg search_arg;
	struct mail_search_seqset seqset;
        struct mailbox_transaction_context *t;
	struct mail_search_context *ctx;
	struct mail *mail;
	int found = FALSE;

	if (client->messages_count == 0 && message == 0)
		return;

	memset(&search_arg, 0, sizeof(search_arg));
	if (message == 0)
		search_arg.type = SEARCH_ALL;
	else {
		seqset.seq1 = seqset.seq2 = message;
		search_arg.type = SEARCH_SEQSET;
		search_arg.value.seqset = &seqset;
	}

	t = mailbox_transaction_begin(client->mailbox, FALSE);
	ctx = mailbox_search_init(t, NULL, &search_arg, NULL, 0, NULL);
	if (ctx == NULL) {
		mailbox_transaction_rollback(t);
		client_send_storage_error(client);
		return;
	}

	while ((mail = mailbox_search_next(ctx)) != NULL) {
		if (client->deleted) {
			uint32_t idx = mail->seq - 1;
			if (client->deleted_bitmask[idx / CHAR_BIT] &
			    (1 << (idx % CHAR_BIT)))
				continue;
		}

		client_send_line(client, message == 0 ?
				 "%u %u.%u" : "+OK %u %u.%u",
				 mail->seq, client->uidvalidity, mail->uid);
		found = TRUE;
	}

	(void)mailbox_search_deinit(ctx);
	(void)mailbox_transaction_commit(t);

	if (!found && message != 0)
		client_send_line(client, "-ERR Message not found.");
}

static int cmd_uidl(struct client *client, const char *args)
{
	if (*args == '\0') {
		client_send_line(client, "+OK");
		list_uids(client, 0);
		client_send_line(client, ".");
	} else {
		unsigned int msgnum;

		if (get_msgnum(client, args, &msgnum) == NULL)
			return FALSE;

		list_uids(client, msgnum+1);
	}

	return TRUE;
}

int client_command_execute(struct client *client,
			    const char *name, const char *args)
{
	/* keep the command uppercased */
	name = str_ucase(t_strdup_noconst(name));

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
