/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "str.h"
#include "message-size.h"
#include "mail-storage.h"
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

	if (num > client->messages_count) {
		client_send_line(client,
				 "-ERR There's only %u messages.",
				 client->messages_count);
		return NULL;
	}

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

static void cmd_dele(struct client *client, const char *args)
{
	unsigned int msgnum;

	if (get_msgnum(client, args, &msgnum) == NULL)
		return;

	if (!client->deleted) {
		client->deleted_bitmask = i_malloc(MSGS_BITMASK_SIZE(client));
		client->deleted = TRUE;
	}

	client->deleted_bitmask[msgnum / CHAR_BIT] |= 1 << (msgnum % CHAR_BIT);
	client_send_line(client, "+OK Marked to be deleted.");
}

static void cmd_list(struct client *client, const char *args)
{
	unsigned int i;

	if (*args == '\0') {
		client_send_line(client, "+OK %u messages:",
				 client->messages_count);
		for (i = 0; i < client->messages_count; i++) {
			client_send_line(client, "%u %"PRIuUOFF_T,
					 i, client->message_sizes[i]);
		}
		client_send_line(client, ".");
	} else {
		unsigned int msgnum;

		if (get_msgnum(client, args, &msgnum) != NULL) {
			client_send_line(client, "+OK %u %"PRIuUOFF_T,
					 msgnum, client->message_sizes[msgnum]);
		}
	}
}

static void cmd_noop(struct client *client, const char *args __attr_unused__)
{
	client_send_line(client, "+OK");
}

static void cmd_quit(struct client *client, const char *args __attr_unused__)
{
	unsigned int first, last, msgnum, max, i, j;
	struct mail_full_flags flags;
	string_t *set;

	if (!client->deleted) {
		client_send_line(client, "+OK Logging out.");
		client_disconnect(client);
		return;
	}

	set = t_str_new(1024);
	first = last = 0; msgnum = 1;
	max = MSGS_BITMASK_SIZE(client);
	for (i = 0; i < max; i++) {
		if (client->deleted_bitmask[i] == 0) {
                        msgnum += CHAR_BIT;
			continue;
		}

		for (j = 0; j < CHAR_BIT; j++, msgnum++) {
			if ((client->deleted_bitmask[i] & (1 << j)) == 0)
				continue;

			if (last == msgnum-1 && last != 0)
				last++;
			else {
				if (first == last)
					str_printfa(set, ",%u", first);
				else
					str_printfa(set, ",%u:%u", first, last);
				first = last = msgnum;
			}
		}
	}

	if (first != 0) {
		if (first == last)
			str_printfa(set, ",%u", first);
		else
			str_printfa(set, ",%u:%u", first, last);
	}

	if (str_len(set) == 0)
		client_send_line(client, "+OK Logging out.");
	else if (client->mailbox->update_flags(client->mailbox, str_c(set),
					       FALSE, &flags, MODIFY_ADD,
					       FALSE, NULL) &&
		 client->mailbox->expunge(client->mailbox, FALSE))
		client_send_line(client, "+OK Logging out, messages deleted.");
	else
		client_send_storage_error(client);

	client_disconnect(client);
}

static void fetch(struct client *client, unsigned int msgnum, uoff_t max_lines)
{
	struct mail_fetch_context *ctx;
	struct mail *mail;
	struct istream *stream;

	ctx = client->mailbox->fetch_init(client->mailbox,
					  MAIL_FETCH_STREAM_HEADER |
					  MAIL_FETCH_STREAM_BODY,
					  NULL, t_strdup_printf("%u", msgnum),
					  FALSE);
	if (ctx == NULL) {
		client_send_storage_error(client);
		return;
	}

	mail = client->mailbox->fetch_next(ctx);
	if (mail == NULL)
		client_send_line(client, "-ERR Message not found.");
	else {
		stream = mail->get_stream(mail, NULL, NULL);

		if (max_lines == (uoff_t)-1) {
			client_send_line(client, "+OK %"PRIuUOFF_T" octets",
					 client->message_sizes[msgnum]);
		} else {
			client_send_line(client, "+OK");
		}

		// FIXME: "." lines needs to be escaped
		// FIXME: and send only max_lines
		client_send_line(client, ".");
	}

	(void)client->mailbox->fetch_deinit(ctx, NULL);
}

static void cmd_retr(struct client *client, const char *args)
{
	unsigned int msgnum;

	if (get_msgnum(client, args, &msgnum) != NULL)
		fetch(client, msgnum, (uoff_t)-1);
}

static void cmd_rset(struct client *client, const char *args __attr_unused__)
{
	if (client->deleted) {
		client->deleted = FALSE;
		memset(client->deleted_bitmask, 0, MSGS_BITMASK_SIZE(client));
	}

	client_send_line(client, "+OK");
}

static void cmd_stat(struct client *client, const char *args __attr_unused__)
{
	client_send_line(client, "+OK %u %"PRIuUOFF_T, client->
			 messages_count, client->total_size);
}

static void cmd_top(struct client *client, const char *args)
{
	unsigned int msgnum;
	uoff_t max_lines;

	if (get_msgnum(client, args, &msgnum) != NULL &&
	    get_size(client, args, &max_lines))
		fetch(client, msgnum, max_lines);
}

static void list_uids(struct client *client, unsigned int message)
{
	struct mail_fetch_context *ctx;
	struct mail *mail;
	const char *messageset;
	int found = FALSE;

	if (client->messages_count == 0 && message == 0)
		return;

	messageset = message == 0 ?
		t_strdup_printf("1:%u", client->messages_count) :
		t_strdup_printf("%u", message);

	ctx = client->mailbox->fetch_init(client->mailbox, 0,
					  NULL, messageset, FALSE);
	if (ctx == NULL) {
		client_send_storage_error(client);
		return;
	}

	while ((mail = client->mailbox->fetch_next(ctx)) != NULL) {
		client_send_line(client, message == 0 ?
				 "%u %u.%u" : "+OK %u %u.%u",
				 mail->seq, client->uidvalidity, mail->uid);
		found = TRUE;
	}

	(void)client->mailbox->fetch_deinit(ctx, NULL);

	if (!found && message != 0)
		client_send_line(client, "-ERR Message not found.");
}

static void cmd_uidl(struct client *client, const char *args)
{
	if (*args == '\0') {
		client_send_line(client, "+OK");
		list_uids(client, 0);
		client_send_line(client, ".");
	} else {
		unsigned int msgnum;

		if (get_msgnum(client, args, &msgnum) != NULL)
			list_uids(client, msgnum);
	}
}

void client_command_execute(struct client *client,
			    const char *name, const char *args)
{
	/* keep the command uppercased */
	name = str_ucase(t_strdup_noconst(name));

	while (*args == ' ') args++;

	switch (*name) {
	case 'D':
		if (strcmp(name, "DELE") == 0) {
			cmd_dele(client, args);
			return;
		}
		break;
	case 'L':
		if (strcmp(name, "LIST") == 0) {
			cmd_list(client, args);
			return;
		}
		break;
	case 'N':
		if (strcmp(name, "NOOP") == 0) {
			cmd_noop(client, args);
			return;
		}
		break;
	case 'Q':
		if (strcmp(name, "QUIT") == 0) {
			cmd_quit(client, args);
			return;
		}
		break;
	case 'R':
		if (strcmp(name, "RETR") == 0) {
			cmd_retr(client, args);
			return;
		}
		if (strcmp(name, "RSET") == 0) {
			cmd_rset(client, args);
			return;
		}
		break;
	case 'S':
		if (strcmp(name, "STAT") == 0) {
			cmd_stat(client, args);
			return;
		}
		break;
	case 'T':
		if (strcmp(name, "TOP") == 0) {
			cmd_top(client, args);
			return;
		}
		break;
	case 'U':
		if (strcmp(name, "UIDL") == 0) {
			cmd_uidl(client, args);
			return;
		}
		break;
	}

	client_send_line(client, "-ERR Unknown command: %s", name);
}
