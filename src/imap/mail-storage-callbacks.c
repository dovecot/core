/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "obuffer.h"
#include "imap-util.h"
#include "commands-util.h"

static void alert_no_diskspace(Mailbox *mailbox __attr_unused__, void *context)
{
	Client *client = context;

	client_send_line(client, "* NO [ALERT] "
			 "Disk space is full, delete some messages.");
}

static void notify_ok(Mailbox *mailbox __attr_unused__,
		      const char *text, void *context)
{
	Client *client = context;

	client_send_line(client, t_strconcat("* OK ", text, NULL));
	o_buffer_flush(client->outbuf);
}

static void notify_no(Mailbox *mailbox __attr_unused__,
		      const char *text, void *context)
{
	Client *client = context;

	client_send_line(client, t_strconcat("* NO ", text, NULL));
	o_buffer_flush(client->outbuf);
}

static void expunge(Mailbox *mailbox, unsigned int seq, void *context)
{
	Client *client = context;
	char str[MAX_INT_STRLEN+20];

	if (client->mailbox != mailbox)
		return;

	i_snprintf(str, sizeof(str), "* %u EXPUNGE", seq);
	client_send_line(client, str);
}

static void update_flags(Mailbox *mailbox, unsigned int seq, unsigned int uid,
			 MailFlags flags, const char *custom_flags[],
			 unsigned int custom_flags_count, void *context)
{
	Client *client = context;
	const char *str;

	if (client->mailbox != mailbox)
		return;

	t_push();
	str = imap_write_flags(flags, custom_flags, custom_flags_count);

	if (client->sync_flags_send_uid) {
		str = t_strdup_printf("* %u FETCH (FLAGS (%s) UID %u)",
				      seq, str, uid);
	} else {
		str = t_strdup_printf("* %u FETCH (FLAGS (%s))", seq, str);
	}

	client_send_line(client, str);
	t_pop();
}

static void new_messages(Mailbox *mailbox, unsigned int messages_count,
			 unsigned int recent_count, void *context)
{
	Client *client = context;
	char str[MAX_INT_STRLEN+20];

	if (client->mailbox != mailbox)
		return;

	i_snprintf(str, sizeof(str), "* %u EXISTS", messages_count);
	client_send_line(client, str);

	i_snprintf(str, sizeof(str), "* %u RECENT", recent_count);
	client_send_line(client, str);
}

static void new_custom_flags(Mailbox *mailbox, const char *custom_flags[],
			     unsigned int custom_flags_count, void *context)
{
	Client *client = context;

	if (client->mailbox != mailbox)
		return;

	client_send_mailbox_flags(client, mailbox, custom_flags,
				  custom_flags_count);
}

MailStorageCallbacks mail_storage_callbacks = {
	alert_no_diskspace,
	notify_ok,
	notify_no,
	expunge,
	update_flags,
	new_messages,
	new_custom_flags
};
