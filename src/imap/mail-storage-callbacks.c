/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "ostream.h"
#include "imap-util.h"
#include "mail-storage.h"
#include "commands-util.h"

static void alert_no_diskspace(struct mailbox *mailbox __attr_unused__,
			       void *context)
{
	struct client *client = context;

	client_send_line(client, "* NO [ALERT] "
			 "Disk space is full, delete some messages.");
}

static void notify_ok(struct mailbox *mailbox __attr_unused__,
		      const char *text, void *context)
{
	struct client *client = context;

	client_send_line(client, t_strconcat("* OK ", text, NULL));
	o_stream_flush(client->output);
}

static void notify_no(struct mailbox *mailbox __attr_unused__,
		      const char *text, void *context)
{
	struct client *client = context;

	client_send_line(client, t_strconcat("* NO ", text, NULL));
	o_stream_flush(client->output);
}

static void expunge(struct mailbox *mailbox, unsigned int seq, void *context)
{
	struct client *client = context;
	char str[MAX_INT_STRLEN+20];

	if (client->mailbox != mailbox)
		return;

	i_snprintf(str, sizeof(str), "* %u EXPUNGE", seq);
	client_send_line(client, str);
}

static void update_flags(struct mailbox *mailbox, unsigned int seq,
			 const struct mail_full_flags *flags, void *context)
{
	struct client *client = context;
	const char *str;

	if (client->mailbox != mailbox)
		return;

	t_push();
	str = imap_write_flags(flags);
	str = t_strdup_printf("* %u FETCH (FLAGS (%s))", seq, str);
	client_send_line(client, str);
	t_pop();
}

static void new_messages(struct mailbox *mailbox, unsigned int messages_count,
			 unsigned int recent_count, void *context)
{
	struct client *client = context;
	char str[MAX_INT_STRLEN+20];

	if (client->mailbox != mailbox)
		return;

	i_snprintf(str, sizeof(str), "* %u EXISTS", messages_count);
	client_send_line(client, str);

	i_snprintf(str, sizeof(str), "* %u RECENT", recent_count);
	client_send_line(client, str);
}

static void new_custom_flags(struct mailbox *mailbox,
			     const char *custom_flags[],
			     unsigned int custom_flags_count, void *context)
{
	struct client *client = context;

	if (client->mailbox != mailbox)
		return;

	client_save_custom_flags(&client->mailbox_flags, custom_flags,
				 custom_flags_count);

	client_send_mailbox_flags(client, mailbox, custom_flags,
				  custom_flags_count);
}

struct mail_storage_callbacks mail_storage_callbacks = {
	alert_no_diskspace,
	notify_ok,
	notify_no,
	expunge,
	update_flags,
	new_messages,
	new_custom_flags
};
