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
	const char *str;

	if (o_stream_get_buffer_used_size(client->output) != 0)
		return;

	t_push();
	str = t_strconcat("* OK ", text, "\r\n", NULL);
	o_stream_send_str(client->output, str);
	t_pop();
}

static void notify_no(struct mailbox *mailbox __attr_unused__,
		      const char *text, void *context)
{
	struct client *client = context;
	const char *str;

	if (o_stream_get_buffer_used_size(client->output) != 0)
		return;

	t_push();
	str = t_strconcat("* NO ", text, "\r\n", NULL);
	o_stream_send_str(client->output, str);
	t_pop();
}

struct mail_storage_callbacks mail_storage_callbacks = {
	alert_no_diskspace,
	notify_ok,
	notify_no
};
