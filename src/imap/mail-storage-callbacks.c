/* Copyright (c) 2002-2007 Dovecot authors, see the included COPYING file */

#include "common.h"
#include "ostream.h"
#include "mail-storage.h"
#include "commands-util.h"

static void notify_ok(struct mailbox *mailbox ATTR_UNUSED,
		      const char *text, void *context)
{
	struct client *client = context;

	if (o_stream_get_buffer_used_size(client->output) != 0)
		return;

	T_FRAME(
		const char *str;

		str = t_strconcat("* OK ", text, "\r\n", NULL);
		o_stream_send_str(client->output, str);
		o_stream_flush(client->output);
	);
}

static void notify_no(struct mailbox *mailbox ATTR_UNUSED,
		      const char *text, void *context)
{
	struct client *client = context;

	if (o_stream_get_buffer_used_size(client->output) != 0)
		return;

	T_FRAME(
		const char *str;

		str = t_strconcat("* NO ", text, "\r\n", NULL);
		o_stream_send_str(client->output, str);
		o_stream_flush(client->output);
	);
}

struct mail_storage_callbacks mail_storage_callbacks = {
	notify_ok,
	notify_no
};
