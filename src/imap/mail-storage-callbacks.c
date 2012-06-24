/* Copyright (c) 2002-2012 Dovecot authors, see the included COPYING file */

#include "imap-common.h"
#include "ostream.h"
#include "mail-storage.h"
#include "imap-commands-util.h"

static void notify_ok(struct mailbox *mailbox ATTR_UNUSED,
		      const char *text, void *context)
{
	struct client *client = context;

	if (o_stream_get_buffer_used_size(client->output) != 0)
		return;

	T_BEGIN {
		const char *str;

		str = t_strconcat("* OK ", text, "\r\n", NULL);
		o_stream_nsend_str(client->output, str);
		(void)o_stream_flush(client->output);
	} T_END;
}

static void notify_no(struct mailbox *mailbox ATTR_UNUSED,
		      const char *text, void *context)
{
	struct client *client = context;

	if (o_stream_get_buffer_used_size(client->output) != 0)
		return;

	T_BEGIN {
		const char *str;

		str = t_strconcat("* NO ", text, "\r\n", NULL);
		o_stream_nsend_str(client->output, str);
		(void)o_stream_flush(client->output);
	} T_END;
}

struct mail_storage_callbacks mail_storage_callbacks = {
	notify_ok,
	notify_no
};
