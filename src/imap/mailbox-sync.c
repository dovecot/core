/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "imap-util.h"
#include "commands-util.h"

static void sync_alert_no_diskspace(Mailbox *mailbox __attr_unused__,
				    void *context)
{
	Client *client = context;

	client_send_line(client, "* NO [ALERT] "
			 "Disk space is full, delete some messages.");

}

static void sync_expunge(Mailbox *mailbox __attr_unused__, unsigned int seq,
			 void *context)
{
	Client *client = context;
	char str[MAX_LARGEST_T_STRLEN+20];

	i_snprintf(str, sizeof(str), "* %u EXPUNGE", seq);
	client_send_line(client, str);
}

static void sync_update_flags(Mailbox *mailbox __attr_unused__,
			      unsigned int seq, unsigned int uid,
			      MailFlags flags, const char *custom_flags[],
			      unsigned int custom_flags_count, void *context)
{
	Client *client = context;
	const char *str;

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

static void sync_new_messages(Mailbox *mailbox __attr_unused__,
			      unsigned int messages_count,
			      unsigned int recent_count, void *context)
{
	Client *client = context;
	char str[MAX_LARGEST_T_STRLEN+20];

	i_snprintf(str, sizeof(str), "* %u EXISTS", messages_count);
	client_send_line(client, str);

	i_snprintf(str, sizeof(str), "* %u RECENT", recent_count);
	client_send_line(client, str);
}

static void sync_new_custom_flags(Mailbox *mailbox, const char *custom_flags[],
				  unsigned int custom_flags_count,
				  void *context)
{
	Client *client = context;

	client_send_mailbox_flags(client, mailbox, custom_flags,
				  custom_flags_count);
}

MailboxSyncCallbacks sync_callbacks = {
	sync_alert_no_diskspace,
	sync_expunge,
	sync_update_flags,
	sync_new_messages,
	sync_new_custom_flags
};
