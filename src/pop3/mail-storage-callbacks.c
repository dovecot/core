/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "imap-util.h"
#include "mail-storage.h"

static void alert_no_diskspace(struct mailbox *mailbox __attr_unused__,
			       void *context __attr_unused__)
{
}

static void notify_ok(struct mailbox *mailbox __attr_unused__,
		      const char *text __attr_unused__,
		      void *context __attr_unused__)
{
}

static void notify_no(struct mailbox *mailbox __attr_unused__,
		      const char *text __attr_unused__,
		      void *context __attr_unused__)
{
}

static void expunge(struct mailbox *mailbox __attr_unused__,
		    unsigned int seq, void *context)
{
	struct client *client = context;
	unsigned char *mask = client->deleted_bitmask;
	unsigned int max, i, j;

	/* external deletes - we have to fix our internal deleted array.
	   this should happen only when we're doing the expunging at quit. */
	seq--;
	client->messages_count--;

	if (!client->deleted)
		return;

	max = client->messages_count / CHAR_BIT;
	i = seq / CHAR_BIT; j = seq % CHAR_BIT;
	mask[i] = (mask[i] & ((1 << j) - 1)) |
		((mask[i] >> (j+1)) << j) |
		(i == max ? 0 : ((mask[i+1] & 1) << (CHAR_BIT-1)));

	if (i != max) {
		for (i++; i < max-1; i++) {
			mask[i] = (mask[i] >> 1) |
				((mask[i+1] & 1) << (CHAR_BIT-1));
		}

		mask[i] >>= 1;
	}
}

static void update_flags(struct mailbox *mailbox __attr_unused__,
			 unsigned int seq __attr_unused__,
			 const struct mail_full_flags *flags __attr_unused__,
			 void *context __attr_unused__)
{
}

static void new_messages(struct mailbox *mailbox __attr_unused__,
			 unsigned int messages_count __attr_unused__,
			 unsigned int recent_count __attr_unused__,
			 void *context __attr_unused__)
{
}

static void new_keywords(struct mailbox *mailbox __attr_unused__,
			 const char *keywords[] __attr_unused__,
			 unsigned int keywords_count __attr_unused__,
			 void *context __attr_unused__)
{
}

struct mail_storage_callbacks mail_storage_callbacks = {
	alert_no_diskspace,
	notify_ok,
	notify_no,
	expunge,
	update_flags,
	new_messages,
	new_keywords
};
