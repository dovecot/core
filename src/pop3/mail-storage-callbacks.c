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
		    unsigned int seq __attr_unused__,
		    void *context __attr_unused__)
{
}

static void update_flags(struct mailbox *mailbox __attr_unused__,
			 unsigned int seq __attr_unused__,
			 unsigned int uid __attr_unused__,
			 enum mail_flags flags __attr_unused__,
			 const char *custom_flags[] __attr_unused__,
			 unsigned int custom_flags_count __attr_unused__,
			 void *context __attr_unused__)
{
}

static void new_messages(struct mailbox *mailbox __attr_unused__,
			 unsigned int messages_count __attr_unused__,
			 unsigned int recent_count __attr_unused__,
			 void *context __attr_unused__)
{
}

static void new_custom_flags(struct mailbox *mailbox __attr_unused__,
			     const char *custom_flags[] __attr_unused__,
			     unsigned int custom_flags_count __attr_unused__,
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
	new_custom_flags
};
