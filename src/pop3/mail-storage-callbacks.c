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

struct mail_storage_callbacks mail_storage_callbacks = {
	alert_no_diskspace,
	notify_ok,
	notify_no
};
