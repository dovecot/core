/* Copyright (c) 2015-2018 Dovecot authors, see the included COPYING file */

#ifndef PUSH_NOTIFICATION_EVENT_FLAGSSET_H
#define PUSH_NOTIFICATION_EVENT_FLAGSSET_H

#include "mail-types.h"

struct push_notification_event_flagsset_config {
	/* RFC 5423[4.2] - allow configuration whether FlagsSet event returns
	   Deleted and/or Seen flags, since these flags are also settable via
	   MessageRead/MessageTrash events. By default, include them here. */
	bool hide_deleted;
	bool hide_seen;
};

struct push_notification_event_flagsset_data {
	enum mail_flags flags_set;
	ARRAY_TYPE(keywords) keywords_set;
};

#endif

