#ifndef DSYNC_MAILBOX_H
#define DSYNC_MAILBOX_H

#include "mail-storage.h"

/* Mailbox that is going to be synced. Its name was already sent in the
   mailbox tree. */
struct dsync_mailbox {
	guid_128_t mailbox_guid;
	bool mailbox_lost;

	uint32_t uid_validity, uid_next, messages_count, first_recent_uid;
	uint64_t highest_modseq;
	ARRAY_TYPE(mailbox_cache_field) cache_fields;
};

#endif
