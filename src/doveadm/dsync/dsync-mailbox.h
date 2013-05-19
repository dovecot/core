#ifndef DSYNC_MAILBOX_H
#define DSYNC_MAILBOX_H

#include "mail-storage.h"

/* Mailbox that is going to be synced. Its name was already sent in the
   mailbox tree. */
struct dsync_mailbox {
	guid_128_t mailbox_guid;
	bool mailbox_lost;
	bool have_guids, have_save_guids;

	uint32_t uid_validity, uid_next, messages_count, first_recent_uid;
	uint64_t highest_modseq, highest_pvt_modseq;
	ARRAY_TYPE(mailbox_cache_field) cache_fields;
};

struct dsync_mailbox_attribute {
	enum mail_attribute_type type;
	const char *key;
	/* if both values are NULL = not looked up yet / deleted */
	const char *value;
	struct istream *value_stream;

	time_t last_change; /* 0 = unknown */
	uint64_t modseq; /* 0 = unknown */

	bool deleted; /* attribute is known to have been deleted */
	bool exported; /* internally used by exporting */
};
#define DSYNC_ATTR_HAS_VALUE(attr) \
	((attr)->value != NULL || (attr)->value_stream != NULL)

void dsync_mailbox_attribute_dup(pool_t pool,
				 const struct dsync_mailbox_attribute *src,
				 struct dsync_mailbox_attribute *dest_r);

#endif
