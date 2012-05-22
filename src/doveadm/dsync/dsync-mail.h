#ifndef DSYNC_MAIL_H
#define DSYNC_MAIL_H

#include "mail-types.h"

struct mail;

struct dsync_mail {
	/* either GUID="" or uid=0 */
	const char *guid;
	uint32_t uid;

	const char *pop3_uidl;
	unsigned int pop3_order;
	time_t received_date;

	/* Input stream containing the message text, or NULL if all instances
	   of the message were already expunged from this mailbox. */
	struct istream *input;
};

struct dsync_mail_request {
	/* either GUID="" or uid=0 */
	const char *guid;
	uint32_t uid;
};

enum dsync_mail_change_type {
	DSYNC_MAIL_CHANGE_TYPE_SAVE,
	DSYNC_MAIL_CHANGE_TYPE_EXPUNGE,
	DSYNC_MAIL_CHANGE_TYPE_FLAG_CHANGE
};

#define KEYWORD_CHANGE_ADD '+'
#define KEYWORD_CHANGE_REMOVE '-'
#define KEYWORD_CHANGE_FINAL '='

struct dsync_mail_change {
	enum dsync_mail_change_type type;

	uint32_t uid;
	/* Message's GUID:
	    - for expunges either 128bit hex or NULL if unknown
	    - "" if backend doesn't support GUIDs */
	const char *guid;
	/* If GUID is "", this contains hash of the message header,
	   otherwise NULL */
	const char *hdr_hash;

	/* Message's current modseq (saves, flag changes) */
	uint64_t modseq;
	/* Message's save timestamp (saves) */
	time_t save_timestamp;

	/* List of flag/keyword changes: (saves, flag changes) */

	/* Flags added/removed since last sync, and final flags containing
	   flags that exist now but haven't changed */
	uint8_t add_flags, remove_flags, final_flags;
	/* Remove all keywords before applying changes. This is used only with
	   old transaction logs, new ones never reset keywords (just explicitly
	   remove unwanted keywords) */
	bool keywords_reset;
	/* +add, -remove, =final. If the flag is both +added and in =final,
	   it's not not duplicated as =flag to avoid wasting space. */
	ARRAY_TYPE(const_string) keyword_changes;
};

int dsync_mail_get_hdr_hash(struct mail *mail, const char **hdr_hash_r);

void dsync_mail_change_dup(pool_t pool, const struct dsync_mail_change *src,
			   struct dsync_mail_change *dest_r);

#endif
