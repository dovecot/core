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

	/* If non-NULL, we're syncing within the dsync process using ibc-pipe.
	   This mail can be used to mailbox_copy() the mail. */
	struct mail *input_mail;
	/* Verify that this equals to input_mail->uid */
	uint32_t input_mail_uid;
};

struct dsync_mail_request {
	/* either GUID=NULL or uid=0 */
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
#define KEYWORD_CHANGE_ADD_AND_FINAL '&'

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
	/* Message's current private modseq (for private flags in
	   shared mailboxes, otherwise 0) */
	uint64_t pvt_modseq;
	/* Message's save timestamp (saves) */
	time_t save_timestamp;

	/* List of flag/keyword changes: (saves, flag changes) */

	/* Flags added/removed since last sync, and final flags containing
	   flags that exist now but haven't changed */
	uint8_t add_flags, remove_flags, final_flags;
	uint8_t add_pvt_flags, remove_pvt_flags;
	/* Remove all keywords before applying changes. This is used only with
	   old transaction logs, new ones never reset keywords (just explicitly
	   remove unwanted keywords) */
	bool keywords_reset;
	/* +add, -remove, =final, &add_and_final. */
	ARRAY_TYPE(const_string) keyword_changes;
};

int dsync_mail_get_hdr_hash(struct mail *mail, const char **hdr_hash_r);
int dsync_mail_fill(struct mail *mail, struct dsync_mail *dmail_r,
		    const char **error_field_r);

void dsync_mail_change_dup(pool_t pool, const struct dsync_mail_change *src,
			   struct dsync_mail_change *dest_r);

#endif
