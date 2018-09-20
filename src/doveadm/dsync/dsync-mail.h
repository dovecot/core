#ifndef DSYNC_MAIL_H
#define DSYNC_MAIL_H

#include "mail-types.h"

struct md5_context;
struct mail;
struct mailbox;

struct dsync_mail {
	/* either GUID="" or uid=0 */
	const char *guid;
	uint32_t uid;
	time_t saved_date;

	/* If non-NULL, we're syncing within the dsync process using ibc-pipe.
	   This mail can be used to mailbox_copy() the mail. */
	struct mail *input_mail;
	/* Verify that this equals to input_mail->uid */
	uint32_t input_mail_uid;

	/* TRUE if the following fields aren't set, because minimal_fill=TRUE
	   parameter was used. */
	bool minimal_fields;

	const char *pop3_uidl;
	uint32_t pop3_order;
	time_t received_date;
	/* Input stream containing the message text, or NULL if all instances
	   of the message were already expunged from this mailbox. */
	struct istream *input;
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

	/* Received timestamp for saves, if brain.sync_since/until_timestamp is set */
	time_t received_timestamp;
	/* Mail's size for saves if brain.sync_max_size is set,
	   (uoff_t)-1 otherwise. */
	uoff_t virtual_size;
};

struct mailbox_header_lookup_ctx *
dsync_mail_get_hash_headers(struct mailbox *box, const char *const *hashed_headers);

int dsync_mail_get_hdr_hash(struct mail *mail, unsigned int version,
			    const char *const *hashed_headers, const char **hdr_hash_r);
static inline bool dsync_mail_hdr_hash_is_empty(const char *hdr_hash)
{
	/* md5(\n) */
	return strcmp(hdr_hash, "68b329da9893e34099c7d8ad5cb9c940") == 0;
}

int dsync_mail_fill(struct mail *mail, bool minimal_fill,
		    struct dsync_mail *dmail_r, const char **error_field_r);
int dsync_mail_fill_nonminimal(struct mail *mail, struct dsync_mail *dmail_r,
			       const char **error_field_r);

void dsync_mail_change_dup(pool_t pool, const struct dsync_mail_change *src,
			   struct dsync_mail_change *dest_r);

#endif
