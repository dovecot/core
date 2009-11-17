#ifndef DSYNC_DATA_H
#define DSYNC_DATA_H

#include "mail-storage.h"

typedef struct {
	uint8_t guid[MAIL_GUID_128_SIZE];
} mailbox_guid_t;
ARRAY_DEFINE_TYPE(mailbox_guid, mailbox_guid_t);

enum dsync_mailbox_flags {
	DSYNC_MAILBOX_FLAG_DELETED_MAILBOX	= 0x01,
	DSYNC_MAILBOX_FLAG_DELETED_DIR		= 0x02
};

struct dsync_mailbox {
	const char *name;
	/* Mailbox directory's GUID. Not necessarily set if mailbox is
	   deleted. */
	mailbox_guid_t dir_guid;
	/* Mailbox's GUID. Full of zero with \Noselect mailboxes. */
	mailbox_guid_t mailbox_guid;

	uint32_t uid_validity, uid_next;
	uint64_t highest_modseq;
	time_t last_renamed;
	enum dsync_mailbox_flags flags;
	ARRAY_TYPE(const_string) cache_fields;
};
ARRAY_DEFINE_TYPE(dsync_mailbox, struct dsync_mailbox *);

/* dsync_worker_msg_iter_next() returns also all expunged messages from
   the end of mailbox with this flag set. The GUIDs are 128 bit GUIDs saved
   to transaction log (mail_generate_guid_128_hash()). */
#define DSYNC_MAIL_FLAG_EXPUNGED 0x10000000

struct dsync_message {
	const char *guid;
	uint32_t uid;
	enum mail_flags flags;
	/* keywords are sorted by name */
	const char *const *keywords;
	uint64_t modseq;
	time_t save_date;
};

struct dsync_msg_static_data {
	const char *pop3_uidl;
	time_t received_date;
	struct istream *input;
};

struct dsync_mailbox *
dsync_mailbox_dup(pool_t pool, const struct dsync_mailbox *box);

struct dsync_message *
dsync_message_dup(pool_t pool, const struct dsync_message *msg);

int dsync_mailbox_guid_cmp(const struct dsync_mailbox *box1,
			   const struct dsync_mailbox *box2);
int dsync_mailbox_p_guid_cmp(struct dsync_mailbox *const *box1,
			     struct dsync_mailbox *const *box2);

int dsync_mailbox_dir_guid_cmp(const struct dsync_mailbox *box1,
			       const struct dsync_mailbox *box2);
int dsync_mailbox_p_dir_guid_cmp(struct dsync_mailbox *const *box1,
				 struct dsync_mailbox *const *box2);

bool dsync_keyword_list_equals(const char *const *k1, const char *const *k2);

bool dsync_guid_equals(const mailbox_guid_t *guid1,
		       const mailbox_guid_t *guid2);
int dsync_guid_cmp(const mailbox_guid_t *guid1, const mailbox_guid_t *guid2);
const char *dsync_guid_to_str(const mailbox_guid_t *guid);
const char *dsync_get_guid_128_str(const char *guid, unsigned char *dest,
				   unsigned int dest_len);
void dsync_str_sha_to_guid(const char *str, mailbox_guid_t *guid);

#endif
