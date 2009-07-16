#ifndef DSYNC_DATA_H
#define DSYNC_DATA_H

#include "mail-storage.h"

typedef struct {
	uint8_t guid[MAILBOX_GUID_SIZE];
} mailbox_guid_t;
ARRAY_DEFINE_TYPE(mailbox_guid, mailbox_guid_t);

struct dsync_mailbox {
	const char *name;
	mailbox_guid_t guid;
	/* uid_validity=0 for \noselect mailbox */
	uint32_t uid_validity, uid_next;
	uint64_t highest_modseq;
};

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

struct dsync_mailbox *
dsync_mailbox_dup(pool_t pool, const struct dsync_mailbox *box);

struct dsync_message *
dsync_message_dup(pool_t pool, const struct dsync_message *msg);

int dsync_mailbox_guid_cmp(const struct dsync_mailbox *box1,
			   const struct dsync_mailbox *box2);
int dsync_mailbox_p_guid_cmp(struct dsync_mailbox *const *box1,
			     struct dsync_mailbox *const *box2);

bool dsync_keyword_list_equals(const char *const *k1, const char *const *k2);

#endif
