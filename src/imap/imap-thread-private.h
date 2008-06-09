#ifndef IMAP_THREAD_PRIVATE_H
#define IMAP_THREAD_PRIVATE_H

#include "crc32.h"
#include "mail-hash.h"
#include "imap-thread.h"

#define HDR_MESSAGE_ID "message-id"
#define HDR_IN_REPLY_TO "in-reply-to"
#define HDR_REFERENCES "references"
#define HDR_SUBJECT "subject"

struct msgid_search_key {
	const char *msgid;
	uint32_t msgid_crc32;
};

struct mail_thread_node {
	struct mail_hash_record rec;

	/* exists=TRUE: UID of the mail this node belongs to
	   exists=FALSE: UID of some message that references (in References: or
	   In-Reply-To: header) this node. Of all the valid references exactly
	   one has the same CRC32 as this node's msgid_crc32. */
	uint32_t uid;
	uint32_t parent_idx;
	uint32_t msgid_crc32;

	uint32_t link_refcount:29;
	uint32_t expunge_rebuilds:1;
	uint32_t parent_unref_rebuilds:1;
	uint32_t exists:1;
};

struct mail_thread_child_node {
	uint32_t idx;
	uint32_t uid;
	time_t sort_date;
};
ARRAY_DEFINE_TYPE(mail_thread_child_node, struct mail_thread_child_node);

struct thread_context {
	struct mail *tmp_mail;

	struct mail_hash *hash;
	struct mail_hash_transaction *hash_trans;

	/* Hash record idx -> Message-ID */
	ARRAY_DEFINE(msgid_cache, const char *);
	pool_t msgid_pool;

	unsigned int cmp_match_count;
	uint32_t cmp_last_idx;

	unsigned int failed:1;
	unsigned int rebuild:1;
	unsigned int syncing:1;
};

static inline uint32_t crc32_str_nonzero(const char *str)
{
	uint32_t value = crc32_str(str);
	return value == 0 ? 1 : value;
}

int mail_thread_add(struct thread_context *ctx, struct mail *mail);
int mail_thread_remove(struct thread_context *ctx, uint32_t seq);

struct mail_thread_iterate_context *
mail_thread_iterate_init(struct mail *tmp_mail,
			 struct mail_hash_transaction *hash_trans,
			 enum mail_thread_type thread_type);
const struct mail_thread_child_node *
mail_thread_iterate_next(struct mail_thread_iterate_context *iter,
			 struct mail_thread_iterate_context **child_iter_r);
unsigned int
mail_thread_iterate_count(struct mail_thread_iterate_context *iter);
int mail_thread_iterate_deinit(struct mail_thread_iterate_context **iter);

#endif
