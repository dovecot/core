#ifndef INDEX_THREAD_PRIVATE_H
#define INDEX_THREAD_PRIVATE_H

struct index_mailbox;
struct mail_thread_list_context;

#include "crc32.h"
#include "mail-hash.h"
#include "mail-thread.h"

#define MAIL_THREAD_INDEX_SUFFIX ".thread"

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

	/* CRC32 checksum of this node's message ID (except CRC32 0 -> 1).
	   If there are more nodes with the same checksum, use uid and
	   ref_index fields to find the original string. */
	uint32_t msgid_crc32;
	/* ref_index=0: ID in external thread IDs list (beginning from 1)
	   ref_index=1: UID of the mail whose Message-ID: header points to
	     this node.
	   ref_index>1: UID of some message which has references to this
	     node. ref_index spcifies how the reference string is found. */
	uint32_t uid_or_id;
	/* Index for this node's parent node */
	unsigned int parent_idx:27;
	/* 0 = uid contains the index to the wanted Message ID in external
	       thread IDs list
	   1 = Message-ID: header's first valid ID
	   2 = In-Reply-To: header's first valid ID
	   3 = References: header's last ID with the same CRC32
	   4 = References: header's second last ID with the same CRC32
	     (i.e. one non-matching ID already had a CRC32 collision)
	   ..
	   31 = References: header's 29th last ID with the same CRC32
	*/
	unsigned int ref_index:5;
	/* Number of messages containing "this message" -> "parent message"
	   link, i.e. "number of links to parent node". However since parents
	   can change, not all of these references might be from our current
	   child nodes. When this refcount reaches 0, it means we must detach
	   from our parent. */
	unsigned int parent_link_refcount:30;
	/* If uid is expunged, rebuild the thread tree. */
	unsigned int expunge_rebuilds:1;
	/* If a link between this node and its child gets unreferenced,
	   rebuild the thread tree. */
	unsigned int parent_unref_rebuilds:1;
};
#define MAIL_INDEX_NODE_REF_EXT 0
#define MAIL_INDEX_NODE_REF_MSGID 1
#define MAIL_INDEX_NODE_REF_INREPLYTO 2
#define MAIL_INDEX_NODE_REF_REFERENCES_LAST 3
#define MAIL_INDEX_NODE_REF_MAX_VALUE 31

#define MAIL_INDEX_NODE_EXISTS(node) \
	((node)->ref_index == MAIL_INDEX_NODE_REF_MSGID)

struct mail_thread_update_context {
	struct mail *tmp_mail;

	struct mail_hash *hash;
	struct mail_hash_transaction *hash_trans;
	struct mail_thread_list_update_context *thread_list_ctx;

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

int mail_thread_add(struct mail_thread_update_context *ctx, struct mail *mail);
int mail_thread_remove(struct mail_thread_update_context *ctx, uint32_t seq);

struct mail_thread_iterate_context *
mail_thread_iterate_init_full(struct mail *tmp_mail,
			      struct mail_hash_transaction *hash_trans,
			      struct mail_thread_list_context *hash_list_ctx,
			      enum mail_thread_type thread_type,
			      bool return_seqs);

void index_thread_mailbox_index_opened(struct index_mailbox *ibox);

struct mail_thread_list_context *
mail_thread_list_init(struct mailbox *box);
void mail_thread_list_deinit(struct mail_thread_list_context **ctx);

struct mail_thread_list_update_context *
mail_thread_list_update_begin(struct mail_thread_list_context *ctx,
			      struct mail_hash_transaction *hash_trans);
int mail_thread_list_lookup(struct mail_thread_list_update_context *ctx,
			    uint32_t id, const char **msgid_r);
uint32_t mail_thread_list_add(struct mail_thread_list_update_context *ctx,
			      const char *msgid);
void mail_thread_list_remove(struct mail_thread_list_update_context *ctx,
			     uint32_t id);
int mail_thread_list_commit(struct mail_thread_list_update_context **ctx);
void mail_thread_list_rollback(struct mail_thread_list_update_context **ctx);

#endif
