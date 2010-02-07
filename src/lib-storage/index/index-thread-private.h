#ifndef INDEX_THREAD_PRIVATE_H
#define INDEX_THREAD_PRIVATE_H

#include "crc32.h"
#include "mail-thread.h"
#include "mail-index-strmap.h"

#define MAIL_THREAD_INDEX_SUFFIX ".thread"

/* After initially building the index, assign first_invalid_msgid_idx to
   the next unused index + SKIP_COUNT. When more messages are added and
   the next valid msgid conflicts with the first invalid msgid, the invalid
   msgids will be moved forward again this many indexes. */
#define THREAD_INVALID_MSGID_STR_IDX_SKIP_COUNT \
	(4096 / sizeof(struct mail_thread_node))

#define HDR_MESSAGE_ID "message-id"
#define HDR_IN_REPLY_TO "in-reply-to"
#define HDR_REFERENCES "references"
#define HDR_SUBJECT "subject"

#define MAIL_THREAD_NODE_REF_MSGID 0
#define MAIL_THREAD_NODE_REF_INREPLYTO 1
#define MAIL_THREAD_NODE_REF_REFERENCES1 2

struct mail_thread_node {
	/* UID of the message, or 0 for dummy nodes */
	uint32_t uid;
	/* Index for this node's parent node, 0 = this is root */
	uint32_t parent_idx;
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
	unsigned int child_unref_rebuilds:1;
};
ARRAY_DEFINE_TYPE(mail_thread_node, struct mail_thread_node);
#define MAIL_THREAD_NODE_EXISTS(node) \
	((node)->uid != 0)

struct mail_thread_cache {
	uint32_t last_uid;
	/* indexes used for invalid Message-IDs. that means no other messages
	   point to them and they can safely be moved around whenever
	   necessary. */
	uint32_t first_invalid_msgid_str_idx;
	uint32_t next_invalid_msgid_str_idx;

	struct mail_search_result *search_result;

	/* indexed by mail_index_strmap_rec.str_idx */
	ARRAY_TYPE(mail_thread_node) thread_nodes;
};

static inline uint32_t crc32_str_nonzero(const char *str)
{
	uint32_t value = crc32_str(str);
	return value == 0 ? 1 : value;
}

void mail_thread_add(struct mail_thread_cache *cache,
		     const struct mail_index_strmap_rec *msgid_map,
		     unsigned int *msgid_map_idx);
bool mail_thread_remove(struct mail_thread_cache *cache,
			const struct mail_index_strmap_rec *msgid_map,
			unsigned int *msgid_map_idx);

struct mail_thread_iterate_context *
mail_thread_iterate_init_full(struct mail_thread_cache *cache,
			      struct mail *tmp_mail,
			      enum mail_thread_type thread_type,
			      bool return_seqs);

void index_thread_mailbox_opened(struct mailbox *box);

#endif
