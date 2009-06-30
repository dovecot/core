#ifndef DSYNC_BRAIN_PRIVATE_H
#define DSYNC_BRAIN_PRIVATE_H

#include "dsync-data.h"
#include "dsync-brain.h"

enum dsync_state {
	DSYNC_STATE_GET_MAILBOXES = 0,
	DSYNC_STATE_CREATE_MAILBOXES,
	DSYNC_STATE_SYNC_EXISTING_MSGS,
	DSYNC_STATE_SYNC_NEW_MSGS,
	DSYNC_STATE_SYNC_RETRY_COPIES,
	DSYNC_STATE_SYNC_UPDATE_MAILBOX,
	DSYNC_STATE_SYNC_RESOLVE_UID_CONFLICTS,
	DSYNC_STATE_SYNC_FLUSH,
	DSYNC_STATE_SYNC_END
};

struct dsync_brain_mailbox_list {
	pool_t pool;
	struct dsync_brain *brain;
	struct dsync_worker *worker;
	struct dsync_worker_mailbox_iter *iter;
	ARRAY_DEFINE(mailboxes, struct dsync_mailbox *);
};

struct dsync_brain_guid_instance {
	struct dsync_brain_guid_instance *next;
	uint32_t uid;
	/* mailbox index in dsync_brain_mailbox_list.mailboxes */
	unsigned int mailbox_idx:31;
	unsigned int failed:1;
};

struct dsync_brain_msg_iter {
	struct dsync_brain_mailbox_sync *sync;
	struct dsync_worker *worker;

	unsigned int wanted_mailbox_idx;

	struct dsync_worker_msg_iter *iter;
	struct dsync_message msg;
	unsigned int mailbox_idx;

	unsigned int save_guids:1;
};

struct dsync_brain_uid_conflict {
	uint32_t mailbox_idx;
	uint32_t uid;
};

struct dsync_brain_new_msg {
	uint32_t mailbox_idx;
	struct dsync_message *msg;
};

struct dsync_brain_mailbox_sync {
	struct dsync_brain *brain;
	pool_t pool;

	/* char *guid -> struct dsync_brain_guid_instance* */
	struct hash_table *guid_hash;

	struct dsync_brain_msg_iter *src_msg_iter;
	struct dsync_brain_msg_iter *dest_msg_iter;

	ARRAY_DEFINE(uid_conflicts, struct dsync_brain_uid_conflict);
	ARRAY_DEFINE(new_msgs, struct dsync_brain_new_msg);
	unsigned int next_new_msg;

	/* copy operations that failed. indexes point to new_msgs array */
	ARRAY_TYPE(uint32_t) copy_retry_indexes;
	unsigned int copy_results_left;

	unsigned int uid_conflict:1;
};

struct dsync_brain {
	struct dsync_worker *src_worker;
	struct dsync_worker *dest_worker;

	enum dsync_state state;

	struct dsync_brain_mailbox_list *src_mailbox_list;
	struct dsync_brain_mailbox_list *dest_mailbox_list;

	struct dsync_brain_mailbox_sync *mailbox_sync;

	unsigned int failed:1;
};

#endif
