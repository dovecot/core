#ifndef DSYNC_BRAIN_PRIVATE_H
#define DSYNC_BRAIN_PRIVATE_H

#include "dsync-data.h"
#include "dsync-brain.h"

enum dsync_state {
	DSYNC_STATE_GET_MAILBOXES = 0,
	DSYNC_STATE_GET_SUBSCRIPTIONS,
	DSYNC_STATE_SYNC_MAILBOXES,
	DSYNC_STATE_SYNC_SUBSCRIPTIONS,
	DSYNC_STATE_SYNC_MSGS,
	DSYNC_STATE_SYNC_MSGS_FLUSH,
	DSYNC_STATE_SYNC_MSGS_FLUSH2,
	DSYNC_STATE_SYNC_UPDATE_MAILBOXES,
	DSYNC_STATE_SYNC_FLUSH,
	DSYNC_STATE_SYNC_FLUSH2,
	DSYNC_STATE_SYNC_END
};

struct dsync_brain_mailbox_list {
	pool_t pool;
	struct dsync_brain *brain;
	struct dsync_worker *worker;
	struct dsync_worker_mailbox_iter *iter;
	ARRAY_TYPE(dsync_mailbox) mailboxes;
	ARRAY_TYPE(dsync_mailbox) dirs;
};

struct dsync_brain_subs_list {
	pool_t pool;
	struct dsync_brain *brain;
	struct dsync_worker *worker;
	struct dsync_worker_subs_iter *iter;
	ARRAY_DEFINE(subscriptions, struct dsync_worker_subscription);
	ARRAY_DEFINE(unsubscriptions, struct dsync_worker_unsubscription);
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

	struct dsync_worker_msg_iter *iter;
	struct dsync_message msg;

	unsigned int mailbox_idx;

	/* char *guid -> struct dsync_brain_guid_instance* */
	struct hash_table *guid_hash;

	ARRAY_DEFINE(new_msgs, struct dsync_brain_new_msg);
	ARRAY_DEFINE(uid_conflicts, struct dsync_brain_uid_conflict);
	unsigned int next_new_msg, next_conflict;

	/* copy operations that failed. indexes point to new_msgs array */
	unsigned int copy_results_left;
	unsigned int save_results_left;

	unsigned int msgs_sent:1;
	unsigned int adding_msgs:1;
};

struct dsync_brain_uid_conflict {
	uint32_t mailbox_idx;
	uint32_t old_uid, new_uid;
};

struct dsync_brain_new_msg {
	unsigned int mailbox_idx:30;
	/* TRUE if it currently looks like message has been saved/copied.
	   if copying fails, it sets this back to FALSE and updates
	   iter->next_new_msg. */
	unsigned int saved:1;
	uint32_t orig_uid;
	struct dsync_message *msg;
};

struct dsync_brain_mailbox {
	struct dsync_mailbox box;
	struct dsync_mailbox *src;
	struct dsync_mailbox *dest;
};
ARRAY_DEFINE_TYPE(dsync_brain_mailbox, struct dsync_brain_mailbox);

struct dsync_brain_mailbox_sync {
	struct dsync_brain *brain;
	pool_t pool;

	ARRAY_TYPE(dsync_brain_mailbox) mailboxes;
	unsigned int wanted_mailbox_idx;

	struct dsync_worker *src_worker;
	struct dsync_worker *dest_worker;

	struct dsync_brain_msg_iter *src_msg_iter;
	struct dsync_brain_msg_iter *dest_msg_iter;

	unsigned int uid_conflict:1;
	unsigned int skip_mailbox:1;
};

struct dsync_brain {
	struct dsync_worker *src_worker;
	struct dsync_worker *dest_worker;
	char *mailbox;
	enum dsync_brain_flags flags;

	enum dsync_state state;

	struct dsync_brain_mailbox_list *src_mailbox_list;
	struct dsync_brain_mailbox_list *dest_mailbox_list;

	struct dsync_brain_subs_list *src_subs_list;
	struct dsync_brain_subs_list *dest_subs_list;

	struct dsync_brain_mailbox_sync *mailbox_sync;
	struct timeout *to;

	unsigned int failed:1;
	unsigned int verbose:1;
	unsigned int backup:1;
	unsigned int unexpected_changes:1;
	unsigned int stdout_tty:1;
};

void dsync_brain_fail(struct dsync_brain *brain);

struct dsync_brain_mailbox_sync *
dsync_brain_msg_sync_init(struct dsync_brain *brain,
			  const ARRAY_TYPE(dsync_brain_mailbox) *mailboxes);
void dsync_brain_msg_sync_more(struct dsync_brain_mailbox_sync *sync);
void dsync_brain_msg_sync_deinit(struct dsync_brain_mailbox_sync **_sync);

void dsync_brain_msg_sync_new_msgs(struct dsync_brain_mailbox_sync *sync);

#endif
