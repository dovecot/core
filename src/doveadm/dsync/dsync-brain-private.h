#ifndef DSYNC_BRAIN_PRIVATE_H
#define DSYNC_BRAIN_PRIVATE_H

#include "hash.h"
#include "dsync-brain.h"
#include "dsync-mailbox.h"
#include "dsync-mailbox-state.h"

struct dsync_mailbox_tree_sync_change;

enum dsync_state {
	DSYNC_STATE_SLAVE_RECV_HANDSHAKE,
	DSYNC_STATE_MASTER_SEND_LAST_COMMON,
	DSYNC_STATE_SLAVE_RECV_LAST_COMMON,
	DSYNC_STATE_SEND_MAILBOX_TREE,
	DSYNC_STATE_SEND_MAILBOX_TREE_DELETES,
	DSYNC_STATE_RECV_MAILBOX_TREE,
	DSYNC_STATE_RECV_MAILBOX_TREE_DELETES,
	DSYNC_STATE_MASTER_SEND_MAILBOX,
	DSYNC_STATE_SLAVE_RECV_MAILBOX,
	DSYNC_STATE_SYNC_MAILS,
	DSYNC_STATE_DONE
};

enum dsync_box_state {
	DSYNC_BOX_STATE_MAILBOX,
	DSYNC_BOX_STATE_CHANGES,
	DSYNC_BOX_STATE_MAIL_REQUESTS,
	DSYNC_BOX_STATE_MAILS,
	DSYNC_BOX_STATE_RECV_LAST_COMMON,
	DSYNC_BOX_STATE_DONE
};

struct dsync_brain {
	pool_t pool;
	struct mail_user *user;
	struct dsync_slave *slave;
	struct mail_namespace *sync_ns;
	enum dsync_brain_sync_type sync_type;

	char hierarchy_sep;
	struct dsync_mailbox_tree *local_mailbox_tree;
	struct dsync_mailbox_tree *remote_mailbox_tree;
	struct dsync_mailbox_tree_iter *local_tree_iter;

	enum dsync_state state, pre_box_state;
	enum dsync_box_state box_recv_state;
	enum dsync_box_state box_send_state;

	struct dsync_transaction_log_scan *log_scan;
	struct dsync_mailbox_importer *box_importer;
	struct dsync_mailbox_exporter *box_exporter;

	struct mailbox *box;
	struct dsync_mailbox local_dsync_box, remote_dsync_box;
	/* list of mailbox states
	   for master brain: given to brain at init and
	   for slave brain: received from DSYNC_STATE_SLAVE_RECV_LAST_COMMON */
	ARRAY_TYPE(dsync_mailbox_state) mailbox_states;
	/* DSYNC_STATE_MASTER_SEND_LAST_COMMON: current send position */
	unsigned int mailbox_state_idx;
	/* state of the mailbox we're currently syncing, changed at
	   init and deinit */
	struct dsync_mailbox_state mailbox_state;
	/* GUID -> dsync_mailbox_state for mailboxes that have already
	   been synced */
	HASH_TABLE(uint8_t *, struct dsync_mailbox_state *) remote_mailbox_states;

	unsigned int master_brain:1;
	unsigned int guid_requests:1;
	unsigned int mails_have_guids:1;
	unsigned int changes_during_sync:1;
	unsigned int failed:1;
};

void dsync_brain_mailbox_trees_init(struct dsync_brain *brain);
void dsync_brain_send_mailbox_tree(struct dsync_brain *brain);
void dsync_brain_send_mailbox_tree_deletes(struct dsync_brain *brain);
bool dsync_brain_recv_mailbox_tree(struct dsync_brain *brain);
bool dsync_brain_recv_mailbox_tree_deletes(struct dsync_brain *brain);
int dsync_brain_mailbox_tree_sync_change(struct dsync_brain *brain,
			const struct dsync_mailbox_tree_sync_change *change);

void dsync_brain_sync_mailbox_deinit(struct dsync_brain *brain);
int dsync_brain_mailbox_alloc(struct dsync_brain *brain, const guid_128_t guid,
			      struct mailbox **box_r);
void dsync_brain_mailbox_update_pre(struct dsync_brain *brain,
				    struct mailbox *box,
				    const struct dsync_mailbox *local_box,
				    const struct dsync_mailbox *remote_box);
bool dsync_boxes_need_sync(const struct dsync_mailbox *box1,
			   const struct dsync_mailbox *box2);

void dsync_brain_master_send_mailbox(struct dsync_brain *brain);
bool dsync_brain_slave_recv_mailbox(struct dsync_brain *brain);
void dsync_brain_sync_mailbox_init_remote(struct dsync_brain *brain,
					  const struct dsync_mailbox *remote_dsync_box);
bool dsync_brain_sync_mails(struct dsync_brain *brain);

#endif
