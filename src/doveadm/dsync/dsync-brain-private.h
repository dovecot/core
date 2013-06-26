#ifndef DSYNC_BRAIN_PRIVATE_H
#define DSYNC_BRAIN_PRIVATE_H

#include "hash.h"
#include "dsync-brain.h"
#include "dsync-mailbox.h"
#include "dsync-mailbox-state.h"

#define DSYNC_LOCK_FILENAME ".dovecot-sync.lock"

struct dsync_mailbox_tree_sync_change;

enum dsync_state {
	DSYNC_STATE_MASTER_RECV_HANDSHAKE,
	DSYNC_STATE_SLAVE_RECV_HANDSHAKE,
	/* if sync_type=STATE, the master brain knows the saved "last common
	   mailbox state". this state is sent to the slave. */
	DSYNC_STATE_MASTER_SEND_LAST_COMMON,
	DSYNC_STATE_SLAVE_RECV_LAST_COMMON,

	/* both sides send their mailbox trees */
	DSYNC_STATE_SEND_MAILBOX_TREE,
	DSYNC_STATE_SEND_MAILBOX_TREE_DELETES,
	DSYNC_STATE_RECV_MAILBOX_TREE,
	DSYNC_STATE_RECV_MAILBOX_TREE_DELETES,

	/* master decides in which order mailboxes are synced (it knows the
	   slave's mailboxes by looking at the received mailbox tree) */
	DSYNC_STATE_MASTER_SEND_MAILBOX,
	DSYNC_STATE_SLAVE_RECV_MAILBOX,
	/* once mailbox is selected, the mails inside it are synced.
	   after the mails are synced, another mailbox is synced. */
	DSYNC_STATE_SYNC_MAILS,

	DSYNC_STATE_DONE
};

enum dsync_box_state {
	DSYNC_BOX_STATE_MAILBOX,
	DSYNC_BOX_STATE_CHANGES,
	DSYNC_BOX_STATE_ATTRIBUTES,
	DSYNC_BOX_STATE_MAIL_REQUESTS,
	DSYNC_BOX_STATE_MAILS,
	DSYNC_BOX_STATE_RECV_LAST_COMMON,
	DSYNC_BOX_STATE_DONE
};

struct dsync_brain {
	pool_t pool;
	struct mail_user *user;
	struct dsync_ibc *ibc;
	struct mail_namespace *sync_ns;
	const char *sync_box;
	guid_128_t sync_box_guid;
	const char *const *exclude_mailboxes;
	enum dsync_brain_sync_type sync_type;

	unsigned int lock_timeout;
	int lock_fd;
	const char *lock_path;
	struct file_lock *lock;

	char hierarchy_sep;
	struct dsync_mailbox_tree *local_mailbox_tree;
	struct dsync_mailbox_tree *remote_mailbox_tree;
	struct dsync_mailbox_tree_iter *local_tree_iter;

	enum dsync_state state, pre_box_state;
	enum dsync_box_state box_recv_state;
	enum dsync_box_state box_send_state;
	unsigned int proctitle_update_counter;

	struct dsync_transaction_log_scan *log_scan;
	struct dsync_mailbox_importer *box_importer;
	struct dsync_mailbox_exporter *box_exporter;

	struct mailbox *box;
	struct dsync_mailbox local_dsync_box, remote_dsync_box;
	/* list of mailbox states
	   for master brain: given to brain at init and
	   for slave brain: received from DSYNC_STATE_SLAVE_RECV_LAST_COMMON */
	HASH_TABLE_TYPE(dsync_mailbox_state) mailbox_states;
	/* DSYNC_STATE_MASTER_SEND_LAST_COMMON: current send position */
	struct hash_iterate_context *mailbox_states_iter;
	/* state of the mailbox we're currently syncing, changed at
	   init and deinit */
	struct dsync_mailbox_state mailbox_state;
	/* new states for synced mailboxes */
	ARRAY_TYPE(dsync_mailbox_state) remote_mailbox_states;

	unsigned int master_brain:1;
	unsigned int mail_requests:1;
	unsigned int backup_send:1;
	unsigned int backup_recv:1;
	unsigned int debug:1;
	unsigned int sync_visible_namespaces:1;
	unsigned int no_mail_sync:1;
	unsigned int no_backup_overwrite:1;
	unsigned int changes_during_sync:1;
	unsigned int verbose_proctitle:1;
	unsigned int failed:1;
};

extern const char *dsync_box_state_names[DSYNC_BOX_STATE_DONE+1];

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
bool dsync_boxes_need_sync(struct dsync_brain *brain,
			   const struct dsync_mailbox *box1,
			   const struct dsync_mailbox *box2);
void dsync_brain_sync_init_box_states(struct dsync_brain *brain);

void dsync_brain_master_send_mailbox(struct dsync_brain *brain);
bool dsync_brain_slave_recv_mailbox(struct dsync_brain *brain);
int dsync_brain_sync_mailbox_open(struct dsync_brain *brain,
				  const struct dsync_mailbox *remote_dsync_box);
bool dsync_brain_sync_mails(struct dsync_brain *brain);

#endif
