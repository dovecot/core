/* Copyright (c) 2012 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "hash.h"
#include "mail-namespace.h"
#include "dsync-mailbox-tree.h"
#include "dsync-slave.h"
#include "dsync-brain-private.h"

static void dsync_brain_run_io(void *context)
{
	struct dsync_brain *brain = context;
	bool changed, try_pending;

	if (dsync_slave_has_failed(brain->slave)) {
		io_loop_stop(current_ioloop);
		brain->failed = TRUE;
		return;
	}

	try_pending = TRUE;
	do {
		if (!dsync_brain_run(brain, &changed)) {
			io_loop_stop(current_ioloop);
			break;
		}
		if (changed)
			try_pending = TRUE;
		else if (try_pending) {
			if (dsync_slave_has_pending_data(brain->slave))
				changed = TRUE;
			try_pending = FALSE;
		}
	} while (changed);
}

static struct dsync_brain *
dsync_brain_common_init(struct mail_user *user, struct dsync_slave *slave)
{
	struct dsync_brain *brain;
	pool_t pool;

	pool = pool_alloconly_create("dsync brain", 10240);
	brain = p_new(pool, struct dsync_brain, 1);
	brain->pool = pool;
	brain->user = user;
	brain->slave = slave;
	brain->sync_type = DSYNC_BRAIN_SYNC_TYPE_UNKNOWN;
	brain->remote_mailbox_states =
		hash_table_create(default_pool, brain->pool, 0,
				  guid_128_hash, guid_128_cmp);
	p_array_init(&brain->mailbox_states, pool, 64);
	return brain;
}

struct dsync_brain *
dsync_brain_master_init(struct mail_user *user, struct dsync_slave *slave,
			struct mail_namespace *sync_ns,
			enum dsync_brain_sync_type sync_type,
			enum dsync_brain_flags flags,
			const char *state)
{
	struct dsync_slave_settings slave_set;
	struct dsync_brain *brain;
	const char *error;

	i_assert(sync_type != DSYNC_BRAIN_SYNC_TYPE_UNKNOWN);
	i_assert(sync_type != DSYNC_BRAIN_SYNC_TYPE_STATE || *state != '\0');

	brain = dsync_brain_common_init(user, slave);
	brain->sync_type = sync_type;
	if (sync_ns != NULL)
		brain->sync_ns = sync_ns;
	brain->master_brain = TRUE;
	brain->mails_have_guids =
		(flags & DSYNC_BRAIN_FLAG_MAILS_HAVE_GUIDS) != 0;
	brain->guid_requests =
		(flags & DSYNC_BRAIN_FLAG_SEND_REQUESTS) != 0;

	brain->state = DSYNC_STATE_SEND_MAILBOX_TREE;
	if (sync_type == DSYNC_BRAIN_SYNC_TYPE_STATE) {
		if (dsync_mailbox_states_import(&brain->mailbox_states, state,
						&error) < 0) {
			array_clear(&brain->mailbox_states);
			i_error("Saved sync state is invalid, "
				"falling back to full sync: %s", error);
			brain->sync_type = DSYNC_BRAIN_SYNC_TYPE_FULL;
		} else {
			brain->state = DSYNC_STATE_MASTER_SEND_LAST_COMMON;
		}
	}
	dsync_brain_mailbox_trees_init(brain);

	memset(&slave_set, 0, sizeof(slave_set));
	slave_set.sync_ns_prefix = sync_ns == NULL ? NULL : sync_ns->prefix;
	slave_set.sync_type = sync_type;
	slave_set.guid_requests = brain->guid_requests;
	slave_set.mails_have_guids = brain->mails_have_guids;
	dsync_slave_send_handshake(slave, &slave_set);

	dsync_slave_set_io_callback(slave, dsync_brain_run_io, brain);
	return brain;
}

struct dsync_brain *
dsync_brain_slave_init(struct mail_user *user, struct dsync_slave *slave)
{
	struct dsync_brain *brain;

	brain = dsync_brain_common_init(user, slave);
	brain->state = DSYNC_STATE_SLAVE_RECV_HANDSHAKE;

	dsync_slave_set_io_callback(slave, dsync_brain_run_io, brain);
	return brain;
}

int dsync_brain_deinit(struct dsync_brain **_brain)
{
	struct dsync_brain *brain = *_brain;
	int ret;

	*_brain = NULL;

	if (dsync_slave_has_failed(brain->slave) ||
	    brain->state != DSYNC_STATE_DONE)
		brain->failed = TRUE;

	if (brain->box != NULL)
		dsync_brain_sync_mailbox_deinit(brain);
	if (brain->local_tree_iter != NULL)
		dsync_mailbox_tree_iter_deinit(&brain->local_tree_iter);

	hash_table_destroy(&brain->remote_mailbox_states);

	ret = brain->failed ? -1 : 0;
	pool_unref(&brain->pool);
	return ret;
}

static bool dsync_brain_slave_recv_handshake(struct dsync_brain *brain)
{
	const struct dsync_slave_settings *slave_set;

	i_assert(!brain->master_brain);

	if (dsync_slave_recv_handshake(brain->slave, &slave_set) == 0)
		return FALSE;

	if (slave_set->sync_ns_prefix != NULL) {
		brain->sync_ns = mail_namespace_find(brain->user->namespaces,
						     slave_set->sync_ns_prefix);
		if (brain->sync_ns == NULL) {
			i_error("Requested sync namespace prefix=%s doesn't exist",
				slave_set->sync_ns_prefix);
			brain->failed = TRUE;
			return TRUE;
		}
	}
	i_assert(brain->sync_type == DSYNC_BRAIN_SYNC_TYPE_UNKNOWN);
	brain->sync_type = slave_set->sync_type;
	brain->guid_requests = slave_set->guid_requests;
	brain->mails_have_guids = slave_set->mails_have_guids;

	dsync_brain_mailbox_trees_init(brain);

	if (brain->sync_type == DSYNC_BRAIN_SYNC_TYPE_STATE)
		brain->state = DSYNC_STATE_SLAVE_RECV_LAST_COMMON;
	else
		brain->state = DSYNC_STATE_SEND_MAILBOX_TREE;
	return TRUE;
}

static void dsync_brain_master_send_last_common(struct dsync_brain *brain)
{
	const struct dsync_mailbox_state *states;
	unsigned int count;
	enum dsync_slave_send_ret ret = DSYNC_SLAVE_SEND_RET_OK;

	i_assert(brain->master_brain);

	states = array_get(&brain->mailbox_states, &count);
	while (brain->mailbox_state_idx < count) {
		if (ret == DSYNC_SLAVE_SEND_RET_FULL)
			return;
		ret = dsync_slave_send_mailbox_state(brain->slave,
				&states[brain->mailbox_state_idx++]);
	}
	dsync_slave_send_end_of_list(brain->slave);
	brain->state = DSYNC_STATE_SEND_MAILBOX_TREE;
	brain->mailbox_state_idx = 0;
}

static bool dsync_brain_slave_recv_last_common(struct dsync_brain *brain)
{
	struct dsync_mailbox_state state;
	enum dsync_slave_recv_ret ret;
	bool changed = FALSE;

	i_assert(!brain->master_brain);

	while ((ret = dsync_slave_recv_mailbox_state(brain->slave, &state)) > 0) {
		array_append(&brain->mailbox_states, &state, 1);
		changed = TRUE;
	}
	if (ret == DSYNC_SLAVE_RECV_RET_FINISHED) {
		brain->state = DSYNC_STATE_SEND_MAILBOX_TREE;
		changed = TRUE;
	}
	return changed;
}

static bool dsync_brain_run_real(struct dsync_brain *brain, bool *changed_r)
{
	bool changed = FALSE, ret = TRUE;

	if (brain->failed)
		return FALSE;

	switch (brain->state) {
	case DSYNC_STATE_SLAVE_RECV_HANDSHAKE:
		changed = dsync_brain_slave_recv_handshake(brain);
		break;
	case DSYNC_STATE_MASTER_SEND_LAST_COMMON:
		dsync_brain_master_send_last_common(brain);
		changed = TRUE;
		break;
	case DSYNC_STATE_SLAVE_RECV_LAST_COMMON:
		changed = dsync_brain_slave_recv_last_common(brain);
		break;
	case DSYNC_STATE_SEND_MAILBOX_TREE:
		dsync_brain_send_mailbox_tree(brain);
		changed = TRUE;
		break;
	case DSYNC_STATE_RECV_MAILBOX_TREE:
		changed = dsync_brain_recv_mailbox_tree(brain);
		break;
	case DSYNC_STATE_SEND_MAILBOX_TREE_DELETES:
		dsync_brain_send_mailbox_tree_deletes(brain);
		changed = TRUE;
		break;
	case DSYNC_STATE_RECV_MAILBOX_TREE_DELETES:
		changed = dsync_brain_recv_mailbox_tree_deletes(brain);
		break;
	case DSYNC_STATE_MASTER_SEND_MAILBOX:
		dsync_brain_master_send_mailbox(brain);
		changed = TRUE;
		break;
	case DSYNC_STATE_SLAVE_RECV_MAILBOX:
		changed = dsync_brain_slave_recv_mailbox(brain);
		break;
	case DSYNC_STATE_SYNC_MAILS:
		changed = dsync_brain_sync_mails(brain);
		break;
	case DSYNC_STATE_DONE:
		changed = TRUE;
		ret = FALSE;
		break;
	}

	*changed_r = changed;
	return brain->failed ? FALSE : ret;
}

bool dsync_brain_run(struct dsync_brain *brain, bool *changed_r)
{
	bool ret;

	*changed_r = FALSE;

	if (dsync_slave_has_failed(brain->slave)) {
		brain->failed = TRUE;
		return FALSE;
	}

	T_BEGIN {
		ret = dsync_brain_run_real(brain, changed_r);
	} T_END;
	if (!brain->failed)
		dsync_slave_flush(brain->slave);
	return ret;
}

bool dsync_brain_has_failed(struct dsync_brain *brain)
{
	return brain->failed;
}
