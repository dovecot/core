/* Copyright (c) 2012 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "ioloop.h"
#include "doveadm-connection.h"
#include "replicator-settings.h"
#include "replicator-queue.h"
#include "replicator-brain.h"

struct replicator_sync_context {
	struct replicator_brain *brain;
	struct replicator_user *user;
};

struct replicator_brain {
	pool_t pool;
	struct replicator_queue *queue;
	const struct replicator_settings *set;
	struct timeout *to;

	ARRAY_DEFINE(doveadm_conns, struct doveadm_connection *);
};

static void replicator_brain_fill(struct replicator_brain *brain);

static void replicator_brain_queue_changed(void *context)
{
	struct replicator_brain *brain = context;

	replicator_brain_fill(brain);
}

struct replicator_brain *
replicator_brain_init(struct replicator_queue *queue,
		      const struct replicator_settings *set)
{
	struct replicator_brain *brain;
	pool_t pool;

	pool = pool_alloconly_create("replication brain", 1024);
	brain = p_new(pool, struct replicator_brain, 1);
	brain->pool = pool;
	brain->queue = queue;
	brain->set = set;
	p_array_init(&brain->doveadm_conns, pool, 16);
	replicator_queue_set_change_callback(queue,
		replicator_brain_queue_changed, brain);
	replicator_brain_fill(brain);
	return brain;
}

void replicator_brain_deinit(struct replicator_brain **_brain)
{
	struct replicator_brain *brain = *_brain;
	struct doveadm_connection **connp;

	*_brain = NULL;

	array_foreach_modifiable(&brain->doveadm_conns, connp)
		doveadm_connection_deinit(connp);
	if (brain->to != NULL)
		timeout_remove(&brain->to);
	pool_unref(&brain->pool);
}

static struct doveadm_connection *
get_doveadm_connection(struct replicator_brain *brain)
{
	struct doveadm_connection *const *connp, *conn = NULL;

	array_foreach(&brain->doveadm_conns, connp) {
		if (!doveadm_connection_is_busy(*connp))
			return *connp;
	}
	if (array_count(&brain->doveadm_conns) ==
	    brain->set->replication_max_conns)
		return NULL;

	conn = doveadm_connection_init(brain->set->doveadm_socket_path);
	array_append(&brain->doveadm_conns, &conn, 1);
	return conn;
}

static void doveadm_sync_callback(enum doveadm_reply reply, void *context)
{
	struct replicator_sync_context *ctx = context;

	if (reply == DOVEADM_REPLY_NOUSER) {
		/* user no longer exists, remove from replication */
		replicator_queue_remove(ctx->brain->queue, &ctx->user);
	} else {
		ctx->user->last_sync_failed =
			reply != DOVEADM_REPLY_OK;
		replicator_queue_push(ctx->brain->queue, ctx->user);
	}
	replicator_brain_fill(ctx->brain);
	i_free(ctx);
}

static bool
doveadm_replicate(struct replicator_brain *brain, struct replicator_user *user)
{
	struct replicator_sync_context *ctx;
	struct doveadm_connection *conn;
	bool full;

	conn = get_doveadm_connection(brain);
	if (conn == NULL)
		return FALSE;

	full = user->last_full_sync +
		brain->set->replication_full_sync_interval < ioloop_time;
	/* update the sync times immediately. if the replication fails we still
	   wouldn't want it to be retried immediately. */
	user->last_fast_sync = ioloop_time;
	if (full)
		user->last_full_sync = ioloop_time;
	/* reset priority also. if more updates arrive during replication
	   we'll do another replication to make sure nothing gets lost */
	user->priority = REPLICATION_PRIORITY_NONE;

	ctx = i_new(struct replicator_sync_context, 1);
	ctx->brain = brain;
	ctx->user = user;
	doveadm_connection_sync(conn, user->username, full,
				doveadm_sync_callback, ctx);
	return TRUE;
}

static void replicator_brain_timeout(struct replicator_brain *brain)
{
	timeout_remove(&brain->to);
	replicator_brain_fill(brain);
}

static bool replicator_brain_fill_next(struct replicator_brain *brain)
{
	struct replicator_user *user;
	unsigned int next_secs;

	user = replicator_queue_pop(brain->queue, &next_secs);
	if (user == NULL) {
		/* nothing more to do */
		if (brain->to != NULL)
			timeout_remove(&brain->to);
		brain->to = timeout_add(next_secs * 1000,
					replicator_brain_timeout, brain);
		return FALSE;
	}

	if (!doveadm_replicate(brain, user)) {
		/* all connections were full, put the user back to queue */
		replicator_queue_push(brain->queue, user);
		return FALSE;
	}
	/* replication started for the user */
	return TRUE;
}

static void replicator_brain_fill(struct replicator_brain *brain)
{
	while (replicator_brain_fill_next(brain)) ;
}
