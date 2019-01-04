/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "ioloop.h"
#include "dsync-client.h"
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

	ARRAY_TYPE(dsync_client) dsync_clients;

	bool deinitializing:1;
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
	p_array_init(&brain->dsync_clients, pool, 16);
	replicator_queue_set_change_callback(queue,
		replicator_brain_queue_changed, brain);
	replicator_brain_fill(brain);
	return brain;
}

void replicator_brain_deinit(struct replicator_brain **_brain)
{
	struct replicator_brain *brain = *_brain;
	struct dsync_client **connp;

	*_brain = NULL;

	brain->deinitializing = TRUE;
	array_foreach_modifiable(&brain->dsync_clients, connp)
		dsync_client_deinit(connp);
	timeout_remove(&brain->to);
	pool_unref(&brain->pool);
}

struct replicator_queue *
replicator_brain_get_queue(struct replicator_brain *brain)
{
	return brain->queue;
}

const struct replicator_settings *
replicator_brain_get_settings(struct replicator_brain *brain)
{
	return brain->set;
}

const ARRAY_TYPE(dsync_client) *
replicator_brain_get_dsync_clients(struct replicator_brain *brain)
{
	return &brain->dsync_clients;
}

static struct dsync_client *
get_dsync_client(struct replicator_brain *brain)
{
	struct dsync_client *const *connp, *conn = NULL;

	array_foreach(&brain->dsync_clients, connp) {
		if (!dsync_client_is_busy(*connp))
			return *connp;
	}
	if (array_count(&brain->dsync_clients) ==
	    brain->set->replication_max_conns)
		return NULL;

	conn = dsync_client_init(brain->set->doveadm_socket_path,
				 brain->set->replication_dsync_parameters);
	array_push_back(&brain->dsync_clients, &conn);
	return conn;
}

static void dsync_callback(enum dsync_reply reply, const char *state,
			   void *context)
{
	struct replicator_sync_context *ctx = context;
	struct replicator_user *user = ctx->user;

	if (!replicator_user_unref(&user)) {
		/* user was already removed */
	} else if (reply == DSYNC_REPLY_NOUSER) {
		/* user no longer exists, remove from replication */
		replicator_queue_remove(ctx->brain->queue, &ctx->user);
	} else {
		i_free(ctx->user->state);
		ctx->user->state = i_strdup_empty(state);
		ctx->user->last_sync_failed = reply != DSYNC_REPLY_OK;
		if (reply == DSYNC_REPLY_OK)
			ctx->user->last_successful_sync = ioloop_time;
		replicator_queue_push(ctx->brain->queue, ctx->user);
	}
	if (!ctx->brain->deinitializing)
		replicator_brain_fill(ctx->brain);
	i_free(ctx);
}

static bool
dsync_replicate(struct replicator_brain *brain, struct replicator_user *user)
{
	struct replicator_sync_context *ctx;
	struct dsync_client *conn;
	time_t next_full_sync;
	bool full;

	conn = get_dsync_client(brain);
	if (conn == NULL)
		return FALSE;

	next_full_sync = user->last_full_sync +
		brain->set->replication_full_sync_interval;
	full = next_full_sync <= ioloop_time;
	/* update the sync times immediately. if the replication fails we still
	   wouldn't want it to be retried immediately. */
	user->last_fast_sync = ioloop_time;
	if (full || user->force_full_sync) {
		user->last_full_sync = ioloop_time;
		user->force_full_sync = FALSE;
	}
	/* reset priority also. if more updates arrive during replication
	   we'll do another replication to make sure nothing gets lost */
	user->priority = REPLICATION_PRIORITY_NONE;

	ctx = i_new(struct replicator_sync_context, 1);
	ctx->brain = brain;
	ctx->user = user;
	replicator_user_ref(user);
	dsync_client_sync(conn, user->username, user->state, full,
			  dsync_callback, ctx);
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
		timeout_remove(&brain->to);
		brain->to = timeout_add(next_secs * 1000,
					replicator_brain_timeout, brain);
		return FALSE;
	}

	if (!dsync_replicate(brain, user)) {
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
