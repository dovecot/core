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
	struct event *event;
};

struct replicator_brain {
	pool_t pool;
	struct replicator_queue *queue;
	const struct replicator_settings *set;
	struct timeout *to;
	struct event *event;

	ARRAY_TYPE(dsync_client) dsync_clients;

	bool deinitializing:1;
};

static void replicator_brain_fill(struct replicator_brain *brain);

static void replicator_brain_timeout(struct replicator_brain *brain)
{
	e_debug(brain->event, "Delayed handling of changed queue");

	timeout_remove(&brain->to);
	replicator_brain_fill(brain);
}

static void replicator_brain_queue_changed(void *context)
{
	struct replicator_brain *brain = context;

	/* Delay a bit filling the replication. We could have gotten here
	   before the replicator_user change was fully filled out. */
	timeout_remove(&brain->to);
	brain->to = timeout_add_short(0, replicator_brain_timeout, brain);
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
	brain->event = event_create(NULL);
	event_add_category(brain->event, &event_category_replication);

	p_array_init(&brain->dsync_clients, pool, 16);
	replicator_queue_set_change_callback(queue,
		replicator_brain_queue_changed, brain);
	replicator_brain_fill(brain);
	return brain;
}

void replicator_brain_deinit(struct replicator_brain **_brain)
{
	struct replicator_brain *brain = *_brain;
	struct dsync_client *conn;

	*_brain = NULL;

	brain->deinitializing = TRUE;
	array_foreach_elem(&brain->dsync_clients, conn)
		dsync_client_deinit(&conn);
	timeout_remove(&brain->to);
	event_unref(&brain->event);
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
	struct dsync_client *conn;

	array_foreach_elem(&brain->dsync_clients, conn) {
		if (!dsync_client_is_busy(conn))
			return conn;
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
		e_debug(ctx->event, "User was already removed");
		/* user was already removed */
	} else if (reply == DSYNC_REPLY_NOUSER ||
		   reply == DSYNC_REPLY_NOREPLICATE) {
		/* user no longer exists, or is not wanted for replication,
		   remove from replication */
		if (reply == DSYNC_REPLY_NOUSER) {
			e_debug(ctx->event, "User does not exist");
		} else {
			e_debug(ctx->event, "User has 'noreplicate' flag and "
					    "will not be replicated");
		}
		replicator_queue_remove(ctx->brain->queue, &ctx->user);
	} else {
		i_free(ctx->user->state);
		ctx->user->last_sync_failed = reply != DSYNC_REPLY_OK;
		if (reply == DSYNC_REPLY_OK) {
			e_debug(ctx->event, "User was successfully synced");
			ctx->user->state = i_strdup_empty(state);
			ctx->user->last_successful_sync = ioloop_time;
		} else {
			e_debug(ctx->event, "User sync failed: %s", state);
		}
		replicator_queue_push(ctx->brain->queue, ctx->user);
	}
	event_unref(&ctx->event);

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
	struct event *event = event_create(brain->event);
	event_set_append_log_prefix(event, t_strdup_printf(
		"%s: ", user->username));
	event_add_str(event, "user", user->username);

	conn = get_dsync_client(brain);
	if (conn == NULL) {
		e_debug(event, "Delay replication - dsync queue is full");
		event_unref(&event);
		return FALSE;
	}

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
	ctx->event = event;

	e_debug(ctx->event, "Starting %s replication",
		full ? "full" : "incremental");

	replicator_user_ref(user);
	dsync_client_sync(conn, user->username, user->state, full,
			  dsync_callback, ctx);
	return TRUE;
}

static bool replicator_brain_fill_next(struct replicator_brain *brain)
{
	struct replicator_user *user;
	unsigned int next_secs;

	user = replicator_queue_pop(brain->queue, &next_secs);
	if (user == NULL) {
		e_debug(brain->event, "Got no user from queue, waiting for %u seconds",
			next_secs);
		/* nothing more to do */
		timeout_remove(&brain->to);
		brain->to = timeout_add(next_secs * 1000,
					replicator_brain_timeout, brain);
		return FALSE;
	}

	if (!dsync_replicate(brain, user)) {
		/* all connections were full, put the user back to queue */
		e_debug(brain->event, "Could not replicate %s - pushing back to queue",
			user->username);
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
