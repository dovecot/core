#ifndef REPLICATOR_QUEUE_H
#define REPLICATOR_QUEUE_H

#include "priorityq.h"
#include "replication-common.h"

struct replicator_user {
	struct priorityq_item item;

	char *username;
	/* dsync state for incremental syncing */
	char *state;
	/* last time this user's state was updated */
	time_t last_update;
	/* last_fast_sync is always >= last_full_sync. */
	time_t last_fast_sync, last_full_sync;

	enum replication_priority priority;
	/* User isn't currently in replication queue */
	unsigned int popped:1;
	/* Last replication sync failed */
	unsigned int last_sync_failed:1;
};

typedef void replicator_sync_callback_t(bool success, void *context);

struct replicator_queue *
replicator_queue_init(unsigned int full_sync_interval,
		      unsigned int failure_resync_interval);
void replicator_queue_deinit(struct replicator_queue **queue);

/* Call the specified callback when data is added/removed/moved in queue
   via _add(), _add_sync() or _remove() functions (not push/pop). */
void replicator_queue_set_change_callback(struct replicator_queue *queue,
					  void (*callback)(void *context),
					  void *context);

/* Lookup an existing user */
struct replicator_user *
replicator_queue_lookup(struct replicator_queue *queue, const char *username);
/* Add a user to queue and return it. If the user already exists, it's updated
   only if the new priority is higher. */
struct replicator_user *
replicator_queue_add(struct replicator_queue *queue, const char *username,
		     enum replication_priority priority);
void replicator_queue_add_sync(struct replicator_queue *queue,
			       const char *username,
			       replicator_sync_callback_t *callback,
			       void *context);
/* Remove user from replication queue and free it. */
void replicator_queue_remove(struct replicator_queue *queue,
			     struct replicator_user **user);

/* Return the next user from replication queue, and remove it from the queue.
   If there's nothing to be replicated currently, returns NULL and sets
   next_secs_r to when there should be more work to do. */
struct replicator_user *
replicator_queue_pop(struct replicator_queue *queue,
		     unsigned int *next_secs_r);
/* Add user back to queue. */
void replicator_queue_push(struct replicator_queue *queue,
			   struct replicator_user *user);

int replicator_queue_import(struct replicator_queue *queue, const char *path);
int replicator_queue_export(struct replicator_queue *queue, const char *path);

/* Returns TRUE if user replication can be started now, FALSE if not. When
   returning FALSE, next_secs_r is set to user's next replication time. */
bool replicator_queue_want_sync_now(struct replicator_queue *queue,
				    struct replicator_user *user,
				    unsigned int *next_secs_r);
/* Iterate through all users in the queue. */
struct replicator_queue_iter *
replicator_queue_iter_init(struct replicator_queue *queue);
struct replicator_user *
replicator_queue_iter_next(struct replicator_queue_iter *iter);
void replicator_queue_iter_deinit(struct replicator_queue_iter **iter);

#endif
