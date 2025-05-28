#ifndef REPLICATOR_QUEUE_PRIVATE_H
#define REPLICATOR_QUEUE_PRIVATE_H

#include "replicator-queue.h"

struct replicator_queue {
	struct priorityq *user_queue;
	struct event *event;
	/* username => struct replicator_user* */
	HASH_TABLE(char *, struct replicator_user *) user_hash;

	ARRAY(struct replicator_sync_lookup) sync_lookups;

	unsigned int full_sync_interval;
	unsigned int failure_resync_interval;

	void (*change_callback)(void *context);
	void *change_context;
};

#endif
