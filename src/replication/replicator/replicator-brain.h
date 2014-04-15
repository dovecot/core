#ifndef REPLICATOR_BRAIN_H
#define REPLICATOR_BRAIN_H

struct replicator_settings;
struct replicator_queue;

struct replicator_brain *
replicator_brain_init(struct replicator_queue *queue,
		      const struct replicator_settings *set);
void replicator_brain_deinit(struct replicator_brain **brain);

struct replicator_queue *
replicator_brain_get_queue(struct replicator_brain *brain);
const struct replicator_settings *
replicator_brain_get_settings(struct replicator_brain *brain);

const ARRAY_TYPE(dsync_client) *
replicator_brain_get_dsync_clients(struct replicator_brain *brain);

#endif
