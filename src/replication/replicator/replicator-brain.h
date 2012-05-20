#ifndef REPLICATOR_BRAIN_H
#define REPLICATOR_BRAIN_H

struct replicator_settings;

struct replicator_brain *
replicator_brain_init(struct replicator_queue *queue,
		      const struct replicator_settings *set);
void replicator_brain_deinit(struct replicator_brain **brain);

#endif
