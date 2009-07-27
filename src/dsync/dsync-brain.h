#ifndef DSYNC_BRAIN_H
#define DSYNC_BRAIN_H

enum dsync_brain_flags {
	DSYNC_BRAIN_FLAG_FULL_SYNC	= 0x01
};

struct dsync_worker;

struct dsync_brain *dsync_brain_init(struct dsync_worker *src_worker,
				     struct dsync_worker *dest_worker,
				     enum dsync_brain_flags flags);
int dsync_brain_deinit(struct dsync_brain **brain);

void dsync_brain_sync(struct dsync_brain *brain);

#endif
