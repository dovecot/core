#ifndef DSYNC_BRAIN_H
#define DSYNC_BRAIN_H

enum dsync_brain_flags {
	DSYNC_BRAIN_FLAG_FULL_SYNC	= 0x01,
	DSYNC_BRAIN_FLAG_VERBOSE	= 0x02,
	/* Run in backup mode. All changes from src are forced into dest,
	   discarding any potential changes in dest. */
	DSYNC_BRAIN_FLAG_BACKUP		= 0x04,
	/* Run in "local mode". Don't use ioloop. */
	DSYNC_BRAIN_FLAG_LOCAL		= 0x08
};

struct dsync_worker;

struct dsync_brain *
dsync_brain_init(struct dsync_worker *src_worker,
		 struct dsync_worker *dest_worker,
		 const char *mailbox, enum dsync_brain_flags flags);
int dsync_brain_deinit(struct dsync_brain **brain);

void dsync_brain_sync(struct dsync_brain *brain);
void dsync_brain_sync_all(struct dsync_brain *brain);

bool dsync_brain_has_unexpected_changes(struct dsync_brain *brain);
bool dsync_brain_has_failed(struct dsync_brain *brain);

#endif
