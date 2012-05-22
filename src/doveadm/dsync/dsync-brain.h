#ifndef DSYNC_BRAIN_H
#define DSYNC_BRAIN_H

struct mail_namespace;
struct mail_user;
struct dsync_slave;

enum dsync_brain_flags {
	DSYNC_BRAIN_FLAG_MAILS_HAVE_GUIDS	= 0x01,
	DSYNC_BRAIN_FLAG_SEND_REQUESTS		= 0x02
};

enum dsync_brain_sync_type {
	DSYNC_BRAIN_SYNC_TYPE_UNKNOWN,
	/* Go through all mailboxes to make sure everything is synced */
	DSYNC_BRAIN_SYNC_TYPE_FULL,
	/* Go through all mailboxes that have changed (based on UIDVALIDITY,
	   UIDNEXT, HIGHESTMODSEQ). If both sides have had equal amount of
	   changes in some mailbox, it may get incorrectly skipped. */
	DSYNC_BRAIN_SYNC_TYPE_CHANGED,
	/* Use saved state to find out what has changed. */
	DSYNC_BRAIN_SYNC_TYPE_STATE
};

struct dsync_brain *
dsync_brain_master_init(struct mail_user *user, struct dsync_slave *slave,
			struct mail_namespace *sync_ns,
			enum dsync_brain_sync_type sync_type,
			enum dsync_brain_flags flags,
			const char *state);
struct dsync_brain *
dsync_brain_slave_init(struct mail_user *user, struct dsync_slave *slave);
/* Returns 0 if everything was successful, -1 if syncing failed in some way */
int dsync_brain_deinit(struct dsync_brain **brain);

/* Returns TRUE if brain needs to run more, FALSE if it's finished.
   changed_r is TRUE if anything happened during this run. */
bool dsync_brain_run(struct dsync_brain *brain, bool *changed_r);
/* Returns TRUE if brain has failed, and there's no point in continuing. */
bool dsync_brain_has_failed(struct dsync_brain *brain);

#endif
