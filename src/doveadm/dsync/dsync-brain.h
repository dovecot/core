#ifndef DSYNC_BRAIN_H
#define DSYNC_BRAIN_H

struct mail_namespace;
struct mail_user;
struct dsync_ibc;

enum dsync_brain_flags {
	DSYNC_BRAIN_FLAG_SEND_MAIL_REQUESTS	= 0x01,
	DSYNC_BRAIN_FLAG_BACKUP_SEND		= 0x02,
	DSYNC_BRAIN_FLAG_BACKUP_RECV		= 0x04,
	DSYNC_BRAIN_FLAG_DEBUG			= 0x08,
	DSYNC_BRAIN_FLAG_SYNC_VISIBLE_NAMESPACES= 0x10
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
dsync_brain_master_init(struct mail_user *user, struct dsync_ibc *ibc,
			struct mail_namespace *sync_ns, const char *sync_box,
			enum dsync_brain_sync_type sync_type,
			enum dsync_brain_flags flags, unsigned int lock_timeout,
			const char *state);
struct dsync_brain *
dsync_brain_slave_init(struct mail_user *user, struct dsync_ibc *ibc);
/* Returns 0 if everything was successful, -1 if syncing failed in some way */
int dsync_brain_deinit(struct dsync_brain **brain);

/* Returns TRUE if brain needs to run more, FALSE if it's finished.
   changed_r is TRUE if anything happened during this run. */
bool dsync_brain_run(struct dsync_brain *brain, bool *changed_r);
/* Returns TRUE if brain has failed, and there's no point in continuing. */
bool dsync_brain_has_failed(struct dsync_brain *brain);
/* Returns the current sync state string, which can be given as parameter to
   dsync_brain_master_init() to quickly sync only the new changes. */
void dsync_brain_get_state(struct dsync_brain *brain, string_t *output);

#endif
