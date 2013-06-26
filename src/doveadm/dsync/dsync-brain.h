#ifndef DSYNC_BRAIN_H
#define DSYNC_BRAIN_H

#include "guid.h"

struct mail_namespace;
struct mail_user;
struct dsync_ibc;

enum dsync_brain_flags {
	DSYNC_BRAIN_FLAG_SEND_MAIL_REQUESTS	= 0x01,
	DSYNC_BRAIN_FLAG_BACKUP_SEND		= 0x02,
	DSYNC_BRAIN_FLAG_BACKUP_RECV		= 0x04,
	DSYNC_BRAIN_FLAG_DEBUG			= 0x08,
	DSYNC_BRAIN_FLAG_SYNC_VISIBLE_NAMESPACES= 0x10,
	/* Sync everything but the actual mails (e.g. mailbox creates,
	   deletes) */
	DSYNC_BRAIN_FLAG_NO_MAIL_SYNC		= 0x20,
	/* Used with BACKUP_SEND/RECV: Don't force the
	   Use the two-way syncing algorithm, but don't actually modify
	   anything locally. (Useful during migration.) */
	DSYNC_BRAIN_FLAG_NO_BACKUP_OVERWRITE	= 0x40
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

struct dsync_brain_settings {
	/* Sync only this namespace */
	struct mail_namespace *sync_ns;
	/* Sync only this mailbox name */
	const char *sync_box;
	/* Sync only this mailbox GUID */
	guid_128_t sync_box_guid;
	/* Exclude these mailboxes from the sync. They can contain '*'
	   wildcards and be \special-use flags. */
	const char *const *exclude_mailboxes;

	/* If non-zero, use dsync lock file for this user */
	unsigned int lock_timeout_secs;
	/* Input state for DSYNC_BRAIN_SYNC_TYPE_STATE */
	const char *state;
};

struct dsync_brain *
dsync_brain_master_init(struct mail_user *user, struct dsync_ibc *ibc,
			enum dsync_brain_sync_type sync_type,
			enum dsync_brain_flags flags,
			const struct dsync_brain_settings *set);
struct dsync_brain *
dsync_brain_slave_init(struct mail_user *user, struct dsync_ibc *ibc,
		       bool local);
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
/* Returns the sync type that was used. Mainly useful with slave brain. */
enum dsync_brain_sync_type dsync_brain_get_sync_type(struct dsync_brain *brain);
/* Returns TRUE if there were any unexpected changes during the sync. */
bool dsync_brain_has_unexpected_changes(struct dsync_brain *brain);
/* Returns TRUE if we want to sync this namespace. */
bool dsync_brain_want_namespace(struct dsync_brain *brain,
				struct mail_namespace *ns);

#endif
