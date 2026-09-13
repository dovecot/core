#ifndef MDBOX_STORAGE_REBUILD_H
#define MDBOX_STORAGE_REBUILD_H

enum mdbox_rebuild_reason {
	/* Storage was marked as corrupted earlier */
	MDBOX_REBUILD_REASON_CORRUPTED = BIT(0),
	/* Mailbox index was marked fsck'd */
	MDBOX_REBUILD_REASON_MAILBOX_FSCKD = BIT(1),
	/* dovecot.map.index was marked fsck'd */
	MDBOX_REBUILD_REASON_MAP_FSCKD = BIT(2),
	/* Forced rebuild (e.g. doveadm force-resync) */
	MDBOX_REBUILD_REASON_FORCED = BIT(3),
};

/* Rebuild the storage. Returns 1 if the rebuild was run, 0 if it was skipped
   because this process has the mailbox list index locked, -1 on error. */
int mdbox_storage_rebuild(struct mdbox_storage *storage,
			  struct mailbox *fscked_box,
			  enum mdbox_rebuild_reason reason);
/* Rebuild the storage, if a forced rebuild was requested while the mailbox
   list index was being rebuilt. */
int mdbox_storage_rebuild_deferred(struct mdbox_storage *storage);

#endif
