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

int mdbox_storage_rebuild(struct mdbox_storage *storage,
			  struct mailbox *fsckd_box,
			  enum mdbox_rebuild_reason reason);

#endif
