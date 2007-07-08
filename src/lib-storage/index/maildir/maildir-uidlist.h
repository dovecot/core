#ifndef __MAILDIR_UIDLI3ST_H
#define __MAILDIR_UIDLIST_H

#define MAILDIR_UIDLIST_NAME "dovecot-uidlist"

struct maildir_uidlist_sync_ctx;

enum maildir_uidlist_sync_flags {
	MAILDIR_UIDLIST_SYNC_PARTIAL	= 0x01
};

enum maildir_uidlist_rec_flag {
	MAILDIR_UIDLIST_REC_FLAG_NEW_DIR	= 0x01,
	MAILDIR_UIDLIST_REC_FLAG_MOVED		= 0x02,
	MAILDIR_UIDLIST_REC_FLAG_RECENT		= 0x04,
	MAILDIR_UIDLIST_REC_FLAG_NONSYNCED	= 0x08,
	MAILDIR_UIDLIST_REC_FLAG_RACING		= 0x10
};

int maildir_uidlist_lock(struct maildir_uidlist *uidlist);
int maildir_uidlist_try_lock(struct maildir_uidlist *uidlist);
int maildir_uidlist_lock_touch(struct maildir_uidlist *uidlist);
void maildir_uidlist_unlock(struct maildir_uidlist *uidlist);
bool maildir_uidlist_is_locked(struct maildir_uidlist *uidlist);

struct maildir_uidlist *maildir_uidlist_init(struct maildir_mailbox *mbox);
void maildir_uidlist_deinit(struct maildir_uidlist *uidlist);

/* Returns -1 if error, 0 if file is broken or lost, 1 if ok. */
int maildir_uidlist_refresh(struct maildir_uidlist *uidlist);

/* Returns uidlist record for given filename, or NULL if not found. */
const char *
maildir_uidlist_lookup(struct maildir_uidlist *uidlist, uint32_t uid,
		       enum maildir_uidlist_rec_flag *flags_r);
/* Returns TRUE if mail with given UID is recent. */
bool maildir_uidlist_is_recent(struct maildir_uidlist *uidlist, uint32_t uid);
/* Returns number of recent messages. */
uint32_t maildir_uidlist_get_recent_count(struct maildir_uidlist *uidlist);

uint32_t maildir_uidlist_get_uid_validity(struct maildir_uidlist *uidlist);
uint32_t maildir_uidlist_get_next_uid(struct maildir_uidlist *uidlist);

void maildir_uidlist_set_uid_validity(struct maildir_uidlist *uidlist,
				      uint32_t uid_validity, uint32_t next_uid);

/* Sync uidlist with what's actually on maildir. Returns same as
   maildir_uidlist_lock(). */
int maildir_uidlist_sync_init(struct maildir_uidlist *uidlist,
			      enum maildir_uidlist_sync_flags sync_flags,
			      struct maildir_uidlist_sync_ctx **sync_ctx_r);
/* Returns 1 = ok, -1 = error, 0 = new file and dovecot-uidlist is locked */
int maildir_uidlist_sync_next_pre(struct maildir_uidlist_sync_ctx *ctx,
				  const char *filename);
int maildir_uidlist_sync_next(struct maildir_uidlist_sync_ctx *ctx,
			      const char *filename,
			      enum maildir_uidlist_rec_flag flags);
const char *
maildir_uidlist_sync_get_full_filename(struct maildir_uidlist_sync_ctx *ctx,
				       const char *filename);
void maildir_uidlist_sync_finish(struct maildir_uidlist_sync_ctx *ctx);
int maildir_uidlist_sync_deinit(struct maildir_uidlist_sync_ctx **ctx);

const char *
maildir_uidlist_get_full_filename(struct maildir_uidlist *uidlist,
				  const char *filename);

void maildir_uidlist_add_flags(struct maildir_uidlist *uidlist,
			       const char *filename,
			       enum maildir_uidlist_rec_flag flags);

/* List all maildir files. */
struct maildir_uidlist_iter_ctx *
maildir_uidlist_iter_init(struct maildir_uidlist *uidlist);
int maildir_uidlist_iter_next(struct maildir_uidlist_iter_ctx *ctx,
			      uint32_t *uid_r,
			      enum maildir_uidlist_rec_flag *flags_r,
			      const char **filename_r);
void maildir_uidlist_iter_deinit(struct maildir_uidlist_iter_ctx *ctx);

#endif
