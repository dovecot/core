#ifndef __DBOX_UIDLIST_H
#define __DBOX_UIDLIST_H

#include "seq-range-array.h"

struct dbox_file;
struct dbox_mailbox;
struct dbox_uidlist_sync_ctx;

struct dbox_uidlist_entry {
	ARRAY_TYPE(seq_range) uid_list;

	uint32_t file_seq;
	/* file creation timestamp. used for rotation checks. */
	time_t create_time;
	/* the used file size. the actual file size may be larger. */
	uoff_t file_size;
};

struct dbox_uidlist *dbox_uidlist_init(struct dbox_mailbox *mbox);
void dbox_uidlist_deinit(struct dbox_uidlist *uidlist);

int dbox_uidlist_lock(struct dbox_uidlist *uidlist);
int dbox_uidlist_lock_touch(struct dbox_uidlist *uidlist);
void dbox_uidlist_unlock(struct dbox_uidlist *uidlist);

struct dbox_uidlist_entry *
dbox_uidlist_entry_lookup(struct dbox_uidlist *uidlist, uint32_t file_seq);

struct dbox_uidlist_append_ctx *
dbox_uidlist_append_init(struct dbox_uidlist *uidlist);
int dbox_uidlist_append_commit(struct dbox_uidlist_append_ctx *ctx,
			       time_t *mtime_r);
void dbox_uidlist_append_rollback(struct dbox_uidlist_append_ctx *ctx);

/* Open/create a file for appending a new message and lock it.
   Returns -1 if failed, 0 if ok. If new file is created, the file's header is
   already appended. */
int dbox_uidlist_append_locked(struct dbox_uidlist_append_ctx *ctx,
			       struct dbox_file **file_r, uoff_t mail_size);
void dbox_uidlist_append_finish_mail(struct dbox_uidlist_append_ctx *ctx,
				     struct dbox_file *file);

struct dbox_file *
dbox_uidlist_append_lookup_file(struct dbox_uidlist_append_ctx *ctx,
				uint32_t file_seq);

uint32_t dbox_uidlist_get_new_file_seq(struct dbox_uidlist *uidlist);
int dbox_uidlist_append_get_first_uid(struct dbox_uidlist_append_ctx *ctx,
				      uint32_t *uid_r, time_t *mtime_r);

int dbox_uidlist_sync_init(struct dbox_uidlist *uidlist,
			   struct dbox_uidlist_sync_ctx **ctx_r,
			   time_t *mtime_r);
int dbox_uidlist_sync_commit(struct dbox_uidlist_sync_ctx *ctx,
			     time_t *mtime_r);
void dbox_uidlist_sync_rollback(struct dbox_uidlist_sync_ctx *ctx);

void dbox_uidlist_sync_from_scratch(struct dbox_uidlist_sync_ctx *ctx);
void dbox_uidlist_sync_set_modified(struct dbox_uidlist_sync_ctx *ctx);

void dbox_uidlist_sync_append(struct dbox_uidlist_sync_ctx *ctx,
			      const struct dbox_uidlist_entry *entry);
void dbox_uidlist_sync_unlink(struct dbox_uidlist_sync_ctx *ctx,
			      uint32_t file_seq);

uint32_t dbox_uidlist_sync_get_uid_validity(struct dbox_uidlist_sync_ctx *ctx);
uint32_t dbox_uidlist_sync_get_next_uid(struct dbox_uidlist_sync_ctx *ctx);

int dbox_uidlist_get_mtime(struct dbox_uidlist *uidlist, time_t *mtime_r);

#endif
