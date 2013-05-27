#ifndef SDBOX_STORAGE_H
#define SDBOX_STORAGE_H

#include "index-storage.h"
#include "dbox-storage.h"

#define SDBOX_STORAGE_NAME "sdbox"
#define SDBOX_MAIL_FILE_PREFIX "u."
#define SDBOX_MAIL_FILE_FORMAT SDBOX_MAIL_FILE_PREFIX"%u"

#define SDBOX_INDEX_HEADER_MIN_SIZE (sizeof(uint32_t))
struct sdbox_index_header {
	/* increased every time a full mailbox rebuild is done */
	uint32_t rebuild_count;
	guid_128_t mailbox_guid;
	uint8_t flags; /* enum dbox_index_header_flags */
	uint8_t unused[3];
};

struct sdbox_storage {
	struct dbox_storage storage;
};

struct sdbox_mailbox {
	struct mailbox box;
	struct sdbox_storage *storage;

	uint32_t hdr_ext_id;
	/* if non-zero, storage should be rebuilt (except if rebuild_count
	   has changed from this value) */
	uint32_t corrupted_rebuild_count;

	guid_128_t mailbox_guid;
};

extern struct mail_vfuncs sdbox_mail_vfuncs;

int sdbox_mail_open(struct dbox_mail *mail, uoff_t *offset_r,
		    struct dbox_file **file_r);

int sdbox_read_header(struct sdbox_mailbox *mbox,
		      struct sdbox_index_header *hdr, bool log_error,
		      bool *need_resize_r);
void sdbox_set_mailbox_corrupted(struct mailbox *box);

struct mail_save_context *
sdbox_save_alloc(struct mailbox_transaction_context *_t);
int sdbox_save_begin(struct mail_save_context *ctx, struct istream *input);
int sdbox_save_finish(struct mail_save_context *ctx);
void sdbox_save_cancel(struct mail_save_context *ctx);

struct dbox_file *
sdbox_save_file_get_file(struct mailbox_transaction_context *t, uint32_t seq);
void sdbox_save_add_file(struct mail_save_context *ctx, struct dbox_file *file);

int sdbox_transaction_save_commit_pre(struct mail_save_context *ctx);
void sdbox_transaction_save_commit_post(struct mail_save_context *ctx,
					struct mail_index_transaction_commit_result *result);
void sdbox_transaction_save_rollback(struct mail_save_context *ctx);

int sdbox_copy(struct mail_save_context *ctx, struct mail *mail);

#endif
