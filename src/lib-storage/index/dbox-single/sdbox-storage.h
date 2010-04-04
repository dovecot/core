#ifndef SDBOX_STORAGE_H
#define SDBOX_STORAGE_H

#include "index-storage.h"
#include "dbox-storage.h"
#include "mailbox-list-private.h"

#define SDBOX_STORAGE_NAME "dbox"
#define SDBOX_MAIL_FILE_PREFIX "u."
#define SDBOX_MAIL_FILE_FORMAT SDBOX_MAIL_FILE_PREFIX"%u"

/* Flag specifies if the message should be in primary or alternative storage */
#define SDBOX_INDEX_FLAG_ALT MAIL_INDEX_MAIL_FLAG_BACKEND

#define SDBOX_INDEX_HEADER_MIN_SIZE (sizeof(uint32_t))
struct sdbox_index_header {
	uint32_t oldv1_highest_maildir_uid;
	uint8_t mailbox_guid[MAIL_GUID_128_SIZE];
};

struct sdbox_storage {
	struct dbox_storage storage;
	union mailbox_list_module_context list_module_ctx;
};

struct sdbox_mailbox {
	struct mailbox box;
	struct sdbox_storage *storage;

	uint32_t hdr_ext_id;

	unsigned int creating:1;
};

extern struct mail_vfuncs sdbox_mail_vfuncs;

int sdbox_mail_open(struct dbox_mail *mail, uoff_t *offset_r,
		    struct dbox_file **file_r);

uint32_t dbox_get_uidvalidity_next(struct mailbox_list *list);
int sdbox_read_header(struct sdbox_mailbox *mbox,
		      struct sdbox_index_header *hdr, bool log_error);
void sdbox_update_header(struct sdbox_mailbox *mbox,
			 struct mail_index_transaction *trans,
			 const struct mailbox_update *update);

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
