#ifndef MDBOX_STORAGE_H
#define MDBOX_STORAGE_H

#include "index-storage.h"
#include "dbox-storage.h"
#include "mdbox-settings.h"

#define MDBOX_STORAGE_NAME "mdbox"
#define MDBOX_GLOBAL_INDEX_PREFIX "dovecot.map.index"
#define MDBOX_GLOBAL_DIR_NAME "storage"
#define MDBOX_MAIL_FILE_PREFIX "m."
#define MDBOX_MAIL_FILE_FORMAT MDBOX_MAIL_FILE_PREFIX"%u"
#define MDBOX_MAX_OPEN_UNUSED_FILES 2
#define MDBOX_CLOSE_UNUSED_FILES_TIMEOUT_SECS 30

#define MDBOX_INDEX_HEADER_MIN_SIZE (sizeof(uint32_t))
struct mdbox_index_header {
	uint32_t map_uid_validity;
	uint8_t mailbox_guid[MAIL_GUID_128_SIZE];
};

struct mdbox_storage {
	struct dbox_storage storage;
	const struct mdbox_settings *set;

	/* paths for storage directories */
	const char *storage_dir, *alt_storage_dir;
	struct mdbox_map *map;

	ARRAY_DEFINE(open_files, struct mdbox_file *);
	struct timeout *to_close_unused_files;

	ARRAY_TYPE(uint32_t) move_to_alt_map_uids;
	ARRAY_TYPE(uint32_t) move_from_alt_map_uids;

	/* if non-zero, storage should be rebuilt (except if rebuild_count
	   has changed from this value) */
	uint32_t corrupted_rebuild_count;

	unsigned int corrupted:1;
	unsigned int rebuilding_storage:1;
	unsigned int preallocate_space:1;
};

struct mdbox_mail_index_record {
	uint32_t map_uid;
	/* UNIX timestamp of when the message was saved/copied to this
	   mailbox */
	uint32_t save_date;
};

struct mdbox_mailbox {
	struct mailbox box;
	struct mdbox_storage *storage;

	uint32_t map_uid_validity;
	uint32_t ext_id, hdr_ext_id, guid_ext_id;

	unsigned int creating:1;
};

extern struct mail_vfuncs mdbox_mail_vfuncs;

struct mailbox *
mdbox_mailbox_alloc(struct mail_storage *storage, struct mailbox_list *list,
		    const char *name, enum mailbox_flags flags);

int mdbox_mail_open(struct dbox_mail *mail, uoff_t *offset_r,
		    struct dbox_file **file_r);

/* Get map_uid for wanted message. */
int mdbox_mail_lookup(struct mdbox_mailbox *mbox, struct mail_index_view *view,
		      uint32_t seq, uint32_t *map_uid_r);
uint32_t dbox_get_uidvalidity_next(struct mailbox_list *list);
int mdbox_read_header(struct mdbox_mailbox *mbox,
		      struct mdbox_index_header *hdr);
void mdbox_update_header(struct mdbox_mailbox *mbox,
			 struct mail_index_transaction *trans,
			 const struct mailbox_update *update);

struct mail_save_context *
mdbox_save_alloc(struct mailbox_transaction_context *_t);
int mdbox_save_begin(struct mail_save_context *ctx, struct istream *input);
int mdbox_save_finish(struct mail_save_context *ctx);
void mdbox_save_cancel(struct mail_save_context *ctx);

struct dbox_file *
mdbox_save_file_get_file(struct mailbox_transaction_context *t,
			 uint32_t seq, uoff_t *offset_r);

int mdbox_transaction_save_commit_pre(struct mail_save_context *ctx);
void mdbox_transaction_save_commit_post(struct mail_save_context *ctx,
					struct mail_index_transaction_commit_result *result);
void mdbox_transaction_save_rollback(struct mail_save_context *ctx);

int mdbox_copy(struct mail_save_context *ctx, struct mail *mail);

void mdbox_purge_alt_flag_change(struct mail *mail, bool move_to_alt);
int mdbox_purge(struct mail_storage *storage);

void mdbox_storage_set_corrupted(struct mdbox_storage *storage);

#endif
