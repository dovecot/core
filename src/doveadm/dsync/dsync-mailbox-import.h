#ifndef DSYNC_MAILBOX_IMPORT_H
#define DSYNC_MAILBOX_IMPORT_H

#include "mail-error.h"

enum dsync_mailbox_import_flags {
	DSYNC_MAILBOX_IMPORT_FLAG_MASTER_BRAIN		= 0x01,
	DSYNC_MAILBOX_IMPORT_FLAG_WANT_MAIL_REQUESTS	= 0x02,
	DSYNC_MAILBOX_IMPORT_FLAG_REVERT_LOCAL_CHANGES	= 0x04,
	DSYNC_MAILBOX_IMPORT_FLAG_DEBUG			= 0x08,
	DSYNC_MAILBOX_IMPORT_FLAG_MAILS_HAVE_GUIDS	= 0x10,
	DSYNC_MAILBOX_IMPORT_FLAG_MAILS_USE_GUID128	= 0x20,
	DSYNC_MAILBOX_IMPORT_FLAG_NO_NOTIFY		= 0x40,
	DSYNC_MAILBOX_IMPORT_FLAG_EMPTY_HDR_WORKAROUND	= 0x100
};

struct mailbox;
struct dsync_mailbox_attribute;
struct dsync_mail;
struct dsync_mail_change;
struct dsync_transaction_log_scan;

struct dsync_mailbox_importer *
dsync_mailbox_import_init(struct mailbox *box,
			  struct mailbox *virtual_all_box,
			  struct dsync_transaction_log_scan *log_scan,
			  uint32_t last_common_uid,
			  uint64_t last_common_modseq,
			  uint64_t last_common_pvt_modseq,
			  uint32_t remote_uid_next,
			  uint32_t remote_first_recent_uid,
			  uint64_t remote_highest_modseq,
			  uint64_t remote_highest_pvt_modseq,
			  time_t sync_since_timestamp,
			  time_t sync_until_timestamp,
			  uoff_t sync_max_size,
			  const char *sync_flag,
			  unsigned int commit_msgs_interval,
			  enum dsync_mailbox_import_flags flags,
			  unsigned int hdr_hash_version,
			  const char *const *hashed_headers);
int dsync_mailbox_import_attribute(struct dsync_mailbox_importer *importer,
				   const struct dsync_mailbox_attribute *attr);
int dsync_mailbox_import_change(struct dsync_mailbox_importer *importer,
				const struct dsync_mail_change *change);
int dsync_mailbox_import_changes_finish(struct dsync_mailbox_importer *importer);
const struct dsync_mail_request *
dsync_mailbox_import_next_request(struct dsync_mailbox_importer *importer);
int dsync_mailbox_import_mail(struct dsync_mailbox_importer *importer,
			      const struct dsync_mail *mail);
int dsync_mailbox_import_deinit(struct dsync_mailbox_importer **importer,
				bool success,
				uint32_t *last_common_uid_r,
				uint64_t *last_common_modseq_r,
				uint64_t *last_common_pvt_modseq_r,
				uint32_t *last_messages_count_r,
				const char **changes_during_sync_r,
				bool *require_full_resync_r,
				enum mail_error *error_r);

const char *dsync_mailbox_import_get_proctitle(struct dsync_mailbox_importer *importer);

#endif
