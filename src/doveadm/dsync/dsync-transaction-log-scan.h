#ifndef DSYNC_TRANSACTION_LOG_SCAN_H
#define DSYNC_TRANSACTION_LOG_SCAN_H

HASH_TABLE_DEFINE_TYPE(dsync_uid_mail_change,
		       uint32_t, struct dsync_mail_change*);

struct mail_index_view;
struct dsync_transaction_log_scan;

int dsync_transaction_log_scan_init(struct mail_index_view *view,
				    uint32_t highest_wanted_uid,
				    uint64_t modseq,
				    struct dsync_transaction_log_scan **scan_r);
void dsync_transaction_log_scan_get_hash(struct dsync_transaction_log_scan *scan,
					 HASH_TABLE_TYPE(dsync_uid_mail_change) *hash_r);
/* Returns TRUE if the entire transaction log was scanned */
bool dsync_transaction_log_scan_has_all_changes(struct dsync_transaction_log_scan *scan);
/* If the given UID has been expunged after the initial log scan, create/update
   a change record for it and return it. */
struct dsync_mail_change *
dsync_transaction_log_scan_find_new_expunge(struct dsync_transaction_log_scan *scan,
					    uint32_t uid);
void dsync_transaction_log_scan_deinit(struct dsync_transaction_log_scan **scan);

#endif
