#ifndef __MAIL_MODIFYLOG_H
#define __MAIL_MODIFYLOG_H

enum modify_log_record_type {
	RECORD_TYPE_EXPUNGE,
	RECORD_TYPE_FLAGS_CHANGED
};

/* if sync_id has this value, the log file is full and should be
   deleted or reused. */
#define SYNC_ID_FULL ((unsigned int)-1)

struct modify_log_header {
	unsigned int indexid;
	unsigned int sync_id;
	uoff_t used_file_size;
};

struct modify_log_record {
	unsigned int type;
	unsigned int seq1, seq2;
	unsigned int uid1, uid2;
};

/* for mail_modifylog_*_get_expunges() */
struct modify_log_expunge {
	unsigned int uid1, uid2; /* NOTE: may be outside wanted range */
	unsigned int seq_count;
};

/* NOTE: All these functions require the index file to be locked. */

int mail_modifylog_create(struct mail_index *index);
int mail_modifylog_open_or_create(struct mail_index *index);
void mail_modifylog_free(struct mail_modify_log *log);

/* Append EXPUGE or FLAGS entry to modify log. Index must be exclusively
   locked before calling these functions, and modifylog must have been
   marked synced within the same lock. */
int mail_modifylog_add_expunges(struct mail_modify_log *log,
				unsigned int first_seq, unsigned int last_seq,
				unsigned int first_uid, unsigned int last_uid,
				int external_change);
int mail_modifylog_add_flags(struct mail_modify_log *log, unsigned int seq,
			     unsigned int uid, int external_change);

/* Synchronize the data into disk */
int mail_modifylog_sync_file(struct mail_modify_log *log, int *fsync_fd);

/* Must be called when exclusive lock is dropped from index. */
void mail_modifylog_notify_lock_drop(struct mail_modify_log *log);

/* Updates arr and count parameters to list nonsynced log entries.
   Returns TRUE if successful. */
int mail_modifylog_get_nonsynced(struct mail_modify_log *log,
				 const struct modify_log_record **arr1,
				 unsigned int *count1,
				 const struct modify_log_record **arr2,
				 unsigned int *count2);

/* Marks the modify log as being synced with in-memory state. */
int mail_modifylog_mark_synced(struct mail_modify_log *log);

/* Finds expunged messages for the given sequence range, and number of
   expunged messages before the range. Returns 0,0 terminated list of
   expunged UIDs, or NULL if error occured.

   Note that returned UID range may not be exact for first returned
   expunge record. For example fetching range 9:10 may return
   expunges_before=8, {uid1=1, uid2=9, seq_count=1} if only message 10
   exists.

   Also the last expunge record's both uid and seq_count ranges may go
   past last_seq */
const struct modify_log_expunge *
mail_modifylog_seq_get_expunges(struct mail_modify_log *log,
				unsigned int first_seq,
				unsigned int last_seq,
				unsigned int *expunges_before);

/* Like above, but for given UID range. expunges_before is treated a bit
   differently however. It specifies the number of messages deleted before
   the first returned expunge-record, which may partially be before our
   wanted range. For example fetching range 9:10 may return
   expunges_before=0, {uid1=1, uid2=9, seq_count=9} if only message 10
   exists. This is because we have no idea how many messages there are
   between UIDs since they're not guaranteed to be contiguous. */
const struct modify_log_expunge *
mail_modifylog_uid_get_expunges(struct mail_modify_log *log,
				unsigned int first_uid,
				unsigned int last_uid,
				unsigned int *expunges_before);

/* Get number of non-synced expunges in modify log. */
unsigned int mail_modifylog_get_expunge_count(struct mail_modify_log *log);

#endif
