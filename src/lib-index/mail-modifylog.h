#ifndef __MAIL_MODIFYLOG_H
#define __MAIL_MODIFYLOG_H

typedef enum {
	RECORD_TYPE_EXPUNGE,
	RECORD_TYPE_FLAGS_CHANGED
} ModifyLogRecordType;

typedef struct _ModifyLogHeader ModifyLogHeader;
typedef struct _ModifyLogRecord ModifyLogRecord;

/* if sync_id has this value, the log file is full and should be
   deleted or reused. */
#define SYNC_ID_FULL ((unsigned int)-1)

struct _ModifyLogHeader {
	unsigned int indexid;
	unsigned int sync_id;
};

struct _ModifyLogRecord {
	unsigned int type;
	unsigned int seq;
	unsigned int uid;
};

/* NOTE: All these functions require the index file to be locked. */

int mail_modifylog_create(MailIndex *index);
int mail_modifylog_open_or_create(MailIndex *index);
void mail_modifylog_free(MailModifyLog *log);

/* Append EXPUGE or FLAGS entry to modify log. Index must be exclusively
   locked before calling these functions, and modifylog must have been
   marked synced within the same lock. */
int mail_modifylog_add_expunge(MailModifyLog *log, unsigned int seq,
			       unsigned int uid, int external_change);
int mail_modifylog_add_flags(MailModifyLog *log, unsigned int seq,
			     unsigned int uid, int external_change);

/* Synchronize the data into disk */
int mail_modifylog_sync_file(MailModifyLog *log);

/* Returns the nonsynced log entries. count is set to number of log records. */
ModifyLogRecord *mail_modifylog_get_nonsynced(MailModifyLog *log,
					      unsigned int *count);

/* Marks the modify log as being synced with in-memory state. */
int mail_modifylog_mark_synced(MailModifyLog *log);

/* Finds expunged messages for the given sequence range, and number of
   expunged messages before the range. Returns sorted 0-terminated list of
   expunged UIDs, or NULL if error occured. */
const unsigned int *
mail_modifylog_seq_get_expunges(MailModifyLog *log,
				unsigned int first_seq,
				unsigned int last_seq,
				unsigned int *expunges_before);

/* Returns sorted 0-terminated list of expunged UIDs in given range,
   or NULL if error occured. */
const unsigned int *
mail_modifylog_uid_get_expunges(MailModifyLog *log,
				unsigned int first_uid,
				unsigned int last_uid);

#endif
