#ifndef DBOX_INDEX_H
#define DBOX_INDEX_H

/* The file begins with a header followed by zero or more records:

   <file id> <status><expunges><dirty> [<status-specific data>]<LF>

   <expunges> contains either '0' = no or 'E' = file contains messages marked
   as expunged, which should be removed when possible.

   <dirty> contains either '0' = no or 'D' = file contains messages that don't
   have up-to-date metadata. When expunge copies message data to a new file,
   the dirty state should be flushed for the copied messages (or the dirty
   state should be copied).

   <expunges> and <dirty> can be written without locking the record, so syncing
   can update them even while messages are being appended to the file.

   If status-specific data isn't specified for the given status, it should be
   ignored. Especially 'U' status may contain different kinds of data.
*/

struct dbox_file;
struct dbox_index_append_context;

#define DBOX_INDEX_VERSION	'1'

enum dbox_index_file_status {
	/* File can be appended to as long as <expunges> is zero. It must be
	   locked when expunging. status-specific data contains a %08x lock
	   timestamp. */
	DBOX_INDEX_FILE_STATUS_APPENDABLE	= '0',
	/* File is currently being appended to. If this record can be locked,
	   the append crashed and this file should be opened for fixing
	   (truncate non-committed appends from the file). */
	DBOX_INDEX_FILE_STATUS_APPENDING	= 'A',
	/* File can't be appended to. */
	DBOX_INDEX_FILE_STATUS_NONAPPENDABLE	= 'N',
	/* File contains only a single message. It can't be appended to
	   and it can be expunged by unlinking the file. */
	DBOX_INDEX_FILE_STATUS_SINGLE_MESSAGE	= '1',
	/* The file has already been unlinked, this record should be removed. */
	DBOX_INDEX_FILE_STATUS_UNLINKED		= 'U',

	/* File is a maildir file. Status-specific data contains
	   old: <uid> <filename>
	   new: <uid> [<maildir extra field>] :<filename>
	*/
	DBOX_INDEX_FILE_STATUS_MAILDIR		= 'M'
};

enum dbox_index_file_lock_status {
	/* File was locked (ret=1) */
	DBOX_INDEX_FILE_LOCKED,
	/* File didn't have appendable status (ret=1) */
	DBOX_INDEX_FILE_LOCK_NOT_NEEDED,
	/* File was already locked by someone else (ret=0) */
	DBOX_INDEX_FILE_LOCK_TRY_AGAIN,
	/* File is already unlinked (ret=0) */
	DBOX_INDEX_FILE_LOCK_UNLINKED
};

struct dbox_index_file_header {
	/* DBOX_INDEX_VERSION */
	unsigned char version;
	unsigned char space_1;

	/* Current UIDVALIDITY */
	unsigned char uid_validity_hex[8];
	unsigned char space_2;

	/* Next available message UID */
	unsigned char next_uid_hex[8];
	unsigned char space_3;

	/* Next available <file id> */
	unsigned char next_file_id_hex[8];
};

struct dbox_index_record {
	unsigned int file_id;
	unsigned int file_offset;

	enum dbox_index_file_status status;
	const char *data;

	unsigned int expunges:1;
	unsigned int dirty:1;
	unsigned int locked:1;
};

struct dbox_index *dbox_index_init(struct dbox_mailbox *mbox);
void dbox_index_deinit(struct dbox_index **index);

/* Get the current UIDVALIDITY. Returns 0 if ok, -1 if I/O error. */
int dbox_index_get_uid_validity(struct dbox_index *index,
				uint32_t *uid_validity_r);

struct dbox_index_record *
dbox_index_record_lookup(struct dbox_index *index, unsigned int file_id);

/* Try to lock a file record. Only appendable files are actually locked.
   Returns 1 if lock acquired or not needed, 0 if we failed to get a lock or
   file is unlinked, -1 if error. lock_status_r is set if 0 or 1 is returned. */
int dbox_index_try_lock_file(struct dbox_index *index, unsigned int file_id,
			     enum dbox_index_file_lock_status *lock_status_r);
void dbox_index_unlock_file(struct dbox_index *index, unsigned int file_id);

/* Try to lock index file for recreating. Returns 1 if ok, 0 if file already
   contains locks, -1 if error. */
int dbox_index_try_lock_recreate(struct dbox_index *index);

struct dbox_index_append_context *
dbox_index_append_begin(struct dbox_index *index);
/* Request file for saving a new message with given size. If an existing file
   can be used, the record is locked and updated in index. Returns 0 if ok,
   -1 if error. */
int dbox_index_append_next(struct dbox_index_append_context *ctx,
			   uoff_t mail_size,
			   struct dbox_file **file_r,
			   struct ostream **output_r);
void dbox_index_append_file(struct dbox_index_append_context *ctx,
			    struct dbox_file *file);
/* Assign file_ids to all appended files. */
int dbox_index_append_assign_file_ids(struct dbox_index_append_context *ctx);
/* Returns 0 if ok, -1 if error. */
int dbox_index_append_commit(struct dbox_index_append_context **ctx);
void dbox_index_append_rollback(struct dbox_index_append_context **ctx);

/* Mark  */
void dbox_index_mark_expunges(struct dbox_index *index, unsigned int file_id);
void dbox_index_mark_dirty(struct dbox_index *index, unsigned int file_id);

#endif
