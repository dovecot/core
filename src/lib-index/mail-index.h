#ifndef __MAIL_INDEX_H
#define __MAIL_INDEX_H

#include "message-parser.h"
#include "imap-util.h"

#define MAIL_INDEX_VERSION 1

#define INDEX_FILE_PREFIX ".imap.index"

enum {
	MAIL_INDEX_COMPAT_LITTLE_ENDIAN	= 0x01
};

enum {
	/* Rebuild flag is set while index is being rebuilt or when
	   some error is noticed in the index file. If this flag is set,
	   the index shouldn't be used before rebuilding it. */
	MAIL_INDEX_FLAG_REBUILD		= 0x01,
	MAIL_INDEX_FLAG_FSCK		= 0x02,
	MAIL_INDEX_FLAG_CACHE_FIELDS	= 0x04,
	MAIL_INDEX_FLAG_COMPRESS	= 0x08,
	MAIL_INDEX_FLAG_COMPRESS_DATA	= 0x10,
	MAIL_INDEX_FLAG_REBUILD_HASH	= 0x20
};

typedef enum {
	/* First MUST become a field that ALWAYS exists. This is because some
	   code which goes through all fields does it by calling
	   lookup_field(.., .., 1) and next() after that. If the first field
	   didn't exist, nothing would be found.

	   Location field is a good first field anyway, it's the one most
	   often needed. With maildir format, it's the file name and with
	   mbox format it's the file position as a string. */
	FIELD_TYPE_LOCATION		= 0x0001,
	FIELD_TYPE_ENVELOPE		= 0x0002,
	FIELD_TYPE_BODY			= 0x0004,
	FIELD_TYPE_BODYSTRUCTURE	= 0x0008,
	FIELD_TYPE_FROM			= 0x0010,
	FIELD_TYPE_TO			= 0x0020,
	FIELD_TYPE_CC			= 0x0040,
	FIELD_TYPE_BCC			= 0x0080,
	FIELD_TYPE_SUBJECT		= 0x0100,
	FIELD_TYPE_MD5			= 0x0200,

	FIELD_TYPE_LAST			= 0x0400,
	FIELD_TYPE_MAX_BITS		= 10
} MailField;

#define IS_HEADER_FIELD(field) \
	(((field) & (FIELD_TYPE_FROM | FIELD_TYPE_TO | FIELD_TYPE_CC | \
		     FIELD_TYPE_BCC | FIELD_TYPE_SUBJECT)) != 0)

typedef enum {
	MAIL_LOCK_UNLOCK = 0,
	MAIL_LOCK_SHARED,
	MAIL_LOCK_EXCLUSIVE
} MailLockType;

typedef struct _MailIndex MailIndex;
typedef struct _MailIndexData MailIndexData;
typedef struct _MailHash MailHash;
typedef struct _MailModifyLog MailModifyLog;

typedef struct _MailIndexHeader MailIndexHeader;
typedef struct _MailIndexDataHeader MailIndexDataHeader;

typedef struct _MailIndexRecord MailIndexRecord;
typedef struct _MailIndexDataRecord MailIndexDataRecord;

typedef struct _MailIndexUpdate MailIndexUpdate;

struct _MailIndexHeader {
	unsigned char compat_data[8];
	/* 0 = version
	   1 = flags,
	   2 = sizeof(unsigned int),
	   3 = sizeof(time_t),
	   4 = sizeof(uoff_t) */

	unsigned int indexid;
	unsigned int flags;

	uoff_t first_hole_position;
	unsigned int first_hole_records;

	unsigned int cache_fields;

	unsigned int uid_validity;
	unsigned int next_uid;

	unsigned int messages_count;
	unsigned int seen_messages_count;
	unsigned int deleted_messages_count;
	unsigned int last_nonrecent_uid;

	/* these UIDs may not exist and may not even be unseen */
	unsigned int first_unseen_uid_lowwater;
	unsigned int first_deleted_uid_lowwater;

	unsigned int reserved_for_future_usage[5];
};

struct _MailIndexDataHeader {
	unsigned int indexid;
	unsigned int reserved; /* for alignment mostly */

	uoff_t deleted_space;
};

struct _MailIndexRecord {
	/* remember to keep uoff_t's 8 byte aligned so we don't waste space */
	unsigned int uid;
	unsigned int msg_flags; /* MailFlags */
	time_t internal_date;
	time_t sent_date;

	uoff_t data_position;
	unsigned int data_size;

	unsigned int cached_fields;
	uoff_t header_size;
	uoff_t body_size;
	uoff_t full_virtual_size;
};

#define MSG_HAS_VALID_CRLF_DATA(rec) \
	((rec)->header_size + (rec)->body_size == (rec)->full_virtual_size)

struct _MailIndexDataRecord {
	unsigned int field; /* MailField */
	unsigned int full_field_size;
	char data[MEM_ALIGN_SIZE]; /* variable size */
};

#define SIZEOF_MAIL_INDEX_DATA \
	(sizeof(MailIndexDataRecord) - MEM_ALIGN_SIZE)

#define DATA_RECORD_SIZE(rec) \
        (SIZEOF_MAIL_INDEX_DATA + (rec)->full_field_size)

struct _MailIndex {
	int (*open)(MailIndex *index, int update_recent);
	int (*open_or_create)(MailIndex *index, int update_recent);

	/* Free index from memory. */
	void (*free)(MailIndex *index);

	/* Lock/unlock index. May block. Note that unlocking must not
	   reset error from get_last_error() as unlocking can be done as
	   a cleanup after some other function failed. Index is always
	   mmap()ed after set_lock() succeeds.

	   Trying to change a shared lock into exclusive lock is a fatal
	   error, since it may create a deadlock. Even though operating
	   system should detect it and fail, it's not a good idea to even
	   let it happen. Better ways to do this would be to a) mark the
	   data to be updated later, b) use try_lock() if the update is
	   preferred but not required, c) unlock + lock again, but make
	   sure that won't create race conditions */
	int (*set_lock)(MailIndex *index, MailLockType lock_type);

	/* Try locking the index. Returns TRUE if the lock was got and
	   FALSE if lock isn't possible to get currently or some other error
	   occured. Never blocks. */
	int (*try_lock)(MailIndex *index, MailLockType lock_type);

	/* Rebuild the whole index. Note that this changes the indexid
	   so all the other files must also be rebuilt after this call.
	   Index MUST NOT have shared lock, exclusive lock or no lock at all
	   is fine. Note that this function may leave the index exclusively
	   locked. */
	int (*rebuild)(MailIndex *index);

	/* Verify that the index is valid. If anything invalid is found,
	   rebuild() is called. Same locking issues as with rebuild(). */
	int (*fsck)(MailIndex *index);

	/* Synchronize the index with the mailbox. Same locking issues as
	   with rebuild(). */
	int (*sync)(MailIndex *index);

	/* Returns the index header (never fails). The index needs to be
	   locked before calling this function, and must be kept locked as
	   long as you keep using the returned structure. */
	MailIndexHeader *(*get_header)(MailIndex *index);

	/* sequence -> data lookup. The index needs to be locked before calling
	   this function, and must be kept locked as long as you keep using
	   the returned structure. */
	MailIndexRecord *(*lookup)(MailIndex *index, unsigned int seq);

	/* Return the next record after specified record, or NULL if it was
	   last record. The index must be locked all the time between
	   lookup() and last next() call. */
	MailIndexRecord *(*next)(MailIndex *index, MailIndexRecord *rec);

	/* First first existing UID in range. */
	MailIndexRecord *(*lookup_uid_range)(MailIndex *index,
					     unsigned int first_uid,
					     unsigned int last_uid);

	/* Find field from specified record, or NULL if it's not in index. */
	const char *(*lookup_field)(MailIndex *index, MailIndexRecord *rec,
				    MailField field);

	/* Returns sequence for given message, or 0 if failed. */
	unsigned int (*get_sequence)(MailIndex *index, MailIndexRecord *rec);

	/* Open mail file and return it as mmap()ed IOBuffer, or
	   NULL if failed. */
	IOBuffer *(*open_mail)(MailIndex *index, MailIndexRecord *rec);

	/* Expunge a mail from index. Hash and modifylog is also updated. The
	   index must be exclusively locked before calling this function.
	   If seq is 0, the modify log isn't updated. This is useful if
	   after append() something goes wrong and you wish to delete the
	   mail immediately. If external_change is TRUE, the modify log is
	   always written.

	   Note that the sequence numbers also update immediately after this
	   call, so if you want to delete messages 1..4 just call this
	   function 4 times with seq being 1. */
	int (*expunge)(MailIndex *index, MailIndexRecord *rec,
		       unsigned int seq, int external_change);

	/* Update mail flags. The index must be exclusively locked before
	   calling this function. This shouldn't be called in the middle of
	   update_begin() as it may modify location field. */
	int (*update_flags)(MailIndex *index, MailIndexRecord *rec,
			    unsigned int seq, MailFlags flags,
			    int external_change);

	/* Append a new record to index. The index must be exclusively
	   locked before calling this function. The record pointer is
	   updated to the mmap()ed record. rec->uid field is updated by this
	   function, nothing else is touched. */
	int (*append)(MailIndex *index, MailIndexRecord **rec);

	/* Updating fields happens by calling update_begin(), one or more
	   update_field()s and finally update_end() which does the actual
	   updating. The index must be exclusively locked all this time.
	   update_begin() and update_field() functions cannot fail.

	   The extra_space parameter for update_field() specifies the amount
	   of extra empty space we should leave after the value, so that if
	   the field grows in future it could be expanded without copying it
	   to end of file. When the field already exists, the extra_space
	   is ignored.

	   The files may not actually be updated until after you've unlocked
	   the file. */
	MailIndexUpdate *(*update_begin)(MailIndex *index,
					 MailIndexRecord *rec);
	int (*update_end)(MailIndexUpdate *update);

	void (*update_field)(MailIndexUpdate *update, MailField field,
			     const char *value, unsigned int extra_space);

	/* Returns last error message */
	const char *(*get_last_error)(MailIndex *index);

	/* Returns TRUE if index is now in inconsistent state with the
	   previous known state, meaning that the message IDs etc. may
	   have changed - only way to recover this would be to fully close
	   the mailbox and reopen it. With IMAP connection this would mean
	   a forced disconnection since we can't do forced CLOSE. */
	int (*is_inconsistency_error)(MailIndex *index);

/* private: */
	MailIndexData *data;
	MailHash *hash;
	MailModifyLog *modifylog;

	char *dir; /* directory where to place the index files */
	char *filepath; /* index file path */
	unsigned int indexid;

	char *mbox_path; /* mbox-specific path to the actual mbox file */
	uoff_t mbox_size; /* last synced size of mbox file */
	int mbox_locks;

	int fd; /* opened index file */
	char *error; /* last error message */

	void *mmap_base;
	size_t mmap_length;

        MailLockType lock_type;

	MailIndexHeader *header;
	MailIndexRecord *last_lookup;
	unsigned int last_lookup_seq;
	unsigned int first_recent_uid;

	unsigned int modifylog_id;
	time_t file_sync_stamp;

	/* these fields are OR'ed to the fields in index header once we
	   get around grabbing exclusive lock */
	unsigned int set_flags;
	unsigned int set_cache_fields;

	unsigned int opened:1;
	unsigned int updating:1;
	unsigned int inconsistent:1;
	unsigned int dirty_mmap:1;
};

/* needed to remove annoying warnings about not initializing all struct
   members.. */
#define MAIL_INDEX_PRIVATE_FILL \
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, \
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, \
	0, 0, 0, 0, 0, 0

/* defaults - same as above but prefixed with mail_index_. */
int mail_index_open(MailIndex *index, int update_recent);
int mail_index_open_or_create(MailIndex *index, int update_recent);
int mail_index_set_lock(MailIndex *index, MailLockType lock_type);
int mail_index_try_lock(MailIndex *index, MailLockType lock_type);
int mail_index_fsck(MailIndex *index);
MailIndexHeader *mail_index_get_header(MailIndex *index);
MailIndexRecord *mail_index_lookup(MailIndex *index, unsigned int seq);
MailIndexRecord *mail_index_next(MailIndex *index, MailIndexRecord *rec);
MailIndexRecord *mail_index_lookup_uid_range(MailIndex *index,
					     unsigned int first_uid,
					     unsigned int last_uid);
const char *mail_index_lookup_field(MailIndex *index, MailIndexRecord *rec,
				    MailField field);
unsigned int mail_index_get_sequence(MailIndex *index, MailIndexRecord *rec);
int mail_index_expunge(MailIndex *index, MailIndexRecord *rec,
		       unsigned int seq, int external_change);
int mail_index_update_flags(MailIndex *index, MailIndexRecord *rec,
			    unsigned int seq, MailFlags flags,
			    int external_change);
int mail_index_append(MailIndex *index, MailIndexRecord **rec);
MailIndexUpdate *mail_index_update_begin(MailIndex *index,
					 MailIndexRecord *rec);
int mail_index_update_end(MailIndexUpdate *update);
void mail_index_update_field(MailIndexUpdate *update, MailField field,
			     const char *value, unsigned int extra_space);
const char *mail_index_get_last_error(MailIndex *index);
int mail_index_is_inconsistency_error(MailIndex *index);

/* INTERNAL: */
void mail_index_init_header(MailIndexHeader *hdr);
void mail_index_close(MailIndex *index);
int mail_index_rebuild_all(MailIndex *index);
int mail_index_sync_file(MailIndex *index);
int mail_index_fmsync(MailIndex *index, size_t size);
int mail_index_verify_hole_range(MailIndex *index);
void mail_index_update_headers(MailIndexUpdate *update, IOBuffer *inbuf,
                               MailField cache_fields,
			       MessageHeaderFunc header_func, void *context);
int mail_index_update_cache(MailIndex *index);
int mail_index_compress(MailIndex *index);
int mail_index_compress_data(MailIndex *index);

/* Max. mmap()ed size for a message */
#define MAIL_MMAP_BLOCK_SIZE (1024*256)

/* uoff_t to index file for given record */
#define INDEX_FILE_POSITION(index, ptr) \
	((uoff_t) ((char *) (ptr) - (char *) ((index)->mmap_base)))

/* index number for uoff_t position */
#define INDEX_POSITION_INDEX(pos) \
	(((pos) - sizeof(MailIndexHeader)) / sizeof(MailIndexRecord))

/* mark the index corrupted */
#define INDEX_MARK_CORRUPTED(index) \
	STMT_START { (index)->set_flags |= MAIL_INDEX_FLAG_REBUILD; } STMT_END

/* get number of records in mmaped index */
#define MAIL_INDEX_RECORD_COUNT(index) \
	((index->mmap_length - sizeof(MailIndexHeader)) / \
	 sizeof(MailIndexRecord))

#endif
