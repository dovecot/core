#ifndef __MAIL_INDEX_H
#define __MAIL_INDEX_H

#include "file-dotlock.h"
#include "message-parser.h"
#include "imap-util.h"

#define MAIL_INDEX_VERSION 2

#define INDEX_FILE_PREFIX ".imap.index"

enum mail_index_open_flags {
	/* Create index if it doesn't exist */
	MAIL_INDEX_OPEN_FLAG_CREATE		= 0x01,
	/* Update \Recent flag counters */
	MAIL_INDEX_OPEN_FLAG_UPDATE_RECENT	= 0x02,
	/* Compressing and cache updates are not performed */
	MAIL_INDEX_OPEN_FLAG_FAST		= 0x04,

	/* internal: we're creating the index */
	_MAIL_INDEX_OPEN_FLAG_CREATING		= 0x10
};

enum mail_index_header_compat {
	MAIL_INDEX_COMPAT_LITTLE_ENDIAN	= 0x01
};

enum mail_index_header_flag {
	/* Rebuild flag is set while index is being rebuilt or when
	   some error is noticed in the index file. If this flag is set,
	   the index shouldn't be used before rebuilding it. */
	MAIL_INDEX_FLAG_REBUILD			= 0x01,
	MAIL_INDEX_FLAG_FSCK			= 0x02,
	MAIL_INDEX_FLAG_CACHE_FIELDS		= 0x04,
	MAIL_INDEX_FLAG_COMPRESS		= 0x08,
	MAIL_INDEX_FLAG_COMPRESS_DATA		= 0x10,
	MAIL_INDEX_FLAG_REBUILD_TREE		= 0x20,
	MAIL_INDEX_FLAG_DIRTY_MESSAGES		= 0x40,
	MAIL_INDEX_FLAG_DIRTY_CUSTOMFLAGS	= 0x80
};

enum mail_data_field {
	DATA_FIELD_LOCATION		= 0x00000001,
	DATA_FIELD_ENVELOPE		= 0x00000002,
	DATA_FIELD_BODY			= 0x00000004,
	DATA_FIELD_BODYSTRUCTURE	= 0x00000008,
	DATA_FIELD_MD5			= 0x00000010,
	DATA_FIELD_MESSAGEPART		= 0x00000020,

	DATA_FIELD_LAST			= 0x00000040,
	DATA_FIELD_MAX_BITS		= 6,

	/* separate from above, but in same bitmask */
	DATA_HDR_INTERNAL_DATE		= 0x40000000,
	DATA_HDR_VIRTUAL_SIZE		= 0x20000000,
	DATA_HDR_HEADER_SIZE		= 0x10000000,
	DATA_HDR_BODY_SIZE		= 0x08000000
};

#define IS_BODYSTRUCTURE_FIELD(field) \
	(((field) & (DATA_FIELD_BODY | DATA_FIELD_BODYSTRUCTURE | \
		     DATA_FIELD_MESSAGEPART)) != 0)

enum mail_index_mail_flag {
	/* If binary flags are set, it's not checked whether mail is
	   missing CRs. So this flag may be set as an optimization for
	   regular non-binary mails as well if it's known that it contains
	   valid CR+LF line breaks. */
	INDEX_MAIL_FLAG_BINARY_HEADER	= 0x0001,
	INDEX_MAIL_FLAG_BINARY_BODY	= 0x0002,

	/* Currently this means with mbox format that message flags have
	   been changed in index, but not written into mbox file yet. */
	INDEX_MAIL_FLAG_DIRTY		= 0x0004
};

enum mail_lock_type {
	MAIL_LOCK_UNLOCK = 0,
	MAIL_LOCK_SHARED,
	MAIL_LOCK_EXCLUSIVE
};

enum mail_lock_notify_type {
	/* Mailbox is locked, will abort in secs_left */
	MAIL_LOCK_NOTIFY_MAILBOX_ABORT,
	/* Mailbox lock looks stale, will override in secs_left */
	MAIL_LOCK_NOTIFY_MAILBOX_OVERRIDE,
	/* Index is locked, will abort in secs_left */
	MAIL_LOCK_NOTIFY_INDEX_ABORT
};

enum mail_index_error {
	/* No errors */
	MAIL_INDEX_ERROR_NONE,
	/* Internal error, see get_error_text() for more information. */
	MAIL_INDEX_ERROR_INTERNAL,
	/* Index is now in inconsistent state with the previous known state,
	   meaning that the message IDs etc. may have changed - only way to
	   recover this would be to fully close the mailbox and reopen it.
	   With IMAP this would mean a forced disconnection since we can't do
	   forced CLOSE. */
	MAIL_INDEX_ERROR_INCONSISTENT,
	/* We ran out of available disk space. */
	MAIL_INDEX_ERROR_DISKSPACE,
	/* Mail index locking timeouted */
	MAIL_INDEX_ERROR_INDEX_LOCK_TIMEOUT,
	/* Mailbox locking timeouted */
	MAIL_INDEX_ERROR_MAILBOX_LOCK_TIMEOUT
};

typedef void mail_lock_notify_callback_t(enum mail_lock_notify_type notify_type,
					 unsigned int secs_left, void *context);

struct mail_index_header {
	unsigned char compat_data[8];
	/* 0 = version
	   1 = flags,
	   2 = sizeof(unsigned int),
	   3 = sizeof(time_t),
	   4 = sizeof(uoff_t),
	   5 = INDEX_ALIGN_SIZE */

	unsigned int indexid;
	unsigned int sync_id; /* re-mmap() when changed, required only
	                         if file size is changed */

	unsigned int flags;
	unsigned int cache_fields;

	uoff_t used_file_size;

	unsigned int first_hole_index;
	unsigned int first_hole_records;

	unsigned int uid_validity;
	unsigned int next_uid;

	unsigned int messages_count;
	unsigned int seen_messages_count;
	unsigned int deleted_messages_count;
	unsigned int last_nonrecent_uid;

	/* these UIDs may not exist and may not even be unseen */
	unsigned int first_unseen_uid_lowwater;
	unsigned int first_deleted_uid_lowwater;
};

struct mail_index_data_header {
	unsigned int indexid;
	unsigned int reserved; /* for alignment mostly */

	uoff_t used_file_size;
	uoff_t deleted_space;
};

struct mail_index_record {
	unsigned int uid;
	unsigned int msg_flags; /* enum mail_flags */

	unsigned int index_flags; /* enum mail_index_mail_flag */
	unsigned int data_fields; /* enum mail_data_field */

	uoff_t data_position;
};

struct mail_index_data_record_header {
	unsigned int data_size; /* including this header */

	time_t internal_date;
	uoff_t virtual_size;

	uoff_t header_size;
	uoff_t body_size;
};

struct mail_index_data_record {
	unsigned int field; /* enum mail_data_field */
	unsigned int full_field_size;
	char data[INDEX_ALIGN_SIZE]; /* variable size */
};

#define SIZEOF_MAIL_INDEX_DATA \
	(sizeof(struct mail_index_data_record) - INDEX_ALIGN_SIZE)

#define DATA_RECORD_SIZE(rec) \
        (SIZEOF_MAIL_INDEX_DATA + (rec)->full_field_size)

struct mail_index {
	/* Note that opening same index twice in the same process is a bad
	   idea since they share the same file locks. As soon one of the
	   indexes is closed, the locks in second index are dropped which
	   especially hurts modify log since it keeps locks all the time. */
	int (*open)(struct mail_index *index, enum mail_index_open_flags flags);

	/* Free index from memory. */
	void (*free)(struct mail_index *index);

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
	   sure that won't create race conditions. */
	int (*set_lock)(struct mail_index *index,
			enum mail_lock_type lock_type);

	/* Try locking the index. Returns TRUE if the lock was got and
	   FALSE if lock isn't possible to get currently or some other error
	   occured. Never blocks. */
	int (*try_lock)(struct mail_index *index,
			enum mail_lock_type lock_type);

	/* If we have to wait for the lock, the given lock notify function
	   is called once in a while. */
	void (*set_lock_notify_callback)(struct mail_index *index,
					 mail_lock_notify_callback_t *callback,
					 void *context);

	/* Rebuild the whole index. Note that this changes the indexid
	   so all the other files must also be rebuilt after this call.
	   Index MUST NOT have shared lock, but exclusive lock or no lock at
	   all is fine. Note that this function may leave the index
	   exclusively locked, and always sets index->inconsistent = TRUE. */
	int (*rebuild)(struct mail_index *index);

	/* Verify that the index is valid. If anything invalid is found,
	   index is set inconsistent and to be rebuilt at next open.
	   Same locking issues as with rebuild(). */
	int (*fsck)(struct mail_index *index);

	/* Synchronize the index with the mailbox. Index must not have shared
	   lock when calling this function. The data_lock_type specifies what
	   lock should be set to data file (mbox file). This function may
	   leave the index in ANY locking state. If changes is non-NULL, it's
	   set to TRUE if any changes were noticed. */
	int (*sync_and_lock)(struct mail_index *index,
			     enum mail_lock_type data_lock_type, int *changes);

	/* Returns the index header (never fails). The index needs to be
	   locked before calling this function, and must be kept locked as
	   long as you keep using the returned structure. */
	struct mail_index_header *(*get_header)(struct mail_index *index);

	/* sequence -> data lookup. The index needs to be locked before calling
	   this function, and must be kept locked as long as you keep using
	   the returned structure. */
	struct mail_index_record *(*lookup)(struct mail_index *index,
					    unsigned int seq);

	/* Return the next record after specified record, or NULL if it was
	   last record. The index must be locked all the time between
	   lookup() and last next() call. */
	struct mail_index_record *(*next)(struct mail_index *index,
					  struct mail_index_record *rec);

	/* Find first existing UID in range. Sequence number is also retrieved
	   if seq_r is non-NULL. */
	struct mail_index_record *(*lookup_uid_range)(struct mail_index *index,
						      unsigned int first_uid,
						      unsigned int last_uid,
						      unsigned int *seq_r);

	/* Find field from specified record, or NULL if it's not in index.
	   Makes sure that the field ends with \0. */
	const char *(*lookup_field)(struct mail_index *index,
				    struct mail_index_record *rec,
				    enum mail_data_field field);

	/* Find field from specified record, or NULL if it's not in index. */
	const void *(*lookup_field_raw)(struct mail_index *index,
					struct mail_index_record *rec,
					enum mail_data_field field,
					size_t *size);

	/* Mark the fields to be cached later. If any of them is already
	   set in hdr->cache_fields, mark the caching to happen next time
	   index is opened. */
	void (*cache_fields_later)(struct mail_index *index,
				   enum mail_data_field field);

	/* Open mail file and return it as mmap()ed IStream. If we fail,
	   we return NULL and set deleted = TRUE if failure was because the
	   mail was just deleted (ie. not an error). internal_date is set
	   if it's non-NULL. */
	struct istream *(*open_mail)(struct mail_index *index,
				     struct mail_index_record *rec,
				     time_t *internal_date, int *deleted);

	/* Returns internal date of message, or (time_t)-1 if error occured. */
	time_t (*get_internal_date)(struct mail_index *index,
				    struct mail_index_record *rec);

	/* Expunge a mail from index. Tree and modifylog is also updated. The
	   index must be exclusively locked before calling this function.
	   If seq is 0, the modify log isn't updated. This is useful if
	   after append() something goes wrong and you wish to delete the
	   mail immediately. If external_change is TRUE, the modify log is
	   always written.

	   Note that the sequence numbers also update immediately after this
	   call, so if you want to delete messages 1..4 just call this
	   function 4 times with seq being 1. */
	int (*expunge)(struct mail_index *index, struct mail_index_record *rec,
		       unsigned int seq, int external_change);

	/* Update mail flags. The index must be exclusively locked before
	   calling this function. This shouldn't be called in the middle of
	   update_begin() as it may modify location field. */
	int (*update_flags)(struct mail_index *index,
			    struct mail_index_record *rec,
			    unsigned int seq, enum mail_flags flags,
			    int external_change);

	/* Append a new record to index. The index must be exclusively
	   locked before calling this function. rec->uid is updated in
	   append_end(). */
	struct mail_index_record *(*append_begin)(struct mail_index *index);
	int (*append_end)(struct mail_index *index,
			  struct mail_index_record *rec);
	void (*append_abort)(struct mail_index *index,
			     struct mail_index_record *rec);

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
	struct mail_index_update *
		(*update_begin)(struct mail_index *index,
				struct mail_index_record *rec);
	int (*update_end)(struct mail_index_update *update);
	void (*update_abort)(struct mail_index_update *update);

	void (*update_field)(struct mail_index_update *update,
			     enum mail_data_field field,
			     const char *value, size_t extra_space);
	/* Just remember that full_field_size will be INDEX_ALIGNed, so
	   it may differer from the given size parameter. */
	void (*update_field_raw)(struct mail_index_update *update,
				 enum mail_data_field field,
				 const void *value, size_t size);

	/* Returns the last error code. */
	enum mail_index_error (*get_last_error)(struct mail_index *index);

	/* Returns the full error message for last error. This message may
	   contain paths etc. so it shouldn't be shown to users. */
	const char *(*get_last_error_text)(struct mail_index *index);

/* private: */
	struct mail_index_data *data;
	struct mail_tree *tree;
	struct mail_modify_log *modifylog;
	struct mail_custom_flags *custom_flags;

	char *dir; /* directory where to place the index files */
	char *filepath; /* index file path */
	char *mailbox_path; /* file/directory for mailbox location */
	char *custom_flags_dir; /* destination for .customflags file */
	enum mail_data_field default_cache_fields, never_cache_fields;
	unsigned int indexid;
	unsigned int sync_id;

        /* updated whenever exclusive lock is set/unset */
	unsigned int excl_lock_counter;

	int mbox_fd;
	struct istream *mbox_stream;
	enum mail_lock_type mbox_lock_type;
	struct dotlock mbox_dotlock;

	/* these counters can be used to check that we've synced the mailbox
	   after locking it */
	unsigned int mbox_lock_counter;
	unsigned int mbox_sync_counter;

	/* last mbox sync: */
	uoff_t mbox_size;
	dev_t mbox_dev;
	ino_t mbox_ino;

	/* last maildir sync: */
	time_t uidlist_mtime;
	int maildir_lock_fd;

	int fd; /* opened index file */
	char *error; /* last error message */

	void *mmap_base;
	size_t mmap_used_length;
	size_t mmap_full_length;

	struct mail_index_header *header;

        enum mail_lock_type lock_type;
	time_t file_sync_stamp;
	unsigned int first_recent_uid;

	mail_lock_notify_callback_t *lock_notify_cb;
	void *lock_notify_context;

	/* these fields are OR'ed to the fields in index header once we
	   get around grabbing exclusive lock */
	unsigned int set_flags;
	enum mail_data_field set_cache_fields;

	unsigned int anon_mmap:1;
	unsigned int opened:1;
	unsigned int rebuilding:1;
	unsigned int mail_read_mmaped:1;
	unsigned int inconsistent:1;
	unsigned int nodiskspace:1;
	unsigned int index_lock_timeout:1;
	unsigned int allow_new_custom_flags:1;
	unsigned int mailbox_readonly:1;
	unsigned int mailbox_lock_timeout:1;
};

#ifdef DEV_T_STRUCT
/* we can't initialize dev_t as 0, and we don't know what it actually
   contains, so don't initialize them. gcc's -W option should be disabled
   with this or we get warnings.. */
#  define MAIL_INDEX_PRIVATE_FILL 0
#else
/* needed to remove annoying warnings about not initializing all struct
   members.. */
#define MAIL_INDEX_PRIVATE_FILL \
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, \
	0, 0, 0, 0, 0, 0, { 0, 0, 0 }, 0, 0, \
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, \
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, \
	0, 0, 0, 0, 0, 0, 0, 0
#endif

/* defaults - same as above but prefixed with mail_index_. */
int mail_index_open(struct mail_index *index, enum mail_index_open_flags flags);
int mail_index_set_lock(struct mail_index *index,
			enum mail_lock_type lock_type);
int mail_index_try_lock(struct mail_index *index,
			enum mail_lock_type lock_type);
void mail_index_set_lock_notify_callback(struct mail_index *index,
					 mail_lock_notify_callback_t *callback,
					 void *context);
int mail_index_fsck(struct mail_index *index);
struct mail_index_header *mail_index_get_header(struct mail_index *index);
struct mail_index_record *mail_index_lookup(struct mail_index *index,
					    unsigned int seq);
struct mail_index_record *mail_index_next(struct mail_index *index,
					  struct mail_index_record *rec);
struct mail_index_record *
mail_index_lookup_uid_range(struct mail_index *index, unsigned int first_uid,
			    unsigned int last_uid, unsigned int *seq_r);
const char *mail_index_lookup_field(struct mail_index *index,
				    struct mail_index_record *rec,
				    enum mail_data_field field);
const void *mail_index_lookup_field_raw(struct mail_index *index,
					struct mail_index_record *rec,
					enum mail_data_field field,
					size_t *size);
void mail_index_cache_fields_later(struct mail_index *index,
				   enum mail_data_field field);
int mail_index_expunge(struct mail_index *index, struct mail_index_record *rec,
		       unsigned int seq, int external_change);
int mail_index_update_flags(struct mail_index *index,
			    struct mail_index_record *rec,
			    unsigned int seq, enum mail_flags flags,
			    int external_change);
struct mail_index_record *mail_index_append_begin(struct mail_index *index);
int mail_index_append_end(struct mail_index *index,
			  struct mail_index_record *rec);
void mail_index_append_abort(struct mail_index *index,
			     struct mail_index_record *rec);
struct mail_index_update *
mail_index_update_begin(struct mail_index *index,
			struct mail_index_record *rec);
int mail_index_update_end(struct mail_index_update *update);
void mail_index_update_abort(struct mail_index_update *update);
void mail_index_update_field(struct mail_index_update *update,
			     enum mail_data_field field,
			     const char *value, size_t extra_space);
void mail_index_update_field_raw(struct mail_index_update *update,
				 enum mail_data_field field,
				 const void *value, size_t size);
time_t mail_get_internal_date(struct mail_index *index,
			      struct mail_index_record *rec);
enum mail_index_error mail_index_get_last_error(struct mail_index *index);
const char *mail_index_get_last_error_text(struct mail_index *index);

/* INTERNAL: */
void mail_index_init(struct mail_index *index, const char *dir);
int mail_index_mmap_update(struct mail_index *index);
void mail_index_init_header(struct mail_index *index,
			    struct mail_index_header *hdr);
void mail_index_close(struct mail_index *index);
int mail_index_fmdatasync(struct mail_index *index, size_t size);
int mail_index_verify_hole_range(struct mail_index *index);
void mail_index_mark_flag_changes(struct mail_index *index,
				  struct mail_index_record *rec,
				  enum mail_flags old_flags,
				  enum mail_flags new_flags);
void mail_index_update_headers(struct mail_index_update *update,
			       struct istream *input,
                               enum mail_data_field cache_fields,
			       message_header_callback_t *header_cb,
			       void *context);
int mail_index_update_cache(struct mail_index *index);
int mail_index_compress(struct mail_index *index);
int mail_index_compress_data(struct mail_index *index);
int mail_index_truncate(struct mail_index *index);

/* Maximum allowed UID number. */
#define MAX_ALLOWED_UID 4294967295U /* 2^32 - 1 */

/* Max. mmap()ed size for a message */
#define MAIL_MMAP_BLOCK_SIZE (1024*256)
/* Block size when read()ing message. */
#define MAIL_READ_BLOCK_SIZE (1024*8)

/* Delete unused non-local temp files after 24h. Just to be sure we don't
   delete it too early. The temp files don't harm much anyway. */
#define TEMP_FILE_TIMEOUT (60*24)

/* number of records to always keep allocated in index file,
   either used or unused */
#define INDEX_MIN_RECORDS_COUNT 64
/* when empty space in index file gets full, grow the file n% larger */
#define INDEX_GROW_PERCENTAGE 10
/* ftruncate() the index file when only n% of it is in use */
#define INDEX_TRUNCATE_PERCENTAGE 30
/* don't truncate whole file anyway, keep n% of the empty space */
#define INDEX_TRUNCATE_KEEP_PERCENTAGE 10
/* Compress the file when deleted space reaches n% of total size */
#define INDEX_COMPRESS_PERCENTAGE 50

/* uoff_t to index file for given record */
#define INDEX_FILE_POSITION(index, ptr) \
	((uoff_t) ((char *) (ptr) - (char *) ((index)->mmap_base)))

/* record for given index */
#define INDEX_RECORD_AT(index, idx) \
	((struct mail_index_record *) \
	 ((char *) index->mmap_base + sizeof(struct mail_index_header)) + (idx))

/* returns the next record after last one */
#define INDEX_END_RECORD(index) \
	((struct mail_index_record *) \
	 ((char *) (index)->mmap_base + (index)->mmap_used_length))

/* index number for uoff_t position */
#define INDEX_POSITION_INDEX(pos) \
	(((pos) - sizeof(struct mail_index_header)) / \
	 sizeof(struct mail_index_record))

/* index number for given record */
#define INDEX_RECORD_INDEX(index, ptr) \
	INDEX_POSITION_INDEX(INDEX_FILE_POSITION(index, ptr))

/* mark the index corrupted */
#define INDEX_MARK_CORRUPTED(index) \
	STMT_START { (index)->set_flags |= MAIL_INDEX_FLAG_REBUILD; } STMT_END

/* get number of records in mmaped index */
#define MAIL_INDEX_RECORD_COUNT(index) \
	((index->mmap_used_length - sizeof(struct mail_index_header)) / \
	 sizeof(struct mail_index_record))

/* minimum size for index file */
#define INDEX_FILE_MIN_SIZE \
	(sizeof(struct mail_index_header) + \
	 INDEX_MIN_RECORDS_COUNT * sizeof(struct mail_index_record))

/* enum mail_lock_type to fcntl() lock type */
#define MAIL_LOCK_TO_FLOCK(lock_type) \
        ((lock_type) == MAIL_LOCK_EXCLUSIVE ? F_WRLCK : \
		(lock_type) == MAIL_LOCK_SHARED ? F_RDLCK : F_UNLCK)

#define INDEX_IS_IN_MEMORY(index) \
	((index)->anon_mmap)

/* Returns alignmentation for given size */
#define INDEX_ALIGN(size) \
	(((size) + INDEX_ALIGN_SIZE-1) & ~((unsigned int) INDEX_ALIGN_SIZE-1))

#endif
