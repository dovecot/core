#ifndef __MAIL_INDEX_H
#define __MAIL_INDEX_H

#include "byteorder.h"
#include "file-dotlock.h"
#include "message-parser.h"
#include "imap-util.h"

#define MAIL_INDEX_MAJOR_VERSION 3
#define MAIL_INDEX_MINOR_VERSION 0

#define INDEX_FILE_PREFIX ".imap.index"

enum mail_index_open_flags {
	/* Create index if it doesn't exist */
	MAIL_INDEX_OPEN_FLAG_CREATE		= 0x01,
	/* Update \Recent flag counters */
	MAIL_INDEX_OPEN_FLAG_UPDATE_RECENT	= 0x02,
	/* Compressing and cache updates are not performed */
	MAIL_INDEX_OPEN_FLAG_FAST		= 0x04,
	/* Invalidate memory maps before accessing them */
	MAIL_INDEX_OPEN_FLAG_MMAP_INVALIDATE	= 0x08,

	/* internal: we're creating the index */
	_MAIL_INDEX_OPEN_FLAG_CREATING		= 0x100
};

enum mail_index_header_flag {
	/* Rebuild flag is set while index is being rebuilt or when
	   some error is noticed in the index file. If this flag is set,
	   the index shouldn't be used before rebuilding it. */
	MAIL_INDEX_HDR_FLAG_FSCK		= NBO32_BIT0,
	MAIL_INDEX_HDR_FLAG_REBUILD		= NBO32_BIT1,
	MAIL_INDEX_HDR_FLAG_COMPRESS		= NBO32_BIT2,
	MAIL_INDEX_HDR_FLAG_COMPRESS_CACHE	= NBO32_BIT3,
	MAIL_INDEX_HDR_FLAG_DIRTY_MESSAGES	= NBO32_BIT4,
	MAIL_INDEX_HDR_FLAG_DIRTY_CUSTOMFLAGS	= NBO32_BIT5,
	MAIL_INDEX_HDR_FLAG_MAILDIR_NEW		= NBO32_BIT6
};

enum mail_index_record_flag {
	/* If binary flags are set, it's not checked whether mail is
	   missing CRs. So this flag may be set as an optimization for
	   regular non-binary mails as well if it's known that it contains
	   valid CR+LF line breaks. */
	MAIL_INDEX_FLAG_BINARY_HEADER	= NBO32_BIT0,
	MAIL_INDEX_FLAG_BINARY_BODY	= NBO32_BIT1,

	/* Mail flags have been changed in index, but not written into
	   actual mailbox yet. */
	MAIL_INDEX_FLAG_DIRTY		= NBO32_BIT2,

	/* Maildir: Mail file is in new/ dir instead of cur/ */
	MAIL_INDEX_FLAG_MAILDIR_NEW	= NBO32_BIT3,

	/* Mail header or body is known to contain NUL characters. */
	MAIL_INDEX_FLAG_HAS_NULS	= NBO32_BIT4,
	/* Mail header or body is known to not contain NUL characters. */
	MAIL_INDEX_FLAG_HAS_NO_NULS	= NBO32_BIT5
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
	/* major version is increased only when you can't have backwards
	   compatibility. minor version is increased when header size is
	   increased to contain new non-critical fields. */
	uint8_t major_version;
	uint8_t minor_version;
	uint8_t header_size;
	uint8_t reserved;

	uint32_t indexid;

	uint32_t used_file_size;
	uint32_t sync_id; /* re-mmap() when changed, required only
	                     if file size is shrinked */

	uint32_t flags;

	uint32_t uid_validity;
	uint32_t next_uid;

	uint32_t messages_count;
	uint32_t seen_messages_count;
	uint32_t deleted_messages_count;
	uint32_t last_nonrecent_uid;

	/* these UIDs may not exist and may not even be unseen */
	uint32_t first_unseen_uid_lowwater;
	uint32_t first_deleted_uid_lowwater;

	uint32_t sync_stamp;
};

struct mail_index_record {
	uint32_t uid;
	uint32_t msg_flags;
	uint32_t cache_offset;
};

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
	   set to TRUE if any changes were noticed. If minimal_sync is TRUE,
	   we do as little as possible to get data file locked (ie. noop with
	   maildir). */
	int (*sync_and_lock)(struct mail_index *index, int minimal_sync,
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
	   lookup() and last next() call. rec must not have been expunged. */
	struct mail_index_record *(*next)(struct mail_index *index,
					  struct mail_index_record *rec);

	/* Find first existing UID in range. Sequence number is also retrieved
	   if seq_r is non-NULL. */
	struct mail_index_record *(*lookup_uid_range)(struct mail_index *index,
						      unsigned int first_uid,
						      unsigned int last_uid,
						      unsigned int *seq_r);

	/* Open mail file and return it as mmap()ed IStream. If we fail,
	   we return NULL and set deleted = TRUE if failure was because the
	   mail was just deleted (ie. not an error). received_date is set
	   if it's non-NULL. */
	struct istream *(*open_mail)(struct mail_index *index,
				     struct mail_index_record *rec,
				     time_t *received_date, int *deleted);

	/* Returns received date of message, or (time_t)-1 if error occured. */
	time_t (*get_received_date)(struct mail_index *index,
				    struct mail_index_record *rec);

	/* Expunge mails from index. Modifylog is also updated. The
	   index must be exclusively locked before calling this function.

	   first_rec+1 .. last_rec-1 range may contain already expunged
	   records.

	   Note that all record pointers are invalidated after this call as
	   expunging may radically modify the file. */
	int (*expunge)(struct mail_index *index,
		       struct mail_index_record *first_rec,
		       struct mail_index_record *last_rec,
		       unsigned int first_seq, unsigned int last_seq,
		       int external_change);

	/* Update mail flags. The index must be exclusively locked before
	   calling this function. */
	int (*update_flags)(struct mail_index *index,
			    struct mail_index_record *rec, unsigned int seq,
			    enum modify_type modify_type, enum mail_flags flags,
			    int external_change);

	/* Append a new record to index. The index must be exclusively
	   locked before calling this function. */
	struct mail_index_record *(*append)(struct mail_index *index);

	/* Returns the last error code. */
	enum mail_index_error (*get_last_error)(struct mail_index *index);

	/* Returns the full error message for last error. This message may
	   contain paths etc. so it shouldn't be shown to users. */
	const char *(*get_last_error_text)(struct mail_index *index);

/* private: */
	struct mail_cache *cache;
	struct mail_modify_log *modifylog;
	struct mail_custom_flags *custom_flags;

	char *dir; /* directory where to place the index files */
	char *filepath; /* index file path */
	char *mailbox_path; /* file/directory for mailbox location */
	char *control_dir; /* destination for control files */
	unsigned int indexid;
	unsigned int sync_id;

        /* updated whenever exclusive lock is set/unset */
	unsigned int excl_lock_counter;
	/* updated whenever expunge() is called */
	unsigned int expunge_counter;

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
	time_t last_new_mtime, last_uidlist_mtime;
	int maildir_lock_fd;
	pool_t new_filename_pool;
	struct hash_table *new_filenames;

	int fd; /* opened index file */
	char *error; /* last error message */

	void *mmap_base;
	size_t mmap_used_length;
	size_t mmap_full_length;

	struct mail_index_header *header;
	size_t header_size;

        enum mail_lock_type lock_type;
	time_t sync_stamp, sync_dirty_stamp;
	time_t next_dirty_flags_flush;
	unsigned int first_recent_uid;

	mail_lock_notify_callback_t *lock_notify_cb;
	void *lock_notify_context;

	/* these fields are OR'ed to the fields in index header once we
	   get around grabbing exclusive lock */
	unsigned int set_flags;
	unsigned int cache_later_locks;

	unsigned int anon_mmap:1;
	unsigned int mmap_invalidate:1;
	unsigned int opened:1;
	unsigned int rebuilding:1;
	unsigned int mail_read_mmaped:1;
	unsigned int inconsistent:1;
	unsigned int nodiskspace:1;
	unsigned int index_lock_timeout:1;
	unsigned int allow_new_custom_flags:1;
	unsigned int mailbox_readonly:1;
	unsigned int mailbox_lock_timeout:1;
	unsigned int maildir_keep_new:1;
	unsigned int maildir_have_new:1;
	unsigned int maildir_synced_once:1;
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
	0, 0, 0, 0, { 0, 0, 0 }, 0, 0, 0, \
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, \
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, \
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, \
	0, 0, 0, 0, 0, 0, 0
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
int mail_index_expunge(struct mail_index *index,
		       struct mail_index_record *first_rec,
		       struct mail_index_record *last_rec,
		       unsigned int first_seq, unsigned int last_seq,
		       int external_change);
int mail_index_update_flags(struct mail_index *index,
			    struct mail_index_record *rec, unsigned int seq,
			    enum modify_type modify_type, enum mail_flags flags,
			    int external_change);
struct mail_index_record *mail_index_append(struct mail_index *index);
enum mail_index_error mail_index_get_last_error(struct mail_index *index);
const char *mail_index_get_last_error_text(struct mail_index *index);

/* INTERNAL: */
void mail_index_init(struct mail_index *index, const char *dir);
int mail_index_mmap_update(struct mail_index *index);
void mail_index_init_header(struct mail_index_header *hdr);
void mail_index_close(struct mail_index *index);
int mail_index_fmdatasync(struct mail_index *index, size_t size);
void mail_index_mark_flag_changes(struct mail_index *index,
				  struct mail_index_record *rec,
				  enum mail_flags old_flags,
				  enum mail_flags new_flags);
int mail_index_rebuild(struct mail_index *index);
int mail_index_compress(struct mail_index *index);
int mail_index_truncate(struct mail_index *index);
int mail_index_expunge_record_range(struct mail_index *index,
				    struct mail_index_record *first_rec,
				    struct mail_index_record *last_rec);

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
/* Compress the file when searching deleted records tree has to go this deep */
#define INDEX_COMPRESS_DEPTH 10

/* uoff_t to index file for given record */
#define INDEX_FILE_POSITION(index, ptr) \
	((uoff_t) ((char *) (ptr) - (char *) ((index)->mmap_base)))

/* record for given index */
#define INDEX_RECORD_AT(index, idx) \
	((struct mail_index_record *) \
	 ((char *) index->mmap_base + (index)->header_size) + (idx))

/* returns the next record after last one */
#define INDEX_END_RECORD(index) \
	((struct mail_index_record *) \
	 ((char *) (index)->mmap_base + (index)->mmap_used_length))

/* index number for uoff_t position */
#define INDEX_POSITION_INDEX(index, pos) \
	(((pos) - (index)->header_size) / \
	 sizeof(struct mail_index_record))

/* index number for given record */
#define INDEX_RECORD_INDEX(index, ptr) \
	INDEX_POSITION_INDEX(index, INDEX_FILE_POSITION(index, ptr))

/* mark the index corrupted */
#define INDEX_MARK_CORRUPTED(index) \
	STMT_START { \
		(index)->set_flags |= MAIL_INDEX_HDR_FLAG_REBUILD; \
	} STMT_END

/* get number of records in mmaped index */
#define MAIL_INDEX_RECORD_COUNT(index) \
	((index->mmap_used_length - (index)->header_size) / \
	 sizeof(struct mail_index_record))

/* minimum size for index file */
#define INDEX_FILE_MIN_SIZE(index) \
	((index)->header_size + \
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
