#ifndef DBOX_FILE_H
#define DBOX_FILE_H

/* The file begins with a header followed by zero or more messages:

   <dbox message header>
   <LF>
   <message body>
   <metadata>

   Metadata block begins with DBOX_MAGIC_POST, followed by zero or more lines
   in format <key character><value><LF>. The block ends with an empty line.
   Unknown metadata should be ignored, but preserved when copying.

   There should be no duplicates for the current metadata, but future
   extensions may need them so they should be preserved.
*/
#define DBOX_VERSION 2
#define DBOX_MAGIC_PRE "\001\002"
#define DBOX_MAGIC_POST "\n\001\003\n"

enum dbox_header_key {
	/* Offset for appending next message. In %08x format so it can be
	   updated without moving data in header. If messages have been
	   expunged and file must not be appended anymore, the value is filled
	   with 'X'. */
	DBOX_HEADER_OLDV1_APPEND_OFFSET	= 'A',
	/* Must be sizeof(struct dbox_message_header) when appending (hex) */
	DBOX_HEADER_MSG_HEADER_SIZE	= 'M',
	/* Creation UNIX timestamp (hex) */
	DBOX_HEADER_CREATE_STAMP	= 'C'
};

enum dbox_metadata_key {
	/* Globally unique identifier for the message. Preserved when
	   copying. */
	DBOX_METADATA_GUID		= 'G',
	/* POP3 UIDL overriding the default format */
	DBOX_METADATA_POP3_UIDL		= 'P',
	/* Received UNIX timestamp in hex */
	DBOX_METADATA_RECEIVED_TIME	= 'R',
	/* Saved UNIX timestamp in hex */
	DBOX_METADATA_SAVE_TIME		= 'S',
	/* Virtual message size in hex (line feeds counted as CRLF) */
	DBOX_METADATA_VIRTUAL_SIZE	= 'V',
	/* Pointer to external message data. Format is:
	   1*(<start offset> <byte count> <ref>) */
	DBOX_METADATA_EXT_REF		= 'X',
	/* Mailbox name where this message was originally saved to.
	   When rebuild finds a message whose mailbox is unknown, it's
	   placed to this mailbox. */
	DBOX_METADATA_ORIG_MAILBOX	= 'B',

	/* metadata used by old Dovecot versions */
	DBOX_METADATA_OLDV1_EXPUNGED	= 'E',
	DBOX_METADATA_OLDV1_FLAGS	= 'F',
	DBOX_METADATA_OLDV1_KEYWORDS	= 'K',
	DBOX_METADATA_OLDV1_SPACE	= ' '
};

enum dbox_message_type {
	/* Normal message */
	DBOX_MESSAGE_TYPE_NORMAL	= 'N',
	/* Parts of the message exists outside the following data.
	   See the metadata for how to find them. */
	DBOX_MESSAGE_TYPE_EXT_REFS	= 'E'
};

struct dbox_message_header {
	unsigned char magic_pre[2];
	unsigned char type;
	unsigned char space1;
	unsigned char oldv1_uid_hex[8];
	unsigned char space2;
	unsigned char message_size_hex[16];
	/* <space reserved for future extensions, LF is always last> */
	unsigned char save_lf;
};

struct dbox_metadata_header {
	unsigned char magic_post[sizeof(DBOX_MAGIC_POST)-1];
};

struct dbox_file {
	struct dbox_storage *storage;
	/* set only for single-msg-per-file */
	struct dbox_mailbox *single_mbox;

	int refcount;
	/* uid is for single-msg-per-file, file_id for multi-msgs-per-file */
	uint32_t uid, file_id;

	time_t create_time;
	unsigned int file_version;
	unsigned int file_header_size;
	unsigned int msg_header_size;

	uoff_t cur_offset;
	uoff_t cur_physical_size;
	/* first appended message's offset (while appending) */
	uoff_t first_append_offset;

	char *fname;
	char *current_path;

	int fd;
	struct istream *input;
	struct ostream *output;
	struct file_lock *lock;

	/* Metadata for the currently seeked metadata block. */
	pool_t metadata_pool;
	ARRAY_DEFINE(metadata, const char *);
	uoff_t metadata_read_offset;

	unsigned int alt_path:1;
	unsigned int maildir_file:1;
	unsigned int deleted:1;
	unsigned int corrupted:1;
};

#define dbox_file_is_open(file) ((file)->input != NULL)

struct dbox_file *
dbox_file_init_single(struct dbox_mailbox *mbox, uint32_t uid);
struct dbox_file *
dbox_file_init_multi(struct dbox_storage *storage, uint32_t file_id);
void dbox_file_unref(struct dbox_file **file);

/* Free all currently opened files. */
void dbox_files_free(struct dbox_storage *storage);
/* Flush all cached input data from opened files. */
void dbox_files_sync_input(struct dbox_storage *storage);

/* Assign a newly created file a new id. For single files assign UID,
   for multi files assign map UID. */
int dbox_file_assign_id(struct dbox_file *file, uint32_t id);

/* Open the file. Returns 1 if ok, 0 if file header is corrupted, -1 if error.
   If file is deleted, deleted_r=TRUE and 1 is returned. */
int dbox_file_open(struct dbox_file *file, bool *deleted_r);
/* Open the file if uid or file_id is not 0, otherwise create it. */
int dbox_file_open_or_create(struct dbox_file *file, bool *deleted_r);
/* Close the file handle from the file, but don't free it. */
void dbox_file_close(struct dbox_file *file);

/* Try to lock the dbox file. Returns 1 if ok, 0 if already locked by someone
   else, -1 if error. */
int dbox_file_try_lock(struct dbox_file *file);
void dbox_file_unlock(struct dbox_file *file);

/* Seek to given offset in file and return the message's input stream
   and physical size. Returns 1 if ok/expunged, 0 if file/offset is corrupted,
   -1 if I/O error. */
int dbox_file_get_mail_stream(struct dbox_file *file, uoff_t offset,
			      uoff_t *physical_size_r,
			      struct istream **stream_r, bool *expunged_r);
/* Start seeking at the beginning of the file. */
void dbox_file_seek_rewind(struct dbox_file *file);
/* Seek to next message after current one. If there are no more messages,
   returns 0 and last_r is set to TRUE. Returns 1 if ok, 0 if file is
   corrupted, -1 if I/O error. */
int dbox_file_seek_next(struct dbox_file *file, uoff_t *offset_r, bool *last_r);

/* Returns TRUE if mail_size bytes can be appended to the file. */
bool dbox_file_can_append(struct dbox_file *file, uoff_t mail_size);
/* Get output stream for appending a new message. Returns 1 if ok, 0 if file
   can't be appended to (old file version or corruption) or -1 if error. */
int dbox_file_get_append_stream(struct dbox_file *file, uoff_t *append_offset_r,
				struct ostream **stream_r);
/* Returns the next offset for append a message. dbox_file_get_append_stream()
   must have been called for this file already at least once. */
uoff_t dbox_file_get_next_append_offset(struct dbox_file *file);
/* Truncate file to append_offset */
void dbox_file_cancel_append(struct dbox_file *file, uoff_t append_offset);
/* Flush writes to dbox file. */
int dbox_file_flush_append(struct dbox_file *file);

/* Read current message's metadata. Returns 1 if ok, 0 if metadata is
   corrupted, -1 if I/O error. */
int dbox_file_metadata_read(struct dbox_file *file);
/* Return wanted metadata value, or NULL if not found. */
const char *dbox_file_metadata_get(struct dbox_file *file,
				   enum dbox_metadata_key key);

/* Move the file to alt path or back. */
int dbox_file_move(struct dbox_file *file, bool alt_path);
/* Fix a broken dbox file by rename()ing over it with a fixed file. Everything
   before start_offset is assumed to be valid and is simply copied. The file
   is reopened afterwards. Returns 0 if ok, -1 if I/O error. */
int dbox_file_fix(struct dbox_file *file, uoff_t start_offset);

/* Fill dbox_message_header with given size. */
void dbox_msg_header_fill(struct dbox_message_header *dbox_msg_hdr,
			  uoff_t message_size);

const char *dbox_file_get_primary_path(struct dbox_file *file);
const char *dbox_file_get_alt_path(struct dbox_file *file);
void dbox_file_set_syscall_error(struct dbox_file *file, const char *function);
void dbox_file_set_corrupted(struct dbox_file *file, const char *reason, ...)
	ATTR_FORMAT(2, 3);

/* private: */
char *dbox_generate_tmp_filename(void);
int dbox_create_fd(struct dbox_storage *storage, const char *path);
int dbox_file_header_write(struct dbox_file *file, struct ostream *output);
int dbox_file_read_mail_header(struct dbox_file *file, uoff_t *physical_size_r);
int dbox_file_metadata_skip_header(struct dbox_file *file);

#endif
