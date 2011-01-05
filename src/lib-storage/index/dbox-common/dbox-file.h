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

/* prefer flock(). fcntl() locking currently breaks if trying to access the
   same file from multiple mail_storages within same process. that's why we
   fallback to dotlocks. */
#ifdef HAVE_FLOCK
#  define DBOX_FILE_LOCK_METHOD_FLOCK
#endif

struct dbox_file;

enum dbox_header_key {
	/* Must be sizeof(struct dbox_message_header) when appending (hex) */
	DBOX_HEADER_MSG_HEADER_SIZE	= 'M',
	/* Creation UNIX timestamp (hex) */
	DBOX_HEADER_CREATE_STAMP	= 'C',

	/* metadata used by old Dovecot versions */
	DBOX_HEADER_OLDV1_APPEND_OFFSET	= 'A'
};

enum dbox_metadata_key {
	/* Globally unique identifier for the message. Preserved when
	   copying. */
	DBOX_METADATA_GUID		= 'G',
	/* POP3 UIDL overriding the default format */
	DBOX_METADATA_POP3_UIDL		= 'P',
	/* Received UNIX timestamp in hex */
	DBOX_METADATA_RECEIVED_TIME	= 'R',
	/* Physical message size in hex. Necessary only if it differs from
	   the dbox_message_header.message_size_hex, for example because the
	   message is compressed. */
	DBOX_METADATA_PHYSICAL_SIZE	= 'Z',
	/* Virtual message size in hex (line feeds counted as CRLF) */
	DBOX_METADATA_VIRTUAL_SIZE	= 'V',
	/* Pointer to external message data. Format is:
	   1*(<start offset> <byte count> <options> <ref>) */
	DBOX_METADATA_EXT_REF		= 'X',
	/* Mailbox name where this message was originally saved to.
	   When rebuild finds a message whose mailbox is unknown, it's
	   placed to this mailbox. */
	DBOX_METADATA_ORIG_MAILBOX	= 'B',

	/* metadata used by old Dovecot versions */
	DBOX_METADATA_OLDV1_EXPUNGED	= 'E',
	DBOX_METADATA_OLDV1_FLAGS	= 'F',
	DBOX_METADATA_OLDV1_KEYWORDS	= 'K',
	DBOX_METADATA_OLDV1_SAVE_TIME	= 'S',
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
	int refcount;

	time_t create_time;
	unsigned int file_version;
	unsigned int file_header_size;
	unsigned int msg_header_size;

	const char *cur_path;
	char *primary_path, *alt_path;
	int fd;
	struct istream *input;
#ifdef DBOX_FILE_LOCK_METHOD_FLOCK
	struct file_lock *lock;
#else
	struct dotlock *lock;
#endif

	uoff_t cur_offset;
	uoff_t cur_physical_size;

	/* Metadata for the currently seeked metadata block. */
	pool_t metadata_pool;
	ARRAY_DEFINE(metadata, const char *);
	uoff_t metadata_read_offset;

	unsigned int appending:1;
	unsigned int deleted:1;
	unsigned int corrupted:1;
};

struct dbox_file_append_context {
	struct dbox_file *file;

	uoff_t first_append_offset, last_checkpoint_offset, last_flush_offset;
	struct ostream *output;
};

#define dbox_file_is_open(file) ((file)->fd != -1)
#define dbox_file_is_in_alt(file) ((file)->cur_path == (file)->alt_path)

void dbox_file_init(struct dbox_file *file);
void dbox_file_unref(struct dbox_file **file);

/* Open the file. Returns 1 if ok, 0 if file header is corrupted, -1 if error.
   If file is deleted, deleted_r=TRUE and 1 is returned. */
int dbox_file_open(struct dbox_file *file, bool *deleted_r);
/* Try to open file only from primary path. */
int dbox_file_open_primary(struct dbox_file *file, bool *notfound_r);
/* Close the file handle from the file, but don't free it. */
void dbox_file_close(struct dbox_file *file);

/* fstat() or stat() the file. If file is already deleted, fails with
   errno=ENOENT. */
int dbox_file_stat(struct dbox_file *file, struct stat *st_r);

/* Try to lock the dbox file. Returns 1 if ok, 0 if already locked by someone
   else, -1 if error. */
int dbox_file_try_lock(struct dbox_file *file);
void dbox_file_unlock(struct dbox_file *file);

/* Seek to given offset in file. Returns 1 if ok/expunged, 0 if file/offset is
   corrupted, -1 if I/O error. */
int dbox_file_seek(struct dbox_file *file, uoff_t offset);
/* Start seeking at the beginning of the file. */
void dbox_file_seek_rewind(struct dbox_file *file);
/* Seek to next message after current one. If there are no more messages,
   returns 0 and last_r is set to TRUE. Returns 1 if ok, 0 if file is
   corrupted, -1 if I/O error. */
int dbox_file_seek_next(struct dbox_file *file, uoff_t *offset_r, bool *last_r);

/* Start appending to dbox file */
struct dbox_file_append_context *dbox_file_append_init(struct dbox_file *file);
/* Finish writing appended mails. */
int dbox_file_append_commit(struct dbox_file_append_context **ctx);
/* Truncate appended mails. */
void dbox_file_append_rollback(struct dbox_file_append_context **ctx);
/* Get output stream for appending a new message. Returns 1 if ok, 0 if file
   can't be appended to (old file version or corruption) or -1 if error. */
int dbox_file_get_append_stream(struct dbox_file_append_context *ctx,
				struct ostream **output_r);
/* Call after message has been fully saved. If this isn't done, the writes
   since the last checkpoint are truncated. */
void dbox_file_append_checkpoint(struct dbox_file_append_context *ctx);
/* Flush output buffer. */
int dbox_file_append_flush(struct dbox_file_append_context *ctx);

/* Read current message's metadata. Returns 1 if ok, 0 if metadata is
   corrupted, -1 if I/O error. */
int dbox_file_metadata_read(struct dbox_file *file);
/* Return wanted metadata value, or NULL if not found. */
const char *dbox_file_metadata_get(struct dbox_file *file,
				   enum dbox_metadata_key key);

/* Returns DBOX_METADATA_PHYSICAL_SIZE if set, otherwise physical size from
   header. They differ only for e.g. compressed mails. */
uoff_t dbox_file_get_plaintext_size(struct dbox_file *file);

/* Fix a broken dbox file by rename()ing over it with a fixed file. Everything
   before start_offset is assumed to be valid and is simply copied. The file
   is reopened afterwards. Returns 0 if ok, -1 if I/O error. */
int dbox_file_fix(struct dbox_file *file, uoff_t start_offset);
/* Delete the given dbox file. Returns 1 if deleted, 0 if file wasn't found
   or -1 if error. */
int dbox_file_unlink(struct dbox_file *file);

/* Fill dbox_message_header with given size. */
void dbox_msg_header_fill(struct dbox_message_header *dbox_msg_hdr,
			  uoff_t message_size);

void dbox_file_set_syscall_error(struct dbox_file *file, const char *function);
void dbox_file_set_corrupted(struct dbox_file *file, const char *reason, ...)
	ATTR_FORMAT(2, 3);

/* private: */
const char *dbox_generate_tmp_filename(void);
void dbox_file_free(struct dbox_file *file);
int dbox_file_header_write(struct dbox_file *file, struct ostream *output);
int dbox_file_read_mail_header(struct dbox_file *file, uoff_t *physical_size_r);
int dbox_file_metadata_skip_header(struct dbox_file *file);

#endif
