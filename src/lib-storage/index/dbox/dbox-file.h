#ifndef DBOX_FILE_H
#define DBOX_FILE_H

/* The file begins with a header followed by zero or more messages:

   <dbox message header>
   <LF>
   <message body>
   <metadata>

   Metadata block begins with DBOX_MAGIC_POST, followed by zero or more lines
   in format <key character><value><LF>. The block ends with a line containing
   zero or more spaces. The spaces can be used for writing more headers.
   Unknown metadata should be ignored, but preserved when copying.

   There should be no duplicates for the current metadata, but future
   extensions may need them so they should be preserved.
*/
#define DBOX_VERSION 1
#define DBOX_MAGIC_PRE "\001\002"
#define DBOX_MAGIC_POST "\n\001\003\n"

#define DBOX_EXTRA_SPACE 64
/* If file_id has this flag set, the file is a single file with file_id=UID. */
#define DBOX_FILE_ID_FLAG_UID 0x80000000

enum dbox_header_key {
	/* Offset for appending next message. In %08x format so it can be
	   updated without moving data in header. If messages have been
	   expunged and file must not be appended anymore, the value is filled
	   with 'X'. */
	DBOX_HEADER_APPEND_OFFSET	= 'A',
	/* Must be sizeof(struct dbox_message_header) when appending (hex) */
	DBOX_HEADER_MSG_HEADER_SIZE	= 'M',
	/* Creation UNIX timestamp (hex) */
	DBOX_HEADER_CREATE_STAMP	= 'C'
};

enum dbox_metadata_flags {
	DBOX_METADATA_FLAGS_ANSWERED = 0,
	DBOX_METADATA_FLAGS_FLAGGED,
	DBOX_METADATA_FLAGS_DELETED,
	DBOX_METADATA_FLAGS_SEEN,
	DBOX_METADATA_FLAGS_DRAFT,

	DBOX_METADATA_FLAGS_COUNT
};

enum dbox_metadata_key {
	/* Message is marked as expunged. '0' = no, '1' = yes */
	DBOX_METADATA_EXPUNGED		= 'E',
	/* Message flags in dbox_metadata_flags order. '0' = not set, anything
	   else = set. Unknown flags should be preserved. */
	DBOX_METADATA_FLAGS		= 'F',
	/* Space separated list of keywords */
	DBOX_METADATA_KEYWORDS		= 'K',
	/* Pointer to external message data. Format is:
	   1*(<start offset> <byte count> <ref>) */
	DBOX_METADATA_EXT_REF		= 'P',
	/* Received UNIX timestamp in hex */
	DBOX_METADATA_RECEIVED_TIME	= 'R',
	/* Saved UNIX timestamp in hex */
	DBOX_METADATA_SAVE_TIME		= 'S',
	/* Virtual message size in hex (line feeds counted as CRLF) */
	DBOX_METADATA_VIRTUAL_SIZE	= 'V',

	/* End of metadata block. The spaces can be used for writing more
	   metadata. */
	DBOX_METADATA_SPACE		= ' '
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
	unsigned char uid_hex[8];
	unsigned char space2;
	unsigned char message_size_hex[16];
	/* <space reserved for future extensions, LF is always last> */
	unsigned char save_lf;
};

struct dbox_metadata_header {
	unsigned char magic_post[sizeof(DBOX_MAGIC_POST)-1];
};

struct dbox_file {
	struct dbox_mailbox *mbox;
	int refcount;
	unsigned int file_id;

	unsigned int file_header_size;
	unsigned int msg_header_size;
	unsigned int append_offset_header_pos;

	unsigned int append_count;
	uint32_t last_append_uid, maildir_append_seq;

	uoff_t append_offset;
	time_t create_time;
	uoff_t output_stream_offset;

	char *path;
	int fd;
	struct istream *input;
	struct ostream *output;

	/* Metadata for the currently seeked metadata block. */
	pool_t metadata_pool;
	ARRAY_DEFINE(metadata, const char *);
	ARRAY_DEFINE(metadata_changes, const char *);
	uoff_t metadata_read_offset;
	unsigned int metadata_space_pos;
	/* Includes the trailing LF that shouldn't be used */
	unsigned int metadata_len;

	unsigned int maildir_file:1;
	unsigned int nonappendable:1;
	unsigned int deleted:1;
};

extern enum mail_flags dbox_mail_flags_map[DBOX_METADATA_FLAGS_COUNT];
extern char dbox_mail_flag_chars[DBOX_METADATA_FLAGS_COUNT];

struct dbox_file *
dbox_file_init(struct dbox_mailbox *mbox, unsigned int file_id);
struct dbox_file *
dbox_file_init_new_maildir(struct dbox_mailbox *mbox, const char *fname);
void dbox_file_unref(struct dbox_file **file);

/* Free all currently opened files. */
void dbox_files_free(struct dbox_mailbox *mbox);

/* Assign a newly created file (file_id=0) a new id. */
int dbox_file_assign_id(struct dbox_file *file, unsigned int file_id);

/* If file_id is 0, open the file, otherwise create it. Returns 1 if ok,
   0 if read_header=TRUE and opened file was broken, -1 if error. If file is
   deleted, deleted_r=TRUE and 1 is returned. */
int dbox_file_open_or_create(struct dbox_file *file, bool read_header,
			     bool *deleted_r);

/* Seek to given offset in file and return the message's input stream, UID
   and physical size. Returns 1 if ok, 0 if file/offset is corrupted,
   -1 if I/O error. */
int dbox_file_get_mail_stream(struct dbox_file *file, uoff_t offset,
			      uint32_t *uid_r, uoff_t *physical_size_r,
			      struct istream **stream_r, bool *expunged_r);
/* Seek to next message after given offset, or to first message if offset=0.
   If there are no more messages, uid_r is set to 0. Returns 1 if ok, 0 if
   file/offset is corrupted, -1 if I/O error. */
int dbox_file_seek_next(struct dbox_file *file, uoff_t *offset,
			uint32_t *uid_r, uoff_t *physical_size_r);

/* Returns TRUE if mail_size bytes can be appended to the file. */
bool dbox_file_can_append(struct dbox_file *file, uoff_t mail_size);
/* Get output stream for appending a new message. Returns 1 if ok, 0 if
   file can't be appended to (limits reached, expunges, corrupted) or
   -1 if error. If 0 is returned, index is also updated. */
int dbox_file_get_append_stream(struct dbox_file *file, uoff_t mail_size,
				struct ostream **stream_r);
/* Returns the next offset for append a message. dbox_file_get_append_stream()
   must have been called for this file already at least once. */
uoff_t dbox_file_get_next_append_offset(struct dbox_file *file);
/* Truncate file to append_offset */
void dbox_file_cancel_append(struct dbox_file *file, uoff_t append_offset);
/* Finish appending the current mail. */
void dbox_file_finish_append(struct dbox_file *file);

/* Calculate offset to message's metadata. */
uoff_t dbox_file_get_metadata_offset(struct dbox_file *file, uoff_t offset,
				     uoff_t physical_size);
/* Seek to given metadata block. Returns 1 if ok, 0 if file/offset is
   corrupted, -1 if I/O error. If message has already been expunged,
   expunged_r=TRUE and 1 is returned. */
int dbox_file_metadata_seek(struct dbox_file *file, uoff_t metadata_offset,
			    bool *expunged_r);
/* Like dbox_file_metadata_seek(), but the offset points to beginning of the
   message. The function internally reads the message header to find the
   metadata offset. */
int dbox_file_metadata_seek_mail_offset(struct dbox_file *file, uoff_t offset,
					bool *expunged_r);

/* Return wanted metadata value, or NULL if not found. */
const char *dbox_file_metadata_get(struct dbox_file *file,
				   enum dbox_metadata_key key);
/* Add key=value metadata update (not written yet, not visible to _get()).
   The changes are reset by dbox_file_metadata_seek() call. */
void dbox_file_metadata_set(struct dbox_file *file, enum dbox_metadata_key key,
			    const char *value);
/* Write all metadata updates to disk. Returns 1 if ok, 0 if metadata doesn't
   fit to its reserved space and message isn't last in file, -1 if I/O error. */
int dbox_file_metadata_write(struct dbox_file *file);
/* Write all metadata to output stream. Returns 0 if ok, -1 if I/O error. */
int dbox_file_metadata_write_to(struct dbox_file *file, struct ostream *output);

/* Get file/offset for wanted message. Returns TRUE if found. */
bool dbox_file_lookup(struct dbox_mailbox *mbox, struct mail_index_view *view,
		      uint32_t seq, uint32_t *file_id_r, uoff_t *offset_r);

/* Append flags as metadata value to given string */
void dbox_mail_metadata_flags_append(string_t *str, enum mail_flags flags);
/* Append keywords as metadata value to given string */
void dbox_mail_metadata_keywords_append(struct dbox_mailbox *mbox,
					string_t *str,
					const struct mail_keywords *keywords);

/* Fill dbox_message_header with given uid/size. */
void dbox_msg_header_fill(struct dbox_message_header *dbox_msg_hdr,
			  uint32_t uid, uoff_t message_size);

void dbox_file_set_syscall_error(struct dbox_file *file, const char *function);

#endif
