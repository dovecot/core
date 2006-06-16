#ifndef __DBOX_FORMAT_H
#define __DBOX_FORMAT_H

#define DBOX_SUBSCRIPTION_FILE_NAME "subscriptions"
#define DBOX_INDEX_PREFIX "dovecot.index"
#define DBOX_MAILDIR_NAME "dbox-Mails"
#define DBOX_MAIL_FILE_PREFIX "msg."
#define DBOX_MAIL_FILE_FORMAT DBOX_MAIL_FILE_PREFIX"%u"

#define DBOX_KEYWORD_COUNT 64
#define DBOX_KEYWORD_NAMES_RESERVED_SPACE (2048-sizeof(struct dbox_file_header))

/* Default rotation settings */
#define DBOX_DEFAULT_ROTATE_SIZE (2*1024*1024)
#define DBOX_DEFAULT_ROTATE_MIN_SIZE (1024*16)
#define DBOX_DEFAULT_ROTATE_DAYS 0

struct dbox_file_header {
	/* Size of the base header. sizeof(struct dbox_file_header) */
	unsigned char base_header_size_hex[4];
	/* Size of the full header, including keywords list and padding */
	unsigned char header_size_hex[8];
	/* Offset where to store the next mail. note that a mail may already
	   have been fully written here and added to uidlist, but this offset
	   just wasn't updated. In that case the append_offset should be
	   updated instead of overwriting the mail. */
	unsigned char append_offset_hex[16];
	/* Initial file creation time as UNIX timestamp. */
	unsigned char create_time_hex[8];
	/* Size of each message's header. */
	unsigned char mail_header_size_hex[4];
	/* If set, mail headers start always at given alignmentation.
	   Currently not supported. */
	unsigned char mail_header_align_hex[4];
	/* Number of keywords allocated for each mail (not necessarily used) */
	unsigned char keyword_count_hex[4];
	/* Offset for the keyword list inside the file header. */
	unsigned char keyword_list_offset_hex[8];

	/* Non-zero if some mails have been marked as expunged in the file. */
	unsigned char have_expunged_mails;

	/* space reserved for keyword list and possible other future
	   extensions. */
	/* unsigned char [header_size - header_base_size]; */
};

#define DBOX_MAIL_HEADER_MAGIC "\001\003"
struct dbox_mail_header {
	/* This field acts as kind of a verification marker to make sure that
	   seeked offset is valid. So the magic value should be something that
	   normally doesn't occur in mails. */
	unsigned char magic[2];
	unsigned char uid_hex[8];
	unsigned char mail_size_hex[16];
	unsigned char received_time_hex[8];
	unsigned char save_time_hex[8];
	unsigned char answered;
	unsigned char flagged;
	unsigned char deleted;
	unsigned char seen;
	unsigned char draft;
	unsigned char expunged;
	/* unsigned char keywords[keywords_count]; */
};

#endif
