#ifndef __MBOX_INDEX_H
#define __MBOX_INDEX_H

#include "md5.h"
#include "mail-index.h"

struct mbox_header_context {
	struct mail_index *index;
	enum mail_flags flags;
	const char **custom_flags;
	struct md5_context md5;
	int received;

	unsigned int uid_validity, uid_last, uid;

	struct istream *input;
	uoff_t content_length;
	int set_read_limit;
};

int mbox_set_syscall_error(struct mail_index *index, const char *function);

/* Make sure the mbox is opened. If reopen is TRUE, the file is closed first,
   which is useful when you want to be sure you're not accessing a deleted
   mbox file. */
int mbox_file_open(struct mail_index *index);
struct istream *mbox_get_stream(struct mail_index *index, uoff_t offset,
				enum mail_lock_type lock_type);
void mbox_file_close_stream(struct mail_index *index);
void mbox_file_close_fd(struct mail_index *index);

void mbox_header_init_context(struct mbox_header_context *ctx,
			      struct mail_index *index,
			      struct istream *input);
void mbox_header_free_context(struct mbox_header_context *ctx);
void mbox_header_cb(struct message_part *part,
		    struct message_header_line *hdr, void *context);
void mbox_keywords_parse(const unsigned char *value, size_t len,
			 const char *custom_flags[MAIL_CUSTOM_FLAGS_COUNT],
			 void (*func)(const unsigned char *, size_t,
				      int, void *),
			 void *context);
int mbox_skip_crlf(struct istream *input);
void mbox_skip_empty_lines(struct istream *input);
void mbox_skip_header(struct istream *input);
void mbox_skip_message(struct istream *input);
int mbox_verify_end_of_body(struct istream *input, uoff_t end_offset);
int mbox_mail_get_location(struct mail_index *index,
			   struct mail_index_record *rec,
			   uoff_t *offset, uoff_t *hdr_size, uoff_t *body_size);

struct mail_index *mbox_index_alloc(const char *dir, const char *mbox_path);
int mbox_index_rebuild(struct mail_index *index);
int mbox_index_sync(struct mail_index *index,
		    enum mail_lock_type lock_type, int *changes);
int mbox_sync_full(struct mail_index *index);
struct istream *mbox_open_mail(struct mail_index *index,
			       struct mail_index_record *rec,
			       time_t *internal_date, int *deleted);

int mbox_index_append(struct mail_index *index, struct istream *input);

time_t mbox_from_parse_date(const unsigned char *msg, size_t size);
const char *mbox_from_create(const char *sender, time_t time);

int mbox_index_rewrite(struct mail_index *index);

#endif
