#ifndef __MBOX_INDEX_H
#define __MBOX_INDEX_H

#include "md5.h"
#include "mail-index.h"

typedef struct {
	MailIndex *index;
	MailFlags flags;
	const char **custom_flags;
	MD5Context md5;
	int received;

	IBuffer *inbuf;
	uoff_t content_length;
	int set_read_limit;
} MboxHeaderContext;

int mbox_set_syscall_error(MailIndex *index, const char *function);

/* Make sure the mbox is opened. If reopen is TRUE, the file is closed first,
   which is useful when you want to be sure you're not accessing a deleted
   mbox file. */
IBuffer *mbox_file_open(MailIndex *index, uoff_t offset, int reopen);
void mbox_file_close(MailIndex *index);

void mbox_header_init_context(MboxHeaderContext *ctx, MailIndex *index,
			      IBuffer *inbuf);
void mbox_header_free_context(MboxHeaderContext *ctx);
void mbox_header_func(MessagePart *part __attr_unused__,
		      const char *name, size_t name_len,
		      const char *value, size_t value_len,
		      void *context);
void mbox_keywords_parse(const char *value, size_t len,
			 const char *custom_flags[MAIL_CUSTOM_FLAGS_COUNT],
			 void (*func)(const char *, size_t, int, void *),
			 void *context);
int mbox_skip_crlf(IBuffer *inbuf);
void mbox_skip_empty_lines(IBuffer *inbuf);
void mbox_skip_header(IBuffer *inbuf);
void mbox_skip_message(IBuffer *inbuf);
int mbox_verify_end_of_body(IBuffer *inbuf, uoff_t end_offset);
int mbox_mail_get_start_offset(MailIndex *index, MailIndexRecord *rec,
			       uoff_t *offset);

MailIndex *mbox_index_alloc(const char *dir, const char *mbox_path);
int mbox_index_rebuild(MailIndex *index);
int mbox_index_sync(MailIndex *index);
int mbox_index_fsck(MailIndex *index);
IBuffer *mbox_open_mail(MailIndex *index, MailIndexRecord *rec);

int mbox_index_append(MailIndex *index, IBuffer *inbuf);

time_t mbox_from_parse_date(const char *msg, size_t size);
const char *mbox_from_create(const char *sender, time_t time);

int mbox_index_rewrite(MailIndex *index);

#endif
