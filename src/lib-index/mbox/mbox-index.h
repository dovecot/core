#ifndef __MBOX_INDEX_H
#define __MBOX_INDEX_H

#include "md5.h"
#include "mail-index.h"

typedef struct {
	MailFlags flags;
	MD5Context md5;
	int received;
} MboxHeaderContext;

MailIndex *mbox_index_alloc(const char *dir, const char *mbox_path);

void mbox_header_init_context(MboxHeaderContext *ctx);
void mbox_header_func(MessagePart *part __attr_unused__,
		      const char *name, unsigned int name_len,
		      const char *value, unsigned int value_len,
		      void *context);
int mbox_skip_crlf(IOBuffer *inbuf);

int mbox_index_rebuild(MailIndex *index);
int mbox_index_sync(MailIndex *index);
int mbox_index_fsck(MailIndex *index);
IOBuffer *mbox_open_mail(MailIndex *index, MailIndexRecord *rec);

int mbox_index_append(MailIndex *index, IOBuffer *inbuf);

time_t mbox_from_parse_date(const char *msg, unsigned int size);
const char *mbox_from_create(const char *sender, time_t time);

#endif
