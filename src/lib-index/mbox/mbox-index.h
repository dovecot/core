#ifndef __MBOX_INDEX_H
#define __MBOX_INDEX_H

#include "mail-index.h"

MailIndex *mbox_index_alloc(const char *dir, const char *mbox_path);

MailFlags mbox_header_get_flags(const char *name, unsigned int name_len,
				const char *value, unsigned int value_len);

int mbox_index_rebuild(MailIndex *index);
int mbox_index_sync(MailIndex *index);
int mbox_index_fsck(MailIndex *index);
int mbox_open_mail(MailIndex *index, MailIndexRecord *rec,
		   off_t *offset, size_t *size);

int mbox_index_append(MailIndex *index, int fd, const char *path);
int mbox_index_append_mmaped(MailIndex *index, const char *data,
			     size_t data_size, off_t start_offset);

#endif
