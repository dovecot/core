#ifndef __INDEX_SORT_H
#define __INDEX_SORT_H

#include "mail-storage.h"
#include "mail-sort.h"

typedef struct {
	IndexMailbox *ibox;
	OBuffer *outbuf;

	unsigned int last_uid;
	MailIndexRecord *rec;

	unsigned int cached:1;
} IndexSortContext;

extern MailSortFuncs index_sort_funcs;

#endif
