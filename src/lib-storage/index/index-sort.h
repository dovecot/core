#ifndef __INDEX_SORT_H
#define __INDEX_SORT_H

#include "mail-storage.h"
#include "mail-sort.h"

struct index_sort_context {
	struct index_mailbox *ibox;
	struct ostream *output;

	unsigned int last_uid;
	struct mail_index_record *rec;

	unsigned int cached:1;
};

extern struct mail_sort_callbacks index_sort_callbacks;

#endif
