#ifndef __INDEX_SORT_H
#define __INDEX_SORT_H

#include "mail-storage.h"
#include "mail-sort.h"

struct index_sort_context {
	struct index_mailbox *ibox;
	struct ostream *output;

	unsigned int current_client_seq;
	struct mail_index_record *current_rec;

	unsigned int last_id;
	struct mail_index_record *rec;

	unsigned int cached:1;
	unsigned int id_is_uid:1;
	unsigned int synced_sequences:1;
};

extern struct mail_sort_callbacks index_sort_callbacks;

#endif
