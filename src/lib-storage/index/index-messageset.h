#ifndef __INDEX_MESSAGESET_H
#define __INDEX_MESSAGESET_H

#include "index-storage.h"

/* If FALSE is returned, the loop is stopped. */
typedef int (*msgset_foreach_callback_t)(struct mail_index *index,
					 struct mail_index_record *rec,
					 unsigned int client_seq,
					 unsigned int idx_seq,
					 void *context);

/* Returns 1 if all were found, 2 if some messages were deleted,
   0 callback returned FALSE, -1 if internal error occured or -2 if messageset
   was invalid. */
int index_messageset_foreach(struct index_mailbox *ibox,
			     const char *messageset, int uidset,
			     msgset_foreach_callback_t callback, void *context);

#endif
