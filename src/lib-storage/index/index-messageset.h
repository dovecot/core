#ifndef __INDEX_MESSAGESET_H
#define __INDEX_MESSAGESET_H

#include "index-storage.h"

/* If FALSE is returned, the loop is stopped. */
typedef int (*MsgsetForeachFunc)(MailIndex *index, MailIndexRecord *rec,
				 unsigned int seq, void *context);

/* Returns 1 if all were found, 2 if some messages were deleted,
   0 func returned FALSE, -1 if internal error occured or -2 if messageset
   was invalid. */
int index_messageset_foreach(IndexMailbox *ibox,
			     const char *messageset, int uidset,
			     MsgsetForeachFunc func, void *context);

#endif
