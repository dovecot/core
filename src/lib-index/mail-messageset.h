#ifndef __MAIL_MESSAGESET_H
#define __MAIL_MESSAGESET_H

#include "mail-index.h"

/* If FALSE is returned, the loop is stopped. */
typedef int (*MsgsetForeachFunc)(MailIndex *index, MailIndexRecord *rec,
				 unsigned int seq, void *context);

/* Returns -1 if internal error occured, -2 if messageset was invalid
   (sets error), 0 if foreach-func returned FALSE, 1 if everything was ok
   or 2 if some of the given sequences were expunged */
int mail_index_messageset_foreach(MailIndex *index, const char *messageset,
				  unsigned int messages_count,
				  MsgsetForeachFunc func, void *context,
				  const char **error);

/* Like messageset_foreach() but for UIDs. */
int mail_index_uidset_foreach(MailIndex *index, const char *uidset,
			      unsigned int messages_count,
			      MsgsetForeachFunc func, void *context,
			      const char **error);

#endif
