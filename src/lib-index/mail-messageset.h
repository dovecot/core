#ifndef __MAIL_MESSAGESET_H
#define __MAIL_MESSAGESET_H

#include "mail-index.h"

/* If FALSE is returned, the loop is stopped. */
typedef int (*MsgsetForeachFunc)(MailIndex *index, MailIndexRecord *rec,
				 unsigned int seq, void *user_data);

/* Returns -1 if error occured, 0 if foreach-func returned FALSE,
   1 if everything was ok or 2 if some of the given sequences were expunged */
int mail_index_messageset_foreach(MailIndex *index, const char *messageset,
				  unsigned int messages_count,
				  MsgsetForeachFunc func, void *user_data);

/* Like messageset_foreach() but for UIDs. */
int mail_index_uidset_foreach(MailIndex *index, const char *uidset,
			      unsigned int messages_count,
			      MsgsetForeachFunc func, void *user_data);

#endif
