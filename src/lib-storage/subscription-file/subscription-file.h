#ifndef __SUBSCRIPTION_FILE_H
#define __SUBSCRIPTION_FILE_H

#include "mail-storage.h"

/* Returns FALSE if foreach should be aborted */
typedef int (*SubsFileForeachFunc)(MailStorage *storage, const char *name,
				   void *context);

int subsfile_set_subscribed(MailStorage *storage, const char *name, int set);

/* Returns -1 if error, 0 if foreach function returned FALSE or 1 if all ok */
int subsfile_foreach(MailStorage *storage, const char *mask,
		     SubsFileForeachFunc func, void *context);

#endif
