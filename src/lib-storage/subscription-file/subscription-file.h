#ifndef __SUBSCRIPTION_FILE_H
#define __SUBSCRIPTION_FILE_H

#include "mail-storage.h"

/* Initialize new subscription file listing. Returns NULL if failed. */
struct subsfile_list_context *
subsfile_list_init(struct mail_storage *storage, const char *path);

/* Deinitialize subscription file listing. Returns FALSE if some error occured
   while listing. */
int subsfile_list_deinit(struct subsfile_list_context *ctx);
/* Returns the next subscribed mailbox, or NULL. */
const char *subsfile_list_next(struct subsfile_list_context *ctx);

int subsfile_set_subscribed(struct mail_storage *storage, const char *path,
			    const char *name, int set);

#endif
