#ifndef IMAP_STORAGE_CALLBACKS_H
#define IMAP_STORAGE_CALLBACKS_H

#include "imap-client.h"

const char *
imap_storage_callback_line(const struct mail_storage_progress_details *dtl,
			   const char *tag);

int imap_notify_progress(const struct mail_storage_progress_details *dtl,
			 struct client *client);

#endif
