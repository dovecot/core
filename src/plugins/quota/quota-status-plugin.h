#ifndef QUOTA_STATUS_PLUGIN_H
#define QUOTA_STATUS_PLUGIN_H

#include "quota.h"

/* Test whether a mail with the given size could be saved to the user's INBOX
   without exceeding the quota. error_r is set to a user visible error
   message. */
enum quota_alloc_result
quota_status_check(struct mail_user *user, uoff_t mail_size,
		   const char **error_r);

#endif
