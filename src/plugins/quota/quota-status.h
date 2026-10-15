#ifndef QUOTA_STATUS_H
#define QUOTA_STATUS_H

#include "quota.h"

/* Test whether a mail with the given size could be saved to the user's INBOX
   without exceeding the quota. error_r is set to a user visible error
   message. */
typedef enum quota_alloc_result
quota_status_check_func_t(struct mail_user *user, uoff_t mail_size,
			  const char **error_r);

/* Called by the quota_status plugin to set the check function, or NULL to
   unset it. The quota-status binary always loads the plugin (and the quota
   plugin it depends on) via mail_plugins. The quota-status binary doesn't
   link against the quota plugin, because linking executables against
   loadable modules isn't portable. This is a function rather than an
   exported variable, so that if the plugin is loaded by some other binary,
   module-dir can lazily load it and give a clear error message about the
   plugin's binary dependency. */
void quota_status_set_check(quota_status_check_func_t *check);

#endif
