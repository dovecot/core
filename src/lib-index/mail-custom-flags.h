#ifndef __MAIL_CUSTOM_FLAGS_H
#define __MAIL_CUSTOM_FLAGS_H

#include "mail-index.h"

#define CUSTOM_FLAGS_FILE_NAME ".customflags"

int mail_custom_flags_open_or_create(MailIndex *index);
void mail_custom_flags_free(MailCustomFlags *mcf);

/* Change custom flags so that they reflect the real flag numbers in
   the file. Returns 1 if ok, 0 if number of custom flags exceeded or
   -1 if error */
int mail_custom_flags_fix_list(MailCustomFlags *mcf, MailFlags *flags,
			       const char *custom_flags[]);

/* Returns a pointer to list of flags. */
const char **mail_custom_flags_list_get(MailCustomFlags *mcf);

/* Call this after you've done with the flags list above */
void mail_custom_flags_list_unref(MailCustomFlags *mcf);

#endif
