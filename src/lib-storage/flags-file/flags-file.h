#ifndef __FLAGS_FILE_H
#define __FLAGS_FILE_H

#include "mail-storage.h"

#define FLAGS_FILE_NAME ".customflags"

typedef struct _FlagsFile FlagsFile;

FlagsFile *flags_file_open_or_create(MailStorage *storage, const char *path);
void flags_file_destroy(FlagsFile *ff);

/* Change custom flags so that they reflect the real flag numbers in
   the file. get_used_flags is called when all flags are in use to figure
   out which of them could be removed. */
int flags_file_fix_custom_flags(FlagsFile *ff, MailFlags *flags,
				const char *custom_flags[],
				MailFlags (*get_used_flags)(void *context),
				void *context);

/* Returns a pointer to list of flags. */
const char **flags_file_list_get(FlagsFile *ff);

/* Call this after you've done with the flags list above */
void flags_file_list_unref(FlagsFile *ff);

#endif
