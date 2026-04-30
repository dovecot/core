#ifndef STORAGE_VERSION_H
#define STORAGE_VERSION_H

#include "version.h"

/* Returns TRUE if dovecot_storage_version selects the v2 (keyed xxh64)
   mail_index_strmap on-disk format. */
static inline bool
storage_version_has_mail_index_strmap_v2(const char *version)
{
	if (version == NULL) {
		/* unit test */
		return TRUE;
	}
#ifdef DOVECOT_PRO_EDITION
	return version_cmp(version, "3.1.6") >= 0;
#else
	return version_cmp(version, "2.4.5") >= 0;
#endif
}

#endif
