#define _XOPEN_SOURCE 4
#define _XOPEN_SOURCE_EXTENDED 1 /* 1 needed for AIX */
#define _XOPEN_VERSION 4
#define _XPG4_2
#ifdef CRYPT_USE_XPG6
#  define _XPG6 /* Some Solaris versions require this, some break with this */
#endif
#include <unistd.h>

#include "mycrypt.h"

char *mycrypt(const char *key, const char *salt)
{
	return crypt(key, salt);
}
