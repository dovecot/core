#define _XOPEN_SOURCE 4
#define _XOPEN_SOURCE_EXTENDED 1
#define _XOPEN_VERSION 4
#define _XPG4_2
#include <unistd.h>

#include "mycrypt.h"

char *mycrypt(const char *key, const char *salt)
{
	return crypt(key, salt);
}
