#define _XOPEN_SOURCE
#include <unistd.h>

#include "mycrypt.h"

char *mycrypt(const char *key, const char *salt)
{
	return crypt(key, salt);
}
