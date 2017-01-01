/* Copyright (c) 2016-2017 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "sort.h"

#include <string.h>
#include <strings.h>

int bsearch_strcmp(const char *key, const char *const *member)
{
	return strcmp(key, *member);
}

int bsearch_strcasecmp(const char *key, const char *const *member)
{
	return strcasecmp(key, *member);
}
