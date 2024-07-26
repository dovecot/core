/* Copyright (c) 2016-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "sort.h"

#include <string.h>
#include <strings.h>

int search_strcmp(const char *key, const char *const *member)
{
	return strcmp(key, *member);
}

int search_strcasecmp(const char *key, const char *const *member)
{
	return strcasecmp(key, *member);
}
