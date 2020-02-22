/* Copyright (c) 2017-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "istream.h"
#include "json-istream.h"
#include "json-tree-io.h"
#include "oauth2.h"
#include "oauth2-private.h"

int oauth2_json_tree_build(const buffer_t *json, struct json_tree **jtree_r,
			   const char **error_r)
{
	return json_tree_read_buffer(json, 0, jtree_r, error_r);
}

bool oauth2_valid_token(const char *token)
{
	if (token == NULL || *token == '\0' || strpbrk(token, "\r\n") != NULL)
		return FALSE;
	return TRUE;
}
