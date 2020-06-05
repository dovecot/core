/* Copyright (c) 2017-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "istream.h"
#include "json-tree.h"
#include "oauth2.h"
#include "oauth2-private.h"

int oauth2_json_tree_build(const buffer_t *json, struct json_tree **tree_r,
			   const char **error_r)
{
	struct istream *is = i_stream_create_from_buffer(json);
	struct json_parser *parser = json_parser_init(is);
	struct json_tree *tree = json_tree_init();
	enum json_type type;
	const char *value;
	int ret;

	while ((ret = json_parse_next(parser, &type, &value)) > 0) {
		/* this is safe to reuse here because it gets rewritten in while
		   loop */
		ret = json_tree_append(tree, type, value);
		i_assert(ret == 0);
	}
	i_assert(ret != 0);
	ret = json_parser_deinit(&parser, error_r);
	i_stream_unref(&is);
	if (ret != 0)
		json_tree_deinit(&tree);
	else
		*tree_r = tree;
	return ret;
}

bool oauth2_valid_token(const char *token)
{
	if (token == NULL || *token == '\0' || strpbrk(token, "\r\n") != NULL)
		return FALSE;
	return TRUE;
}
