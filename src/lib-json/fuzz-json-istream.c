/* Copyright (c) 2023 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "istream.h"
#include "test-common.h"
#include "test-common.h"
#include "fuzzer.h"

#include "json-types.h"
#include "json-parser.h"
#include "json-istream.h"

FUZZ_BEGIN_DATA(const unsigned char *data, size_t size)
{
	struct istream *input;
	struct json_limits limits = {
		.max_name_size = 1024U,
		.max_string_size = 1024U,
		.max_nesting = 10U,
		.max_list_items = JSON_DEFAULT_MAX_LIST_ITEMS,
	};
	struct json_tree *tree = NULL;
	struct json_istream *jinput;
	int ret;

	input = test_istream_create_data(data, size);
	jinput = json_istream_create(input, JSON_ISTREAM_TYPE_NORMAL, &limits,
				     JSON_PARSER_FLAG_STRICT);
	ret = json_istream_read_tree(jinput, &tree);
	i_assert(ret < 1 || tree != NULL);
	if (tree != NULL)
		json_tree_unref(&tree);
	json_istream_unref(&jinput);
	i_stream_unref(&input);
}
FUZZ_END
