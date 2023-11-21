/* Copyright (c) 2017-2023 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "istream.h"
#include "ostream.h"
#include "test-common.h"

#include "json-tree.h"

#include <unistd.h>

static bool debug = FALSE;

static void test_stream_value(struct istream *val_input, const char *expected)
{
	const unsigned char *data;
	size_t size;
	string_t *buffer;
	int ret;

	buffer = str_new(default_pool, 256);

	while ((ret = i_stream_read_more(val_input, &data, &size)) > 0) {
		str_append_data(buffer, data, size);
		i_stream_skip(val_input, size);
	}
	if (ret < 0)
		test_assert(!i_stream_have_bytes_left(val_input));

	test_assert_strcmp(str_c(buffer), expected);
	str_free(&buffer);
}

static void test_json_tree_walker(void)
{
	struct istream *input;
	const char *data;
	struct json_tree *jtree, *jtree2, *jtree3;
	struct json_tree_node *jtnode;
	struct json_tree_walker *jtwalker;
	struct json_node jnode;
	intmax_t num_val = 0;

	/* number */
	test_begin("json tree walker - number");
	jtree = json_tree_create();
	json_tree_node_add_number_int(json_tree_get_root(jtree), NULL, 23423);
	jtwalker = json_tree_walker_create(jtree);
	test_assert(json_tree_walk(jtwalker, &jnode));
	test_assert(json_node_is_number(&jnode));
	test_assert(json_node_get_intmax(&jnode, &num_val) == 0);
	test_assert(num_val == 23423);
	test_assert(!json_tree_walk(jtwalker, &jnode));
	json_tree_walker_free(&jtwalker);
	json_tree_unref(&jtree);
	test_end();

	/* false */
	test_begin("json tree walker - false");
	jtree = json_tree_create();
	json_tree_node_add_false(json_tree_get_root(jtree), NULL);
	jtwalker = json_tree_walker_create(jtree);
	test_assert(json_tree_walk(jtwalker, &jnode));
	test_assert(json_node_is_false(&jnode));
	test_assert(!json_tree_walk(jtwalker, &jnode));
	json_tree_walker_free(&jtwalker);
	json_tree_unref(&jtree);
	test_end();

	/* null */
	test_begin("json tree walker - null");
	jtree = json_tree_create();
	json_tree_node_add_null(json_tree_get_root(jtree), NULL);
	jtwalker = json_tree_walker_create(jtree);
	test_assert(json_tree_walk(jtwalker, &jnode));
	test_assert(json_node_is_null(&jnode));
	test_assert(!json_tree_walk(jtwalker, &jnode));
	json_tree_walker_free(&jtwalker);
	json_tree_unref(&jtree);
	test_end();

	/* true */
	test_begin("json tree walker - true");
	jtree = json_tree_create();
	json_tree_node_add_true(json_tree_get_root(jtree), NULL);
	jtwalker = json_tree_walker_create(jtree);
	test_assert(json_tree_walk(jtwalker, &jnode));
	test_assert(json_node_is_true(&jnode));
	test_assert(!json_tree_walk(jtwalker, &jnode));
	json_tree_walker_free(&jtwalker);
	json_tree_unref(&jtree);
	test_end();

	/* string */
	test_begin("json tree walker - string");
	jtree = json_tree_create();
	json_tree_node_add_string(json_tree_get_root(jtree), NULL, "frop");
	jtwalker = json_tree_walker_create(jtree);
	test_assert(json_tree_walk(jtwalker, &jnode));
	test_assert(json_node_is_string(&jnode));
	test_assert_strcmp(json_node_get_str(&jnode), "frop");
	test_assert(!json_tree_walk(jtwalker, &jnode));
	json_tree_walker_free(&jtwalker);
	json_tree_unref(&jtree);
	test_end();

	/* string stream */
	test_begin("json tree walker - string stream");
	jtree = json_tree_create();
	data = "AABBCCDDEEFFGGHHIIJJKKLLMMNNOOPPQQRRSSTTUUVVWWXXYYZZ";
	input = i_stream_create_from_data(data, strlen(data));
	json_tree_node_add_string_stream(json_tree_get_root(jtree),
					 NULL, input);
	i_stream_unref(&input);
	jtwalker = json_tree_walker_create(jtree);
	test_assert(json_tree_walk(jtwalker, &jnode));
	test_assert(json_node_is_string(&jnode));
	test_assert(jnode.value.content_type == JSON_CONTENT_TYPE_STREAM);
	test_assert(jnode.value.content.stream != NULL);
	test_stream_value(jnode.value.content.stream, data);
	test_assert(!json_tree_walk(jtwalker, &jnode));
	json_tree_walker_free(&jtwalker);
	json_tree_unref(&jtree);
	test_end();

	/* array */
	test_begin("json tree walker - array");
	jtree = json_tree_create();
	json_tree_node_add_array(json_tree_get_root(jtree), NULL);
	jtwalker = json_tree_walker_create(jtree);
	test_assert(json_tree_walk(jtwalker, &jnode));
	test_assert(json_node_is_array(&jnode));
	test_assert(json_tree_walk(jtwalker, &jnode));
	test_assert(json_node_is_array_end(&jnode));
	test_assert(!json_tree_walk(jtwalker, &jnode));
	json_tree_walker_free(&jtwalker);
	json_tree_unref(&jtree);
	test_end();

	/* [ string ] */
	test_begin("json tree walker - array [ string ]");
	jtree = json_tree_create();
	jtnode = json_tree_node_add_array(json_tree_get_root(jtree), NULL);
	json_tree_node_add_string(jtnode, NULL, "frop");
	jtwalker = json_tree_walker_create(jtree);
	test_assert(json_tree_walk(jtwalker, &jnode));
	test_assert(json_node_is_array(&jnode));
	test_assert(json_tree_walk(jtwalker, &jnode));
	test_assert(json_node_is_string(&jnode));
	test_assert_strcmp(json_node_get_str(&jnode), "frop");
	test_assert(json_tree_walk(jtwalker, &jnode));
	test_assert(json_node_is_array_end(&jnode));
	test_assert(!json_tree_walk(jtwalker, &jnode));
	json_tree_walker_free(&jtwalker);
	json_tree_unref(&jtree);
	test_end();

	/* [ string stream ] */
	test_begin("json tree walker - array [ string stream ]");
	jtree = json_tree_create();
	jtnode = json_tree_node_add_array(json_tree_get_root(jtree), NULL);
	data = "AABBCCDDEEFFGGHHIIJJKKLLMMNNOOPPQQRRSSTTUUVVWWXXYYZZ";
	input = i_stream_create_from_data(data, strlen(data));
	json_tree_node_add_string_stream(jtnode, NULL, input);
	i_stream_unref(&input);
	jtwalker = json_tree_walker_create(jtree);
	test_assert(json_tree_walk(jtwalker, &jnode));
	test_assert(json_node_is_array(&jnode));
	test_assert(json_tree_walk(jtwalker, &jnode));
	test_assert(json_node_is_string(&jnode));
	test_assert(jnode.value.content_type == JSON_CONTENT_TYPE_STREAM);
	test_assert(jnode.value.content.stream != NULL);
	test_stream_value(jnode.value.content.stream, data);
	test_assert(json_tree_walk(jtwalker, &jnode));
	test_assert(json_node_is_array_end(&jnode));
	test_assert(!json_tree_walk(jtwalker, &jnode));
	json_tree_walker_free(&jtwalker);
	json_tree_unref(&jtree);
	test_end();

	/* object */
	test_begin("json tree walker - object");
	jtree = json_tree_create();
	json_tree_node_add_object(json_tree_get_root(jtree), NULL);
	jtwalker = json_tree_walker_create(jtree);
	test_assert(json_tree_walk(jtwalker, &jnode));
	test_assert(json_node_is_object(&jnode));
	test_assert(json_tree_walk(jtwalker, &jnode));
	test_assert(json_node_is_object_end(&jnode));
	test_assert(!json_tree_walk(jtwalker, &jnode));
	json_tree_unref(&jtree);
	json_tree_walker_free(&jtwalker);
	test_end();

	/* { member: string } */
	test_begin("json tree walker - object { member: string }");
	jtree = json_tree_create();
	jtnode = json_tree_node_add_object(json_tree_get_root(jtree), NULL);
	json_tree_node_add_string(jtnode, "frop", "friep");
	jtwalker = json_tree_walker_create(jtree);
	test_assert(json_tree_walk(jtwalker, &jnode));
	test_assert(json_node_is_object(&jnode));
	test_assert(json_tree_walk(jtwalker, &jnode));
	test_assert(json_node_is_string(&jnode));
	test_assert_strcmp(jnode.name, "frop");
	test_assert_strcmp(json_node_get_str(&jnode), "friep");
	test_assert(json_tree_walk(jtwalker, &jnode));
	test_assert(json_node_is_object_end(&jnode));
	test_assert(!json_tree_walk(jtwalker, &jnode));
	json_tree_unref(&jtree);
	json_tree_walker_free(&jtwalker);
	test_end();

	/* { member: string stream } */
	test_begin("json tree walker - object { member: string stream }");
	jtree = json_tree_create();
	jtnode = json_tree_node_add_object(json_tree_get_root(jtree), NULL);
	data = "AABBCCDDEEFFGGHHIIJJKKLLMMNNOOPPQQRRSSTTUUVVWWXXYYZZ";
	input = i_stream_create_from_data(data, strlen(data));
	json_tree_node_add_string_stream(jtnode, "frop", input);
	i_stream_unref(&input);
	jtwalker = json_tree_walker_create(jtree);
	test_assert(json_tree_walk(jtwalker, &jnode));
	test_assert(json_node_is_object(&jnode));
	test_assert(json_tree_walk(jtwalker, &jnode));
	test_assert(json_node_is_string(&jnode));
	test_assert_strcmp(jnode.name, "frop");
	test_assert(jnode.value.content_type == JSON_CONTENT_TYPE_STREAM);
	test_assert(jnode.value.content.stream != NULL);
	test_stream_value(jnode.value.content.stream, data);
	test_assert(json_tree_walk(jtwalker, &jnode));
	test_assert(json_node_is_object_end(&jnode));
	test_assert(!json_tree_walk(jtwalker, &jnode));
	json_tree_walker_free(&jtwalker);
	json_tree_unref(&jtree);
	test_end();

	/* { "a": [{"d": 1}], "b": [{"e": 2}], "c": [{"f": 3}] } */
	test_begin("json tree walker - object { \"a\": [{\"d\": 1}], \"b\": [{\"e\": 2}], \"c\": [{\"f\": 3}] }");
	jtree = json_tree_create();
	jtnode = json_tree_node_add_object(json_tree_get_root(jtree), NULL);
	jtnode = json_tree_node_add_array(jtnode, "a");
	jtnode = json_tree_node_add_object(jtnode, NULL);
	json_tree_node_add_number_int(jtnode, "d", 1);
	jtnode = json_tree_node_get_parent(jtnode);
	jtnode = json_tree_node_get_parent(jtnode);
	jtnode = json_tree_node_add_array(jtnode, "b");
	jtnode = json_tree_node_add_object(jtnode, NULL);
	json_tree_node_add_number_int(jtnode, "e", 2);
	jtnode = json_tree_node_get_parent(jtnode);
	jtnode = json_tree_node_get_parent(jtnode);
	jtnode = json_tree_node_add_array(jtnode, "c");
	jtnode = json_tree_node_add_object(jtnode, NULL);
	json_tree_node_add_number_int(jtnode, "f", 3);
	jtwalker = json_tree_walker_create(jtree);
	test_assert(json_tree_walk(jtwalker, &jnode));
	test_assert(json_node_is_object(&jnode));
	test_assert(json_tree_walk(jtwalker, &jnode));
	test_assert(json_node_is_array(&jnode));
	test_assert_strcmp(jnode.name, "a");
	test_assert(json_tree_walk(jtwalker, &jnode));
	test_assert(json_node_is_object(&jnode));
	test_assert(json_tree_walk(jtwalker, &jnode));
	test_assert(json_node_is_number(&jnode));
	test_assert_strcmp(jnode.name, "d");
	test_assert(json_node_get_intmax(&jnode, &num_val) == 0);
	test_assert(num_val == 1);
	test_assert(json_tree_walk(jtwalker, &jnode));
	test_assert(json_node_is_object_end(&jnode));
	test_assert(json_tree_walk(jtwalker, &jnode));
	test_assert(json_node_is_array_end(&jnode));
	test_assert(json_tree_walk(jtwalker, &jnode));
	test_assert(json_node_is_array(&jnode));
	test_assert_strcmp(jnode.name, "b");
	test_assert(json_tree_walk(jtwalker, &jnode));
	test_assert(json_node_is_object(&jnode));
	test_assert(json_tree_walk(jtwalker, &jnode));
	test_assert(json_node_is_number(&jnode));
	test_assert_strcmp(jnode.name, "e");
	test_assert(json_node_get_intmax(&jnode, &num_val) == 0);
	test_assert(num_val == 2);
	test_assert(json_tree_walk(jtwalker, &jnode));
	test_assert(json_node_is_object_end(&jnode));
	test_assert(json_tree_walk(jtwalker, &jnode));
	test_assert(json_node_is_array_end(&jnode));
	test_assert(json_tree_walk(jtwalker, &jnode));
	test_assert(json_node_is_array(&jnode));
	test_assert_strcmp(jnode.name, "c");
	test_assert(json_tree_walk(jtwalker, &jnode));
	test_assert(json_node_is_object(&jnode));
	test_assert(json_tree_walk(jtwalker, &jnode));
	test_assert(json_node_is_number(&jnode));
	test_assert_strcmp(jnode.name, "f");
	test_assert(json_node_get_intmax(&jnode, &num_val) == 0);
	test_assert(num_val == 3);
	test_assert(json_tree_walk(jtwalker, &jnode));
	test_assert(json_node_is_object_end(&jnode));
	test_assert(json_tree_walk(jtwalker, &jnode));
	test_assert(json_node_is_array_end(&jnode));
	test_assert(json_tree_walk(jtwalker, &jnode));
	test_assert(json_node_is_object_end(&jnode));
	test_assert(!json_tree_walk(jtwalker, &jnode));
	json_tree_unref(&jtree);
	json_tree_walker_free(&jtwalker);
	test_end();

	/* { "a": [{"d": 1}], "b": [{"e": 2}], "c": [{"f": 3}] } */
	test_begin("json tree walker - nested trees");
	jtree = json_tree_create();
	jtnode = json_tree_get_root(jtree);
	json_tree_node_add_object(jtnode, NULL);
	jtree2 = json_tree_create();
	jtnode = json_tree_get_root(jtree2);
	jtnode = json_tree_node_add_array(jtnode, NULL);
	jtnode = json_tree_node_add_object(jtnode, NULL);
	json_tree_node_add_number_int(jtnode, "d", 1);
	jtnode = json_tree_get_root(jtree);
	json_tree_node_add_subtree(jtnode, "a", jtree2);
	json_tree_unref(&jtree2);
	jtree2 = json_tree_create();
	jtnode = json_tree_get_root(jtree2);
	jtnode = json_tree_node_add_array(jtnode, NULL);
	jtnode = json_tree_node_add_object(jtnode, NULL);
	json_tree_node_add_number_int(jtnode, "e", 2);
	jtnode = json_tree_get_root(jtree);
	json_tree_node_add_subtree(jtnode, "b", jtree2);
	json_tree_unref(&jtree2);
	jtree2 = json_tree_create();
	jtnode = json_tree_get_root(jtree2);
	jtnode = json_tree_node_add_array(jtnode, NULL);
	jtnode = json_tree_node_add_object(jtnode, NULL);
	json_tree_node_add_number_int(jtnode, "f", 3);
	jtnode = json_tree_get_root(jtree);
	json_tree_node_add_subtree(jtnode, "c", jtree2);
	json_tree_unref(&jtree2);
	jtwalker = json_tree_walker_create(jtree);
	test_assert(json_tree_walk(jtwalker, &jnode));
	test_assert(json_node_is_object(&jnode));
	test_assert(json_tree_walk(jtwalker, &jnode));
	test_assert(json_node_is_array(&jnode));
	test_assert_strcmp(jnode.name, "a");
	test_assert(json_tree_walk(jtwalker, &jnode));
	test_assert(json_node_is_object(&jnode));
	test_assert(json_tree_walk(jtwalker, &jnode));
	test_assert(json_node_is_number(&jnode));
	test_assert_strcmp(jnode.name, "d");
	test_assert(json_node_get_intmax(&jnode, &num_val) == 0);
	test_assert(num_val == 1);
	test_assert(json_tree_walk(jtwalker, &jnode));
	test_assert(json_node_is_object_end(&jnode));
	test_assert(json_tree_walk(jtwalker, &jnode));
	test_assert(json_node_is_array_end(&jnode));
	test_assert(json_tree_walk(jtwalker, &jnode));
	test_assert(json_node_is_array(&jnode));
	test_assert_strcmp(jnode.name, "b");
	test_assert(json_tree_walk(jtwalker, &jnode));
	test_assert(json_node_is_object(&jnode));
	test_assert(json_tree_walk(jtwalker, &jnode));
	test_assert(json_node_is_number(&jnode));
	test_assert_strcmp(jnode.name, "e");
	test_assert(json_node_get_intmax(&jnode, &num_val) == 0);
	test_assert(num_val == 2);
	test_assert(json_tree_walk(jtwalker, &jnode));
	test_assert(json_node_is_object_end(&jnode));
	test_assert(json_tree_walk(jtwalker, &jnode));
	test_assert(json_node_is_array_end(&jnode));
	test_assert(json_tree_walk(jtwalker, &jnode));
	test_assert(json_node_is_array(&jnode));
	test_assert_strcmp(jnode.name, "c");
	test_assert(json_tree_walk(jtwalker, &jnode));
	test_assert(json_node_is_object(&jnode));
	test_assert(json_tree_walk(jtwalker, &jnode));
	test_assert(json_node_is_number(&jnode));
	test_assert_strcmp(jnode.name, "f");
	test_assert(json_node_get_intmax(&jnode, &num_val) == 0);
	test_assert(num_val == 3);
	test_assert(json_tree_walk(jtwalker, &jnode));
	test_assert(json_node_is_object_end(&jnode));
	test_assert(json_tree_walk(jtwalker, &jnode));
	test_assert(json_node_is_array_end(&jnode));
	test_assert(json_tree_walk(jtwalker, &jnode));
	test_assert(json_node_is_object_end(&jnode));
	test_assert(!json_tree_walk(jtwalker, &jnode));
	json_tree_walker_free(&jtwalker);
	json_tree_unref(&jtree);
	test_end();

	/* { "a": [{"d": 1}], "b": [{"e": 2}], "c": [{"f": 3}] } */
	test_begin("json tree walker - doubly nested trees");
	jtree = json_tree_create();
	jtnode = json_tree_get_root(jtree);
	json_tree_node_add_object(jtnode, NULL);
	jtree2 = json_tree_create();
	jtnode = json_tree_get_root(jtree2);
	json_tree_node_add_array(jtnode, NULL);
	jtree3 = json_tree_create();
	jtnode = json_tree_get_root(jtree3);
	jtnode = json_tree_node_add_object(jtnode, NULL);
	json_tree_node_add_number_int(jtnode, "d", 1);
	jtnode = json_tree_get_root(jtree2);
	json_tree_node_add_subtree(jtnode, NULL, jtree3);
	json_tree_unref(&jtree3);
	jtnode = json_tree_get_root(jtree);
	json_tree_node_add_subtree(jtnode, "a", jtree2);
	json_tree_unref(&jtree2);
	jtree2 = json_tree_create();
	jtnode = json_tree_get_root(jtree2);
	json_tree_node_add_array(jtnode, NULL);
	jtree3 = json_tree_create();
	jtnode = json_tree_get_root(jtree3);
	jtnode = json_tree_node_add_object(jtnode, NULL);
	json_tree_node_add_number_int(jtnode, "e", 2);
	jtnode = json_tree_get_root(jtree2);
	json_tree_node_add_subtree(jtnode, NULL, jtree3);
	json_tree_unref(&jtree3);
	jtnode = json_tree_get_root(jtree);
	json_tree_node_add_subtree(jtnode, "b", jtree2);
	json_tree_unref(&jtree2);
	jtree2 = json_tree_create();
	jtnode = json_tree_get_root(jtree2);
	json_tree_node_add_array(jtnode, NULL);
	jtree3 = json_tree_create();
	jtnode = json_tree_get_root(jtree3);
	jtnode = json_tree_node_add_object(jtnode, NULL);
	json_tree_node_add_number_int(jtnode, "f", 3);
	jtnode = json_tree_get_root(jtree2);
	json_tree_node_add_subtree(jtnode, NULL, jtree3);
	json_tree_unref(&jtree3);
	jtnode = json_tree_get_root(jtree);
	json_tree_node_add_subtree(jtnode, "c", jtree2);
	json_tree_unref(&jtree2);
	jtwalker = json_tree_walker_create(jtree);
	test_assert(json_tree_walk(jtwalker, &jnode));
	test_assert(json_node_is_object(&jnode));
	test_assert(json_tree_walk(jtwalker, &jnode));
	test_assert(json_node_is_array(&jnode));
	test_assert_strcmp(jnode.name, "a");
	test_assert(json_tree_walk(jtwalker, &jnode));
	test_assert(json_node_is_object(&jnode));
	test_assert(json_tree_walk(jtwalker, &jnode));
	test_assert(json_node_is_number(&jnode));
	test_assert_strcmp(jnode.name, "d");
	test_assert(json_node_get_intmax(&jnode, &num_val) == 0);
	test_assert(num_val == 1);
	test_assert(json_tree_walk(jtwalker, &jnode));
	test_assert(json_node_is_object_end(&jnode));
	test_assert(json_tree_walk(jtwalker, &jnode));
	test_assert(json_node_is_array_end(&jnode));
	test_assert(json_tree_walk(jtwalker, &jnode));
	test_assert(json_node_is_array(&jnode));
	test_assert_strcmp(jnode.name, "b");
	test_assert(json_tree_walk(jtwalker, &jnode));
	test_assert(json_node_is_object(&jnode));
	test_assert(json_tree_walk(jtwalker, &jnode));
	test_assert(json_node_is_number(&jnode));
	test_assert_strcmp(jnode.name, "e");
	test_assert(json_node_get_intmax(&jnode, &num_val) == 0);
	test_assert(num_val == 2);
	test_assert(json_tree_walk(jtwalker, &jnode));
	test_assert(json_node_is_object_end(&jnode));
	test_assert(json_tree_walk(jtwalker, &jnode));
	test_assert(json_node_is_array_end(&jnode));
	test_assert(json_tree_walk(jtwalker, &jnode));
	test_assert(json_node_is_array(&jnode));
	test_assert_strcmp(jnode.name, "c");
	test_assert(json_tree_walk(jtwalker, &jnode));
	test_assert(json_node_is_object(&jnode));
	test_assert(json_tree_walk(jtwalker, &jnode));
	test_assert(json_node_is_number(&jnode));
	test_assert_strcmp(jnode.name, "f");
	test_assert(json_node_get_intmax(&jnode, &num_val) == 0);
	test_assert(num_val == 3);
	test_assert(json_tree_walk(jtwalker, &jnode));
	test_assert(json_node_is_object_end(&jnode));
	test_assert(json_tree_walk(jtwalker, &jnode));
	test_assert(json_node_is_array_end(&jnode));
	test_assert(json_tree_walk(jtwalker, &jnode));
	test_assert(json_node_is_object_end(&jnode));
	test_assert(!json_tree_walk(jtwalker, &jnode));
	json_tree_walker_free(&jtwalker);
	json_tree_unref(&jtree);
	test_end();
}

int main(int argc, char *argv[])
{
	int c;

	static void (*test_functions[])(void) = {
		test_json_tree_walker,
		NULL
	};

	while ((c = getopt(argc, argv, "D")) > 0) {
		switch (c) {
		case 'D':
			debug = TRUE;
			break;
		default:
			i_fatal("Usage: %s [-D]", argv[0]);
		}
	}

	return test_run(test_functions);
}
