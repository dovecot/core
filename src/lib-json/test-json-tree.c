/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "lib.h"
#include "str.h"
#include "istream.h"
#include "ostream.h"
#include "test-common.h"

#include "json-tree.h"
#include "json-tree-io.h"
#include "json-istream.h"

#include <unistd.h>

static bool debug = FALSE;

static void test_stream_value(struct istream *val_input, const char *expected)
{
	const unsigned char *data;
	size_t size;
	string_t *buffer;
	int ret;

	buffer = t_str_new(256);

	while ((ret = i_stream_read_more(val_input, &data, &size)) > 0) {
		str_append_data(buffer, data, size);
		i_stream_skip(val_input, size);
	}
	if (ret < 0)
		test_assert(!i_stream_have_bytes_left(val_input));

	test_assert_strcmp(str_c(buffer), expected);
}

static void test_stream_data(struct istream *val_input,
			     const unsigned char *expected, size_t size)
{
	const unsigned char *data;
	size_t rsize;
	string_t *buffer;
	int ret;

	buffer = t_str_new(256);

	while ((ret = i_stream_read_more(val_input, &data, &rsize)) > 0) {
		str_append_data(buffer, data, rsize);
		i_stream_skip(val_input, rsize);
	}
	if (ret < 0)
		test_assert(!i_stream_have_bytes_left(val_input));

	test_assert_memcmp(str_data(buffer), str_len(buffer), expected, size);
}

static void test_json_tree_object(void)
{
	struct json_tree *jtree, *jtree2;
	struct json_tree_node *jtnode, *root;
	pool_t pool;

	/* empty tree */
	test_begin("json tree - empty tree");
	jtree = json_tree_create();
	root = json_tree_get_root(jtree);
	test_assert(root != NULL);
	test_assert(json_tree_get_root_const(jtree) == root);
	test_assert(json_tree_node_is_root(root));
	test_assert_cmp(json_tree_node_get_type(root), ==, JSON_TYPE_NONE);
	test_assert(json_tree_node_get_name(root) == NULL);
	test_assert(json_tree_node_get_parent(root) == NULL);
	test_assert(json_tree_node_get_next(root) == NULL);
	test_assert(json_tree_node_get_tree(root) == jtree);
	test_assert(json_tree_node_get_tree_const(root) == jtree);
	test_assert(!json_tree_is_object(jtree));
	test_assert(!json_tree_is_array(jtree));
	test_assert(!json_tree_is_string(jtree));
	test_assert(!json_tree_is_number(jtree));
	test_assert(!json_tree_is_true(jtree));
	test_assert(!json_tree_is_false(jtree));
	test_assert(!json_tree_is_boolean(jtree));
	test_assert(!json_tree_is_null(jtree));
	json_tree_unref(&jtree);
	test_assert(jtree == NULL);
	test_end();

	/* create with pool */
	test_begin("json tree - create with pool");
	pool = pool_alloconly_create("test json tree", 1024);
	jtree = json_tree_create_pool(pool);
	/* tree holds its own reference to the pool */
	pool_unref(&pool);
	json_tree_node_add_string(json_tree_get_root(jtree), NULL, "frop");
	test_assert(json_tree_is_string(jtree));
	test_assert_strcmp(json_tree_node_get_str(json_tree_get_root(jtree)),
			   "frop");
	json_tree_unref(&jtree);
	test_end();

	/* references */
	test_begin("json tree - references");
	jtree = json_tree_create();
	json_tree_node_add_true(json_tree_get_root(jtree), NULL);
	json_tree_ref(jtree);
	jtree2 = jtree;
	json_tree_unref(&jtree2);
	test_assert(jtree2 == NULL);
	/* the tree is still alive */
	test_assert(json_tree_is_true(jtree));
	json_tree_unref(&jtree);
	test_assert(jtree == NULL);
	/* unref of NULL is a no-op */
	json_tree_unref(&jtree);
	test_end();

	/* create object */
	test_begin("json tree - create object");
	jtree = json_tree_create_object(&root);
	test_assert(root == json_tree_get_root(jtree));
	test_assert(json_tree_is_object(jtree));
	test_assert(json_tree_node_is_object(root));
	test_assert_ucmp(json_tree_node_get_child_count(root), ==, 0);
	test_assert(json_tree_node_get_child(root) == NULL);
	test_assert(json_tree_node_get_nth_child(root, 0) == NULL);
	test_assert(json_tree_node_get_member(root, "frop") == NULL);
	test_assert(json_tree_node_get_child_with(root, "frop",
						  "friep") == NULL);
	jtnode = json_tree_node_add_string(root, "frop", "friep");
	test_assert(!json_tree_node_is_root(jtnode));
	test_assert(json_tree_node_get_parent(jtnode) == root);
	test_assert_ucmp(json_tree_node_get_child_count(root), ==, 1);
	json_tree_unref(&jtree);
	test_end();

	/* create array */
	test_begin("json tree - create array");
	jtree = json_tree_create_array(&root);
	test_assert(root == json_tree_get_root(jtree));
	test_assert(json_tree_is_array(jtree));
	test_assert(json_tree_node_is_array(root));
	test_assert_ucmp(json_tree_node_get_child_count(root), ==, 0);
	jtnode = json_tree_node_add_string(root, NULL, "frop");
	test_assert(json_tree_node_get_name(jtnode) == NULL);
	test_assert_ucmp(json_tree_node_get_child_count(root), ==, 1);
	json_tree_unref(&jtree);
	test_end();

	/* tree type predicates */
	test_begin("json tree - type predicates");
	jtree = json_tree_create();
	json_tree_node_add_number_int(json_tree_get_root(jtree), NULL, 42);
	test_assert(json_tree_is_number(jtree));
	test_assert(!json_tree_is_string(jtree));
	json_tree_unref(&jtree);
	jtree = json_tree_create();
	json_tree_node_add_true(json_tree_get_root(jtree), NULL);
	test_assert(json_tree_is_true(jtree));
	test_assert(json_tree_is_boolean(jtree));
	test_assert(!json_tree_is_false(jtree));
	json_tree_unref(&jtree);
	jtree = json_tree_create();
	json_tree_node_add_false(json_tree_get_root(jtree), NULL);
	test_assert(json_tree_is_false(jtree));
	test_assert(json_tree_is_boolean(jtree));
	test_assert(!json_tree_is_true(jtree));
	json_tree_unref(&jtree);
	jtree = json_tree_create();
	json_tree_node_add_null(json_tree_get_root(jtree), NULL);
	test_assert(json_tree_is_null(jtree));
	test_assert(!json_tree_is_boolean(jtree));
	json_tree_unref(&jtree);
	test_end();
}

static void test_json_tree_node_add(void)
{
	static const unsigned char data[] = "AA\0BB";
	struct json_tree *jtree, *jtree2;
	struct json_tree_node *root, *jtnode;
	struct json_value jvalue;
	struct json_node jnode;
	const unsigned char *rdata;
	size_t rsize;
	intmax_t num_val = 0;

	/* root substitution */
	test_begin("json tree node add - root substitution");
	jtree = json_tree_create();
	/* the first added node replaces the root; the name is ignored */
	jtnode = json_tree_node_add_string(json_tree_get_root(jtree),
					   "frop", "friep");
	test_assert(jtnode == json_tree_get_root(jtree));
	test_assert(json_tree_node_is_root(jtnode));
	test_assert(json_tree_node_get_name(jtnode) == NULL);
	test_assert_strcmp(json_tree_node_get_str(jtnode), "friep");
	json_tree_unref(&jtree);
	test_end();

	/* json_tree_node_add() */
	test_begin("json tree node add - node");
	jtree = json_tree_create_object(&root);
	i_zero(&jnode);
	jnode.name = "frop";
	jnode.type = JSON_TYPE_STRING;
	jnode.value.content_type = JSON_CONTENT_TYPE_STRING;
	jnode.value.content.str = "friep";
	jtnode = json_tree_node_add(root, &jnode);
	test_assert(json_tree_node_is_string(jtnode));
	test_assert_strcmp(json_tree_node_get_name(jtnode), "frop");
	test_assert_strcmp(json_tree_node_get_str(jtnode), "friep");
	json_tree_unref(&jtree);
	test_end();

	/* json_tree_node_add_value() */
	test_begin("json tree node add - value");
	jtree = json_tree_create_object(&root);
	i_zero(&jvalue);
	jvalue.content_type = JSON_CONTENT_TYPE_INTEGER;
	jvalue.content.intnum = -23423;
	jtnode = json_tree_node_add_value(root, "frop", JSON_TYPE_NUMBER,
					  &jvalue);
	test_assert(json_tree_node_is_number(jtnode));
	test_assert_cmp(json_tree_node_get_intmax(jtnode, &num_val), ==, 0);
	test_assert_cmp(num_val, ==, -23423);
	/* a list value is equivalent to adding an object */
	i_zero(&jvalue);
	jvalue.content_type = JSON_CONTENT_TYPE_LIST;
	jtnode = json_tree_node_add_value(root, "friep", JSON_TYPE_OBJECT,
					  &jvalue);
	test_assert(json_tree_node_is_object(jtnode));
	test_assert_ucmp(json_tree_node_get_child_count(jtnode), ==, 0);
	json_tree_node_add_string(jtnode, "frml", "frop");
	test_assert_ucmp(json_tree_node_get_child_count(jtnode), ==, 1);
	json_tree_unref(&jtree);
	test_end();

	/* json_tree_node_add_data() */
	test_begin("json tree node add - data");
	jtree = json_tree_create_object(&root);
	jtnode = json_tree_node_add_data(root, "frop", data, sizeof(data) - 1);
	test_assert(json_tree_node_is_string(jtnode));
	test_assert_cmp(json_tree_node_get_type(jtnode), ==, JSON_TYPE_STRING);
	rdata = json_tree_node_get_data(jtnode, &rsize);
	test_assert_memcmp(rdata, rsize, data, sizeof(data) - 1);
	/* the data is copied into the tree pool */
	test_assert(rdata != data);
	json_tree_unref(&jtree);
	test_end();

	/* json_tree_node_add_number_str() */
	test_begin("json tree node add - number string");
	jtree = json_tree_create_object(&root);
	jtnode = json_tree_node_add_number_str(root, "frop", "1.0e+23");
	test_assert(json_tree_node_is_number(jtnode));
	test_assert_strcmp(json_tree_node_get_str(jtnode), "1.0e+23");
	/* it is not an integer, so it cannot be read as a number */
	test_assert_cmp(json_tree_node_get_intmax(jtnode, &num_val), <, 0);
	json_tree_unref(&jtree);
	test_end();

	/* json_tree_node_add_boolean() */
	test_begin("json tree node add - boolean");
	jtree = json_tree_create_object(&root);
	jtnode = json_tree_node_add_boolean(root, "frop", TRUE);
	test_assert(json_tree_node_is_true(jtnode));
	test_assert(json_tree_node_is_boolean(jtnode));
	test_assert(!json_tree_node_is_false(jtnode));
	test_assert_cmp(json_tree_node_get_type(jtnode), ==, JSON_TYPE_TRUE);
	jtnode = json_tree_node_add_boolean(root, "friep", FALSE);
	test_assert(json_tree_node_is_false(jtnode));
	test_assert(json_tree_node_is_boolean(jtnode));
	test_assert(!json_tree_node_is_true(jtnode));
	test_assert_cmp(json_tree_node_get_type(jtnode), ==, JSON_TYPE_FALSE);
	json_tree_unref(&jtree);
	test_end();

	/* json_tree_node_add_text() */
	test_begin("json tree node add - text");
	jtree = json_tree_create_object(&root);
	jtnode = json_tree_node_add_text(root, "frop", "[1,2,3]");
	test_assert_cmp(json_tree_node_get_type(jtnode), ==, JSON_TYPE_TEXT);
	test_assert(!json_tree_node_is_string(jtnode));
	test_assert(!json_tree_node_is_array(jtnode));
	test_assert_strcmp(json_tree_node_get_str(jtnode), "[1,2,3]");
	jtnode = json_tree_node_add_text_data(root, "friep",
					      data, sizeof(data) - 1);
	test_assert_cmp(json_tree_node_get_type(jtnode), ==, JSON_TYPE_TEXT);
	rdata = json_tree_node_get_data(jtnode, &rsize);
	test_assert_memcmp(rdata, rsize, data, sizeof(data) - 1);
	json_tree_unref(&jtree);
	test_end();

	/* json_tree_node_add_subtree() */
	test_begin("json tree node add - subtree");
	jtree = json_tree_create_object(&root);
	jtree2 = json_tree_create_array(&jtnode);
	json_tree_node_add_number_int(jtnode, NULL, 1);
	jtnode = json_tree_node_add_subtree(root, "frop", jtree2);
	/* the subtree is referenced by the parent tree */
	json_tree_unref(&jtree2);
	test_assert_cmp(json_tree_node_get_type(jtnode), ==, JSON_TYPE_TEXT);
	test_assert(!json_tree_node_is_array(jtnode));
	test_assert_strcmp(json_tree_node_get_name(jtnode), "frop");
	test_assert(json_tree_node_get_member(root, "frop") == jtnode);
	json_tree_unref(&jtree);
	test_end();
}

static void test_json_tree_node_inspect(void)
{
	struct json_tree *jtree;
	struct json_tree_node *root, *jtnode, *child;

	/* { "a": 1, "b": "frop", "c": [ 1, 2, 3 ] } */
	test_begin("json tree node inspect - object");
	jtree = json_tree_create_object(&root);
	json_tree_node_add_number_int(root, "a", 1);
	json_tree_node_add_string(root, "b", "frop");
	jtnode = json_tree_node_add_array(root, "c");
	json_tree_node_add_number_int(jtnode, NULL, 1);
	json_tree_node_add_number_int(jtnode, NULL, 2);
	json_tree_node_add_number_int(jtnode, NULL, 3);

	test_assert_ucmp(json_tree_node_get_child_count(root), ==, 3);
	child = json_tree_node_get_child(root);
	test_assert(child != NULL);
	test_assert(json_tree_node_get_child(root) ==
		    json_tree_node_get_nth_child(root, 0));
	test_assert_strcmp(json_tree_node_get_name(child), "a");
	test_assert(json_tree_node_get_parent(child) == root);
	test_assert(json_tree_node_get_tree(child) == jtree);
	test_assert(json_tree_node_get(child) != NULL);
	test_assert(json_node_is_number(json_tree_node_get(child)));

	child = json_tree_node_get_next(child);
	test_assert(child == json_tree_node_get_nth_child(root, 1));
	test_assert_strcmp(json_tree_node_get_name(child), "b");
	child = json_tree_node_get_next(child);
	test_assert(child == json_tree_node_get_nth_child(root, 2));
	test_assert_strcmp(json_tree_node_get_name(child), "c");
	test_assert(json_tree_node_get_next(child) == NULL);
	test_assert(json_tree_node_get_nth_child(root, 3) == NULL);
	test_assert(json_tree_node_get_nth_child(root, 100) == NULL);

	test_assert(json_tree_node_get_member(root, "a") ==
		    json_tree_node_get_nth_child(root, 0));
	test_assert(json_tree_node_get_member(root, "c") == child);
	test_assert(json_tree_node_get_member(root, "d") == NULL);

	/* array child */
	jtnode = json_tree_node_get_member(root, "c");
	test_assert(json_tree_node_is_array(jtnode));
	test_assert_ucmp(json_tree_node_get_child_count(jtnode), ==, 3);
	test_assert(json_tree_node_get_nth_child(jtnode, 2) != NULL);
	test_assert(json_tree_node_get_name(
		json_tree_node_get_nth_child(jtnode, 2)) == NULL);
	test_assert(json_tree_node_get_nth_child(jtnode, 3) == NULL);
	json_tree_unref(&jtree);
	test_end();

	/* [ { "a": "1" }, { "a": "2" }, { "b": "3" }, [ ], { "a": 4 },
	     { "a": <DATA "5"> } ] */
	test_begin("json tree node inspect - child with");
	jtree = json_tree_create_array(&root);
	jtnode = json_tree_node_add_object(root, NULL);
	json_tree_node_add_string(jtnode, "a", "1");
	jtnode = json_tree_node_add_object(root, NULL);
	json_tree_node_add_string(jtnode, "a", "2");
	jtnode = json_tree_node_add_object(root, NULL);
	json_tree_node_add_string(jtnode, "b", "3");
	/* not an object */
	json_tree_node_add_array(root, NULL);
	/* member is not a string */
	jtnode = json_tree_node_add_object(root, NULL);
	json_tree_node_add_number_int(jtnode, "a", 4);
	/* member is a DATA-content string, not STRING-content, but is
	   still directly comparable */
	jtnode = json_tree_node_add_object(root, NULL);
	json_tree_node_add_data(jtnode, "a", (const unsigned char *)"5", 1);

	jtnode = json_tree_node_get_child_with(root, "a", "1");
	test_assert(jtnode == json_tree_node_get_nth_child(root, 0));
	jtnode = json_tree_node_get_child_with(root, "a", "2");
	test_assert(jtnode == json_tree_node_get_nth_child(root, 1));
	/* no child has this value */
	test_assert(json_tree_node_get_child_with(root, "a", "3") == NULL);
	/* no child has this member as a string */
	test_assert(json_tree_node_get_child_with(root, "b", "4") == NULL);
	test_assert(json_tree_node_get_child_with(root, "c", "1") == NULL);
	/* DATA-content member is found like a STRING-content one */
	jtnode = json_tree_node_get_child_with(root, "a", "5");
	test_assert(jtnode == json_tree_node_get_nth_child(root, 5));
	json_tree_unref(&jtree);
	test_end();
}

static void test_json_tree_node_value(void)
{
	static const unsigned char data[] = "AA\0BB";
	const char *str = "AABBCCDDEEFFGGHHIIJJKKLLMMNNOOPPQQRRSSTTUUVVWWXXYYZZ";
	struct json_tree *jtree;
	struct json_tree_node *root, *jtnode;
	struct istream *input, *val_input;
	intmax_t num_val = 0;
	uintmax_t unum_val = 0;
	int num_int = 0;
	long num_long = 0;
	long long num_llong = 0;
	int32_t num32_val = 0;
	int64_t num64_val = 0;
	unsigned int unum_int = 0;
	unsigned long unum_long = 0;
	unsigned long long unum_llong = 0;
	uint32_t unum32_val = 0;
	uint64_t unum64_val = 0;

	/* string values */
	test_begin("json tree node value - string");
	jtree = json_tree_create_object(&root);
	jtnode = json_tree_node_add_string(root, "frop", "friep");
	test_assert_strcmp(json_tree_node_get_str(jtnode), "friep");
	test_assert_strcmp(json_tree_node_as_str(jtnode), "friep");
	test_assert(json_tree_node_get_str_istream(jtnode, &val_input) == 0);
	test_stream_value(val_input, "friep");
	i_stream_unref(&val_input);
	json_tree_unref(&jtree);
	test_end();

	/* data values */
	test_begin("json tree node value - data");
	jtree = json_tree_create_object(&root);
	jtnode = json_tree_node_add_data(root, "frop", data, sizeof(data) - 1);
	test_assert(json_tree_node_get_str_istream(jtnode, &val_input) == 0);
	test_stream_data(val_input, data, sizeof(data) - 1);
	i_stream_unref(&val_input);
	json_tree_unref(&jtree);
	test_end();

	/* stream values */
	test_begin("json tree node value - stream");
	jtree = json_tree_create_object(&root);
	input = i_stream_create_from_data(str, strlen(str));
	jtnode = json_tree_node_add_string_stream(root, "frop", input);
	i_stream_unref(&input);
	test_assert(json_tree_node_get_str_istream(jtnode, &val_input) == 0);
	test_stream_value(val_input, str);
	i_stream_unref(&val_input);
	/* each call yields an independent stream */
	test_assert(json_tree_node_get_str_istream(jtnode, &val_input) == 0);
	test_stream_value(val_input, str);
	i_stream_unref(&val_input);
	json_tree_unref(&jtree);
	test_end();

	/* number values */
	test_begin("json tree node value - number");
	jtree = json_tree_create_object(&root);
	jtnode = json_tree_node_add_number_int(root, "frop", 23423);
	test_assert_cmp(json_tree_node_get_intmax(jtnode, &num_val), ==, 0);
	test_assert_cmp(num_val, ==, 23423);
	test_assert_cmp(json_tree_node_get_int(jtnode, &num_int), ==, 0);
	test_assert_cmp(num_int, ==, 23423);
	test_assert_cmp(json_tree_node_get_long(jtnode, &num_long), ==, 0);
	test_assert_cmp(num_long, ==, 23423);
	test_assert_cmp(json_tree_node_get_llong(jtnode, &num_llong), ==, 0);
	test_assert_cmp(num_llong, ==, 23423);
	test_assert_cmp(json_tree_node_get_int32(jtnode, &num32_val), ==, 0);
	test_assert_cmp(num32_val, ==, 23423);
	test_assert_cmp(json_tree_node_get_int64(jtnode, &num64_val), ==, 0);
	test_assert_cmp(num64_val, ==, 23423);
	test_assert_cmp(json_tree_node_get_uintmax(jtnode, &unum_val), ==, 0);
	test_assert_ucmp(unum_val, ==, 23423);
	test_assert_cmp(json_tree_node_get_uint(jtnode, &unum_int), ==, 0);
	test_assert_ucmp(unum_int, ==, 23423);
	test_assert_cmp(json_tree_node_get_ulong(jtnode, &unum_long), ==, 0);
	test_assert_ucmp(unum_long, ==, 23423);
	test_assert_cmp(json_tree_node_get_ullong(jtnode, &unum_llong), ==, 0);
	test_assert_ucmp(unum_llong, ==, 23423);
	test_assert_cmp(json_tree_node_get_uint32(jtnode, &unum32_val), ==, 0);
	test_assert_ucmp(unum32_val, ==, 23423);
	test_assert_cmp(json_tree_node_get_uint64(jtnode, &unum64_val), ==, 0);
	test_assert_ucmp(unum64_val, ==, 23423);
	test_assert_strcmp(json_tree_node_as_str(jtnode), "23423");

	/* value out of range for the smaller types */
	jtnode = json_tree_node_add_number_int(root, "friep", 5000000000);
	test_assert_cmp(json_tree_node_get_int64(jtnode, &num64_val), ==, 0);
	test_assert_cmp(num64_val, ==, 5000000000);
	test_assert_cmp(json_tree_node_get_int32(jtnode, &num32_val), <, 0);
	test_assert_cmp(json_tree_node_get_uint32(jtnode, &unum32_val), <, 0);
	test_assert_cmp(json_tree_node_get_uint64(jtnode, &unum64_val), ==, 0);
	test_assert_ucmp(unum64_val, ==, 5000000000);

	/* negative value cannot be read as unsigned */
	i_zero(&num_val);
	jtnode = json_tree_node_add_value(root, "frml", JSON_TYPE_NUMBER,
		&(struct json_value){
			.content_type = JSON_CONTENT_TYPE_INTEGER,
			.content = { .intnum = -1 },
		});
	test_assert_cmp(json_tree_node_get_intmax(jtnode, &num_val), ==, 0);
	test_assert_cmp(num_val, ==, -1);
	test_assert_cmp(json_tree_node_get_int(jtnode, &num_int), ==, 0);
	test_assert_cmp(num_int, ==, -1);
	test_assert_cmp(json_tree_node_get_uintmax(jtnode, &unum_val), <, 0);
	test_assert_cmp(json_tree_node_get_uint(jtnode, &unum_int), <, 0);
	test_assert_cmp(json_tree_node_get_ulong(jtnode, &unum_long), <, 0);
	test_assert_cmp(json_tree_node_get_ullong(jtnode, &unum_llong), <, 0);

	/* non-numbers cannot be read as numbers */
	jtnode = json_tree_node_add_string(root, "frul", "frop");
	test_assert_cmp(json_tree_node_get_intmax(jtnode, &num_val), <, 0);
	json_tree_unref(&jtree);
	test_end();

	/* literal values */
	test_begin("json tree node value - literals");
	jtree = json_tree_create_object(&root);
	jtnode = json_tree_node_add_true(root, "frop");
	test_assert_strcmp(json_tree_node_get_str(jtnode), "true");
	jtnode = json_tree_node_add_false(root, "friep");
	test_assert_strcmp(json_tree_node_get_str(jtnode), "false");
	jtnode = json_tree_node_add_null(root, "frml");
	test_assert_strcmp(json_tree_node_get_str(jtnode), "null");
	test_assert(json_tree_node_is_null(jtnode));
	json_tree_unref(&jtree);
	test_end();
}

static void test_json_tree_walker_from_node(void)
{
	struct json_tree *jtree;
	struct json_tree_node *root, *jtnode;
	struct json_tree_walker *jtwalker;
	struct json_node jnode;
	intmax_t num_val = 0;

	/* { "a": [ 1, 2 ], "b": "frop" } walked from the "a" member */
	test_begin("json tree walker - from node");
	jtree = json_tree_create_object(&root);
	jtnode = json_tree_node_add_array(root, "a");
	json_tree_node_add_number_int(jtnode, NULL, 1);
	json_tree_node_add_number_int(jtnode, NULL, 2);
	json_tree_node_add_string(root, "b", "frop");

	jtwalker = json_tree_walker_create_from_node(jtnode);
	test_assert(json_tree_walk(jtwalker, &jnode));
	test_assert(json_node_is_array(&jnode));
	test_assert_strcmp(jnode.name, "a");
	test_assert(json_tree_walk(jtwalker, &jnode));
	test_assert(json_node_is_number(&jnode));
	test_assert_cmp(json_node_get_intmax(&jnode, &num_val), ==, 0);
	test_assert_cmp(num_val, ==, 1);
	test_assert(json_tree_walk(jtwalker, &jnode));
	test_assert(json_node_is_number(&jnode));
	test_assert_cmp(json_node_get_intmax(&jnode, &num_val), ==, 0);
	test_assert_cmp(num_val, ==, 2);
	test_assert(json_tree_walk(jtwalker, &jnode));
	test_assert(json_node_is_array_end(&jnode));
	/* the "b" sibling is not part of the walk */
	test_assert(!json_tree_walk(jtwalker, &jnode));
	json_tree_walker_free(&jtwalker);
	test_assert(jtwalker == NULL);
	json_tree_unref(&jtree);
	test_end();

	/* single value node */
	test_begin("json tree walker - from value node");
	jtree = json_tree_create_object(&root);
	jtnode = json_tree_node_add_string(root, "a", "frop");
	jtwalker = json_tree_walker_create_from_node(jtnode);
	test_assert(json_tree_walk(jtwalker, &jnode));
	test_assert(json_node_is_string(&jnode));
	test_assert_strcmp(json_node_get_str(&jnode), "frop");
	test_assert(!json_tree_walk(jtwalker, &jnode));
	json_tree_walker_free(&jtwalker);
	json_tree_unref(&jtree);
	test_end();
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
	test_assert_cmp(json_node_get_intmax(&jnode, &num_val), ==, 0);
	test_assert_cmp(num_val, ==, 23423);
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
	test_assert_cmp(jnode.value.content_type, ==,
			JSON_CONTENT_TYPE_STREAM);
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
	test_assert_cmp(jnode.value.content_type, ==,
			JSON_CONTENT_TYPE_STREAM);
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
	test_assert_cmp(jnode.value.content_type, ==,
			JSON_CONTENT_TYPE_STREAM);
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
	test_assert_cmp(json_node_get_intmax(&jnode, &num_val), ==, 0);
	test_assert_cmp(num_val, ==, 1);
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
	test_assert_cmp(json_node_get_intmax(&jnode, &num_val), ==, 0);
	test_assert_cmp(num_val, ==, 2);
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
	test_assert_cmp(json_node_get_intmax(&jnode, &num_val), ==, 0);
	test_assert_cmp(num_val, ==, 3);
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
	test_assert_cmp(json_node_get_intmax(&jnode, &num_val), ==, 0);
	test_assert_cmp(num_val, ==, 1);
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
	test_assert_cmp(json_node_get_intmax(&jnode, &num_val), ==, 0);
	test_assert_cmp(num_val, ==, 2);
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
	test_assert_cmp(json_node_get_intmax(&jnode, &num_val), ==, 0);
	test_assert_cmp(num_val, ==, 3);
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
	test_assert_cmp(json_node_get_intmax(&jnode, &num_val), ==, 0);
	test_assert_cmp(num_val, ==, 1);
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
	test_assert_cmp(json_node_get_intmax(&jnode, &num_val), ==, 0);
	test_assert_cmp(num_val, ==, 2);
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
	test_assert_cmp(json_node_get_intmax(&jnode, &num_val), ==, 0);
	test_assert_cmp(num_val, ==, 3);
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

static void fatal_json_tree_unref(struct json_tree *jtree)
{
	json_tree_unref(&jtree);
}

/* Regression guard: the panic json_tree_node_get_str() raises on
   STREAM content is intentional and documented (json-tree.h); the escape
   hatch for that case is json_tree_node_get_str_istream(). Pin the panic
   down so a future refactor cannot silently start swallowing it and hand
   back a bogus string instead. */
static enum fatal_test_state
test_json_tree_node_get_str_stream_fatal(unsigned int stage)
{
	static const char *text = "{\"a\":\"AAAAAAAA\"}";
	struct istream *input;
	struct json_istream *jinput;
	struct json_tree *jtree = NULL;
	struct json_tree_node *root, *jtnode;
	const char *error = NULL;
	int ret;

	switch (stage) {
	case 0:
		test_begin(
			"json tree node get_str still panics on STREAM content");
		input = i_stream_create_from_data(text, strlen(text));
		jinput = json_istream_create(input, 0, NULL, 0);
		i_stream_unref(&input);

		/* threshold=1: even this short value is stored as STREAM
		   content. */
		while ((ret = json_istream_read_tree_lazy_strings(
					jinput, 1, 65536, &jtree)) == 0)
			;
		test_assert(ret > 0);
		ret = json_istream_finish(&jinput, &error);
		test_assert(ret > 0);

		root = json_tree_get_root(jtree);
		jtnode = json_tree_node_get_member(root, "a");
		test_assert(jtnode != NULL);
		test_assert(json_tree_node_get(jtnode)->value.content_type ==
			    JSON_CONTENT_TYPE_STREAM);

		test_expect_fatal_string(
			"(json_value_get_str): assertion failed: "
			"(jvalue->content_type == JSON_CONTENT_TYPE_STRING)");
		/* json_tree_node_get_str() panics before returning, so the
		   tree is never reached by the json_tree_unref() below it -
		   free it via the fatal callback instead, or valgrind sees
		   it as leaked (the panic longjmps back into this same
		   process, it doesn't fork). */
		test_fatal_set_callback(fatal_json_tree_unref, jtree);
		(void)json_tree_node_get_str(jtnode);
		return FATAL_TEST_FAILURE;
	}

	test_end();
	return FATAL_TEST_FINISHED;
}

struct fatal_json_tree_add_stream_ctx {
	struct json_tree *jtree;
	struct istream *input;
};

static void
fatal_json_tree_add_stream_cleanup(struct fatal_json_tree_add_stream_ctx *ctx)
{
	json_tree_unref(&ctx->jtree);
	i_stream_unref(&ctx->input);
}

/* Regression guard: json_tree_node_add_value() must reject a non-seekable
   STREAM value at add time rather than let it reach the tree, where it
   would panic three layers down in json_generate_stream_rewind() the first
   time the tree is serialized. */
static enum fatal_test_state
test_json_tree_node_add_string_stream_nonseekable_fatal(unsigned int stage)
{
	static struct fatal_json_tree_add_stream_ctx ctx;
	struct json_tree_node *root;

	switch (stage) {
	case 0:
		test_begin(
			"json tree node add string stream panics on "
			"non-seekable stream");
		ctx.input = test_istream_create_data("x", 1);
		ctx.input->seekable = FALSE;
		ctx.jtree = json_tree_create();
		root = json_tree_get_root(ctx.jtree);

		test_expect_fatal_string(
			"(json_tree_node_add_value): assertion failed: "
			"(jvalue->content.stream->seekable)");
		test_fatal_set_callback(
			fatal_json_tree_add_stream_cleanup, &ctx);
		(void)json_tree_node_add_string_stream(root, "k", ctx.input);
		return FATAL_TEST_FAILURE;
	}

	test_end();
	return FATAL_TEST_FINISHED;
}

int main(int argc, char *argv[])
{
	int c;

	static void (*test_functions[])(void) = {
		test_json_tree_object,
		test_json_tree_node_add,
		test_json_tree_node_inspect,
		test_json_tree_node_value,
		test_json_tree_walker_from_node,
		test_json_tree_walker,
		NULL
	};
	static enum fatal_test_state (*fatal_functions[])(unsigned int) = {
		test_json_tree_node_get_str_stream_fatal,
		test_json_tree_node_add_string_stream_nonseekable_fatal,
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

	return test_run_with_fatals(test_functions, fatal_functions);
}
