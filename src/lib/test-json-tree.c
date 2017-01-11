/* Copyright (c) 2015-2017 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "json-tree.h"

struct {
	enum json_type type;
	const char *value;
} test_input[] = {
	{ JSON_TYPE_OBJECT_KEY, "key-str" },
	{ JSON_TYPE_STRING, "string" },
	{ JSON_TYPE_OBJECT_KEY, "key-num" },
	{ JSON_TYPE_NUMBER, "1234" },
	{ JSON_TYPE_OBJECT_KEY, "key-true" },
	{ JSON_TYPE_TRUE, "true" },
	{ JSON_TYPE_OBJECT_KEY, "key-false" },
	{ JSON_TYPE_FALSE, "false" },
	{ JSON_TYPE_OBJECT_KEY, "key-null" },
	{ JSON_TYPE_NULL, NULL },

	{ JSON_TYPE_OBJECT_KEY, "key-obj-empty" },
	{ JSON_TYPE_OBJECT, NULL },
	{ JSON_TYPE_OBJECT_END, NULL },

	{ JSON_TYPE_OBJECT_KEY, "key-obj" },
	{ JSON_TYPE_OBJECT, NULL },
	  { JSON_TYPE_OBJECT_KEY, "sub" },
	  { JSON_TYPE_STRING, "value" },
	{ JSON_TYPE_OBJECT_END, NULL },

	{ JSON_TYPE_OBJECT_KEY, "key-arr-empty" },
	{ JSON_TYPE_ARRAY, NULL },
	{ JSON_TYPE_ARRAY_END, NULL },

	{ JSON_TYPE_OBJECT_KEY, "key-arr" },
	{ JSON_TYPE_ARRAY, NULL },
	  { JSON_TYPE_STRING, "foo" },
	  { JSON_TYPE_ARRAY, NULL },
	  { JSON_TYPE_TRUE, "true" },
	  { JSON_TYPE_ARRAY_END, NULL },
	  { JSON_TYPE_OBJECT, NULL },
	    { JSON_TYPE_OBJECT_KEY, "aobj" },
	    { JSON_TYPE_ARRAY, NULL },
	    { JSON_TYPE_ARRAY_END, NULL },
	  { JSON_TYPE_OBJECT_END, NULL },
	  { JSON_TYPE_OBJECT, NULL },
	    { JSON_TYPE_OBJECT_KEY, "aobj-key" },
	    { JSON_TYPE_STRING, "value1" },
	  { JSON_TYPE_OBJECT_END, NULL },
	  { JSON_TYPE_OBJECT, NULL },
	    { JSON_TYPE_OBJECT_KEY, "aobj-key" },
	    { JSON_TYPE_STRING, "value2" },
	  { JSON_TYPE_OBJECT_END, NULL },
	{ JSON_TYPE_ARRAY_END, NULL }
};

void test_json_tree(void)
{
	struct json_tree *tree;
	struct json_tree_node *root, *node, *node1, *node2;
	unsigned int i;

	test_begin("json tree");
	tree = json_tree_init();
	for (i = 0; i < N_ELEMENTS(test_input); i++) {
		test_assert_idx(json_tree_append(tree, test_input[i].type,
						 test_input[i].value) == 0, i);
	}

	root = json_tree_root(tree);
	i_assert(root != NULL);
	test_assert(root->value_type == JSON_TYPE_OBJECT);
	root = root->value.child;
	i_assert(root != NULL);

	for (i = 0; i < 10+2; i += 2) {
		node = json_tree_find_key(root, test_input[i].value);
		test_assert(node != NULL &&
			    node->value_type == test_input[i+1].type &&
			    null_strcmp(node->value.str, test_input[i+1].value) == 0);
	}

	node = json_tree_find_key(root, "key-obj");
	test_assert(node != NULL);

	node = json_tree_find_key(root, "key-arr-empty");
	test_assert(node != NULL && node->value_type == JSON_TYPE_ARRAY &&
		    node->value.child == NULL);

	node = json_tree_find_key(root, "key-arr");
	test_assert(node != NULL && node->value_type == JSON_TYPE_ARRAY);
	node = node->value.child;
	test_assert(node != NULL && node->value_type == JSON_TYPE_STRING &&
		    strcmp(node->value.str, "foo") == 0);
	node = node->next;
	test_assert(node != NULL && node->value_type == JSON_TYPE_ARRAY &&
		    node->value.child != NULL &&
		    node->value.child->next == NULL &&
		    node->value.child->value_type == JSON_TYPE_TRUE);
	node = node->next;
	test_assert(node != NULL && node->value_type == JSON_TYPE_OBJECT &&
		    node->value.child != NULL &&
		    node->value.child->next == NULL &&
		    node->value.child->value_type == JSON_TYPE_ARRAY &&
		    node->value.child->value.child == NULL);

	node1 = json_tree_find_child_with(node->parent, "aobj-key", "value1");
	node2 = json_tree_find_child_with(node->parent, "aobj-key", "value2");
	test_assert(node1 != NULL && node2 != NULL && node1 != node2);
	test_assert(json_tree_find_child_with(node->parent, "aobj-key", "value3") == NULL);

	json_tree_deinit(&tree);
	test_end();
}
