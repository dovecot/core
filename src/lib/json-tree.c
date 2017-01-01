/* Copyright (c) 2015-2017 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "json-tree.h"

struct json_tree {
	pool_t pool;
	struct json_tree_node *root, *cur, *cur_child;
};

struct json_tree *
json_tree_init_type(enum json_type container)
{
	struct json_tree *tree;
	pool_t pool;

	pool = pool_alloconly_create("json tree", 1024);
	tree = p_new(pool, struct json_tree, 1);
	tree->pool = pool;
	tree->root = tree->cur = p_new(tree->pool, struct json_tree_node, 1);
	tree->cur->value_type = container == JSON_TYPE_ARRAY ? container : JSON_TYPE_OBJECT;
	return tree;
}

void json_tree_deinit(struct json_tree **_tree)
{
	struct json_tree *tree = *_tree;

	*_tree = NULL;
	pool_unref(&tree->pool);
}

static void
json_tree_append_child(struct json_tree *tree, enum json_type type,
		       const char *value)
{
	struct json_tree_node *node;

	node = p_new(tree->pool, struct json_tree_node, 1);
	node->parent = tree->cur;
	node->value_type = type;
	node->value.str = p_strdup(tree->pool, value);

	if (tree->cur_child == NULL)
		tree->cur->value.child = node;
	else
		tree->cur_child->next = node;
	tree->cur_child = node;
}

static void
json_tree_set_cur(struct json_tree *tree, struct json_tree_node *node)
{
	tree->cur = node;
	tree->cur_child = tree->cur->value.child;
	if (tree->cur_child != NULL) {
		while (tree->cur_child->next != NULL)
			tree->cur_child = tree->cur_child->next;
	}
}

static int
json_tree_append_value(struct json_tree *tree, enum json_type type,
		       const char *value)
{
	switch (tree->cur->value_type) {
	case JSON_TYPE_OBJECT_KEY:
		/* "key": value - we already added the node and set its key,
		   so now just set the value */
		tree->cur->value_type = type;
		tree->cur->value.str = p_strdup(tree->pool, value);
		json_tree_set_cur(tree, tree->cur->parent);
		break;
	case JSON_TYPE_ARRAY:
		/* element in array - add a new node */
		json_tree_append_child(tree, type, value);
		break;
	default:
		return -1;
	}
	return 0;
}

int json_tree_append(struct json_tree *tree, enum json_type type,
		     const char *value)
{
	switch (type) {
	case JSON_TYPE_OBJECT_KEY:
		if (tree->cur->value_type != JSON_TYPE_OBJECT)
			return -1;
		json_tree_append_child(tree, type, NULL);
		json_tree_set_cur(tree, tree->cur_child);
		tree->cur->key = p_strdup(tree->pool, value);
		break;
	case JSON_TYPE_ARRAY:
		if (json_tree_append_value(tree, type, NULL) < 0)
			return -1;
		json_tree_set_cur(tree, tree->cur_child);
		break;
	case JSON_TYPE_OBJECT:
		if (tree->cur->value_type == JSON_TYPE_OBJECT_KEY)
			tree->cur->value_type = JSON_TYPE_OBJECT;
		else if (tree->cur->value_type == JSON_TYPE_ARRAY) {
			json_tree_append_child(tree, type, NULL);
			json_tree_set_cur(tree, tree->cur_child);
		} else {
			return -1;
		}
		break;
	case JSON_TYPE_OBJECT_END:
		if (tree->cur->parent == NULL ||
		    tree->cur->value_type != JSON_TYPE_OBJECT)
			return -1;
		json_tree_set_cur(tree, tree->cur->parent);
		break;
	case JSON_TYPE_ARRAY_END:
		if (tree->cur->parent == NULL ||
		    tree->cur->value_type != JSON_TYPE_ARRAY)
			return -1;
		json_tree_set_cur(tree, tree->cur->parent);
		break;
	case JSON_TYPE_STRING:
	case JSON_TYPE_NUMBER:
	case JSON_TYPE_TRUE:
	case JSON_TYPE_FALSE:
	case JSON_TYPE_NULL:
		if (json_tree_append_value(tree, type, value) < 0)
			return -1;
		break;
	}
	return 0;
}

const struct json_tree_node *
json_tree_root(const struct json_tree *tree)
{
	return tree->root;
}

const struct json_tree_node *
json_tree_find_key(const struct json_tree_node *node, const char *key)
{
	i_assert(node->value_type == JSON_TYPE_OBJECT);

	node = json_tree_get_child(node);
	for (; node != NULL; node = node->next) {
		if (node->key != NULL && strcmp(node->key, key) == 0)
			return node;
	}
	return NULL;
}

const struct json_tree_node *
json_tree_find_child_with(const struct json_tree_node *node,
			  const char *key, const char *value)
{
	const struct json_tree_node *child;

	i_assert(node->value_type == JSON_TYPE_OBJECT ||
		 node->value_type == JSON_TYPE_ARRAY);

	for (node = json_tree_get_child(node); node != NULL; node = node->next) {
		if (node->value_type != JSON_TYPE_OBJECT)
			continue;

		child = json_tree_find_key(node, key);
		if (child != NULL &&
		    json_tree_get_value_str(child) != NULL &&
		    strcmp(json_tree_get_value_str(child), value) == 0)
			return node;
	}
	return NULL;
}
