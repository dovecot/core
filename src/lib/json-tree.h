#ifndef JSON_TREE_H
#define JSON_TREE_H

#include "json-parser.h"

/* Direct access to this structure is not encouraged, use the inline
   function accessors where possible, so that the implementation
   details can remain fluid, or, even better, hidden. */
struct json_tree_node {
	/* object key, or NULL if we're in a list */
	const char *key;
	struct json_tree_node *parent, *next;

	enum json_type value_type;
	struct {
		/* for JSON_TYPE_OBJECT and JSON_TYPE_ARRAY */
		struct json_tree_node *child;
		/* for other types */
		const char *str;
	} value;
};
static inline ATTR_PURE const struct json_tree_node *json_tree_get_child(const struct json_tree_node *node)
{
	return node->value.child;
}
static inline ATTR_PURE const char *json_tree_get_value_str(const struct json_tree_node *node)
{
	return node->value.str;
}

/* You can build a list or an object, nothing else. */
struct json_tree *json_tree_init_type(enum json_type container);
static inline struct json_tree *json_tree_init(void)
{
	return json_tree_init_type(JSON_TYPE_OBJECT);
}
static inline struct json_tree *json_tree_init_array(void)
{
	return json_tree_init_type(JSON_TYPE_ARRAY);
}

void json_tree_deinit(struct json_tree **tree);

/* Append data to a tree. The type/value should normally come from json-parser.
   Returns 0 on success, -1 if the input was invalid (which should never happen
   if it's coming from json-parser). */
int json_tree_append(struct json_tree *tree, enum json_type type,
		     const char *value);

/* Return the root node. */
const struct json_tree_node *
json_tree_root(const struct json_tree *tree);
/* Find a node with the specified key from an OBJECT node */
const struct json_tree_node *
json_tree_find_key(const struct json_tree_node *node, const char *key);
/* Find an object node (from an array), which contains the specified key=value
   in its values. */
const struct json_tree_node *
json_tree_find_child_with(const struct json_tree_node *node,
			  const char *key, const char *value);

#endif
