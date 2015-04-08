#ifndef JSON_TREE_H
#define JSON_TREE_H

#include "json-parser.h"

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

struct json_tree *json_tree_init(void);
void json_tree_deinit(struct json_tree **tree);

/* Append data to a tree. The type/value should normally come from json-parser.
   Returns 0 on success, -1 if the input was invalid (which should never happen
   if it's coming from json-parser). */
int json_tree_append(struct json_tree *tree, enum json_type type,
		     const char *value);

/* Return the root node. */
struct json_tree_node *json_tree_root(struct json_tree *tree);
/* Find a node with the specified key (from node's siblings) */
struct json_tree_node *
json_tree_find_key(struct json_tree_node *node, const char *key);
/* Find an object node (from an array), which contains the specified key=value
   in its values. */
struct json_tree_node *
json_tree_find_child_with(struct json_tree_node *node,
			  const char *key, const char *value);

#endif
