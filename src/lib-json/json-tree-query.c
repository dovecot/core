/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "lib.h"

#include "json-pointer.h"
#include "json-tree-query.h"

/* Evaluate a single JSON Pointer reference token against a tree node
   (RFC 6901 sect 4):
     - If the node is an object, the result is the member named by the
       (already-unescaped) token.  Missing member -> NULL.  Tree member
       names are plain NUL-terminated C strings, so a token containing an
       embedded NUL (only reachable via json_pointer_import()) can never
       match a real member and is rejected up front.
     - If the node is an array, the token must match the array-index
       production (see json_pointer_token_parse_array_index()).  The
       token "-" refers to the (nonexistent) element past the end and
       resolves to NULL.
     - Any other node type cannot be descended into and resolves to
       NULL. */
static const struct json_tree_node *
json_tree_node_pointer_step(const struct json_tree_node *node,
			    const struct json_pointer_step *step)
{
	if (json_tree_node_is_object(node)) {
		if (strlen(step->token) != step->token_len)
			return NULL;
		return json_tree_node_get_member(node, step->token);
	} else if (json_tree_node_is_array(node)) {
		unsigned int idx;

		if (step->token_len == 1 && step->token[0] == '-')
			return NULL;
		if (!json_pointer_token_parse_array_index(step->token,
							  step->token_len,
							  &idx))
			return NULL;
		return json_tree_node_get_nth_child(node, idx);
	}
	return NULL;
}

/* Evaluate a compiled JSON Pointer against a tree node (RFC 6901 sect 4).

   Per sect 4, an empty json-pointer ("") resolves to the starting value
   unchanged. */
const struct json_tree_node *
json_tree_node_pointer_query(const struct json_pointer *pointer,
			     const struct json_tree_node *node)
{
	const struct json_tree_node *cur = node;

	i_assert(pointer != NULL);
	i_assert(node != NULL);

	if (json_tree_node_get_type(cur) == JSON_TYPE_NONE)
		return NULL;

	for (const struct json_pointer_step *step = pointer->first;
	     step != NULL && cur != NULL; step = step->next)
		cur = json_tree_node_pointer_step(cur, step);

	return cur;
}

const struct json_tree_node *
json_tree_pointer_query(const struct json_pointer *pointer,
			     const struct json_tree *jtree)
{
	const struct json_tree_node *node = json_tree_get_root_const(jtree);
	return json_tree_node_pointer_query(pointer, node);
}

const struct json_tree_node *
json_tree_node_resolve_pointer(const struct json_tree_node *node,
			       const char *pointer)
{
	struct json_pointer *jpointer;
	const struct json_tree_node *result;
	const char *error;

	i_assert(node != NULL);
	i_assert(pointer != NULL);

	if (json_pointer_create(pointer, &jpointer, &error) < 0)
		return NULL;
	result = json_tree_node_pointer_query(jpointer, node);
	json_pointer_free(&jpointer);
	return result;
}

const struct json_tree_node *
json_tree_resolve_pointer(const struct json_tree *jtree, const char *pointer)
{
	const struct json_tree_node *node = json_tree_get_root_const(jtree);
	return json_tree_node_resolve_pointer(node, pointer);
}
