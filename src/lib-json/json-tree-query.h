#ifndef JSON_TREE_QUERY_H
#define JSON_TREE_QUERY_H

#include "json-tree.h"

struct json_pointer;

/*
 * Apply a compiled pointer to a tree node (RFC 6901 sect 4).
 *
 * Returns the matching node, or NULL if the pointer does not resolve to
 * any node in the tree.  A NULL return is a normal "not found" outcome
 * (missing member, out-of-range index, "-" index on array, descent into
 * a scalar) - it does not indicate a syntax error, which is caught at
 * parse time.
 *
 * Empty pointer returns `node` unchanged, except when `node` is the
 * NONE-typed empty-tree sentinel, in which case NULL is returned.
 */
const struct json_tree_node *
json_tree_node_pointer_query(const struct json_pointer *pointer,
			     const struct json_tree_node *node);

/* Convenience: apply pointer to the root of a tree. */
const struct json_tree_node *
json_tree_pointer_query(const struct json_pointer *pointer,
			const struct json_tree *jtree);

/*
 * Convenience wrappers that parse, traverse, and free in a single call.
 * They return NULL for both syntax errors and "not found"; prefer the
 * two-phase API when the same pointer is applied more than once.
 */
const struct json_tree_node *
json_tree_node_resolve_pointer(const struct json_tree_node *node, const char *pointer);

const struct json_tree_node *
json_tree_resolve_pointer(const struct json_tree *jtree, const char *pointer);

#endif
