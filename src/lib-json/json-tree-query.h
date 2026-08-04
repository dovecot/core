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

/*
 * RFC 8620 section 3.7 multi-result query.
 *
 * Like json_tree_node_pointer_query() but supports "*" wildcard steps that
 * expand all elements of an array.  Results are appended to *results_r
 * (caller initialises it).  Works for splat-free pointers too (appends 0 or
 * 1 nodes).
 *
 * Example: pointer "/list/[*]/id" (written with [*] to avoid closing this
 *          comment) appends all "id" values from each element of "list".
 *
 * A "*" step applied to a non-array is looked up like any other member
 * name (so an object with a literal "*" member stays reachable via "*")
 * rather than producing no results.  This is not an RFC 8620 deviation:
 * sect 3.7's splat clause is explicitly conditioned on "If the currently
 * referenced value is a JSON array"; for anything else, plain RFC 6901
 * member-name lookup applies, which is exactly this.
 *
 * If applying the rest of the pointer to a splat item does not resolve
 * (missing member, wrong type, etc.), that item is silently skipped
 * rather than reported as an error.  This part *is* deliberate but does
 * diverge from RFC 8620 sect 3.7, which treats any unresolvable per-item
 * remainder as a hard evaluation failure (invalidResultReference).
 *
 * Allocates two t_array_init() arrays from the caller's current datastack
 * frame on every call; a caller looping over many pointers without its own
 * T_BEGIN/T_END will grow the datastack accordingly.
 */
void json_tree_node_pointer_query_all(const struct json_pointer *pointer,
				      const struct json_tree_node *node,
				      ARRAY_TYPE(json_tree_node_const) *results_r);

/* Convenience: apply to the root of a tree. */
void json_tree_pointer_query_all(const struct json_pointer *pointer,
				 const struct json_tree *jtree,
				 ARRAY_TYPE(json_tree_node_const) *results_r);

#endif
