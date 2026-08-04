/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "lib.h"
#include "array.h"

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

/* --- RFC 8620 sect 3.7 multi-result query --- */

void json_tree_node_pointer_query_all(const struct json_pointer *pointer,
				      const struct json_tree_node *node,
				      ARRAY_TYPE(json_tree_node_const) *results_r)
{
	ARRAY_TYPE(json_tree_node_const) set_a, set_b;
	ARRAY_TYPE(json_tree_node_const) *cur, *nxt, *tmp;
	bool used_splat = FALSE;

	i_assert(pointer != NULL);
	i_assert(node != NULL);
	i_assert(results_r != NULL);

	t_array_init(&set_a, 8);
	t_array_init(&set_b, 8);
	cur = &set_a;
	nxt = &set_b;

	if (json_tree_node_get_type(node) != JSON_TYPE_NONE)
		array_push_back(cur, &node);

	for (const struct json_pointer_step *step = pointer->first;
	     step != NULL; step = step->next) {
		array_clear(nxt);

		const struct json_tree_node *c;
		array_foreach_elem(cur, c) {
			/* RFC 8620 sect 3.7 "*" is only a splat wildcard
			   against arrays; against an object it is looked up
			   like any other member name (so a literal "*"
			   member stays reachable). */
			if (json_tree_node_is_array(c) &&
			    step->token_len == 1 && step->token[0] == '*') {
				used_splat = TRUE;
				const struct json_tree_node *child;
				for (child = json_tree_node_get_child(c);
				     child != NULL;
				     child = json_tree_node_get_next(child))
					array_push_back(nxt, &child);
			} else {
				const struct json_tree_node *m =
					json_tree_node_pointer_step(c, step);
				if (m != NULL)
					array_push_back(nxt, &m);
			}
			/* scalar: produces no output */
		}

		/* nxt becomes the frontier for the next step; cur is now
		   stale and gets reused as next round's nxt buffer. */
		tmp = cur; cur = nxt; nxt = tmp;
	}

	/* RFC 8620 sect 3.7: if the per-item result of applying the rest of
	   the pointer tokens is itself an array, its contents are added to
	   the output rather than the array itself.  Flatten exactly one
	   level here, once, on the final frontier - not inside the step
	   loop - so "/a/[*]/b" (written with [*] to avoid closing this
	   comment) where "b" is an array of arrays is flattened only at
	   the outermost level, not recursively.  Only applies once a "*"
	   has actually been used; splat-free pointers keep appending the
	   resolved node as-is (0 or 1 results, per the doc comment). */
	const struct json_tree_node *resp;
	array_foreach_elem(cur, resp) {
		if (used_splat && json_tree_node_is_array(resp)) {
			const struct json_tree_node *child;
			for (child = json_tree_node_get_child(resp);
			     child != NULL;
			     child = json_tree_node_get_next(child))
				array_push_back(results_r, &child);
		} else {
			array_push_back(results_r, &resp);
		}
	}
}

void json_tree_pointer_query_all(const struct json_pointer *pointer,
				 const struct json_tree *jtree,
				 ARRAY_TYPE(json_tree_node_const) *results_r)
{
	const struct json_tree_node *node = json_tree_get_root_const(jtree);
	json_tree_node_pointer_query_all(pointer, node, results_r);
}
