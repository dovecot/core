#ifndef JSON_TREE_H
#define JSON_TREE_H

#include "json-types.h"

struct json_tree;

ARRAY_DEFINE_TYPE(json_tree, struct json_tree *);
ARRAY_DEFINE_TYPE(json_tree_node, struct json_tree_node *);
ARRAY_DEFINE_TYPE(json_tree_node_const, const struct json_tree_node *);

/*
 * Tree construction
 */

/* node */
struct json_tree_node * ATTR_NOWARN_UNUSED_RESULT
json_tree_node_add(struct json_tree_node *parent,
		   const struct json_node *node);

/* object, array */
struct json_tree_node * ATTR_NOWARN_UNUSED_RESULT
json_tree_node_add_object(struct json_tree_node *parent, const char *name);
struct json_tree_node * ATTR_NOWARN_UNUSED_RESULT
json_tree_node_add_array(struct json_tree_node *parent, const char *name);

/* value */
struct json_tree_node * ATTR_NOWARN_UNUSED_RESULT
json_tree_node_add_value(struct json_tree_node *parent, const char *name,
			 enum json_type type,
			 const struct json_value *value);

/* string */
struct json_tree_node * ATTR_NOWARN_UNUSED_RESULT
json_tree_node_add_string(struct json_tree_node *parent, const char *name,
			  const char *str);
struct json_tree_node * ATTR_NOWARN_UNUSED_RESULT
json_tree_node_add_data(struct json_tree_node *parent, const char *name,
			const unsigned char *data, size_t size);
/* `input' must be seekable: the tree keeps its own reference and may
   serialize it more than once, rewinding it to offset 0 before each read.
   json_tree_node_add_value() asserts this at add time. */
struct json_tree_node * ATTR_NOWARN_UNUSED_RESULT
json_tree_node_add_string_stream(struct json_tree_node *parent,
				 const char *name, struct istream *input);

/* number */
struct json_tree_node * ATTR_NOWARN_UNUSED_RESULT
json_tree_node_add_number_int(struct json_tree_node *parent, const char *name,
			      uintmax_t num);
struct json_tree_node * ATTR_NOWARN_UNUSED_RESULT
json_tree_node_add_number_str(struct json_tree_node *parent, const char *name,
			      const char *num);

/* false, true */
struct json_tree_node * ATTR_NOWARN_UNUSED_RESULT
json_tree_node_add_false(struct json_tree_node *parent, const char *name);
struct json_tree_node * ATTR_NOWARN_UNUSED_RESULT
json_tree_node_add_true(struct json_tree_node *parent, const char *name);
struct json_tree_node * ATTR_NOWARN_UNUSED_RESULT
json_tree_node_add_boolean(struct json_tree_node *parent, const char *name,
			   bool val);

/* null */
struct json_tree_node * ATTR_NOWARN_UNUSED_RESULT
json_tree_node_add_null(struct json_tree_node *parent, const char *name);

/* JSON-text */

struct json_tree_node * ATTR_NOWARN_UNUSED_RESULT
json_tree_node_add_text(struct json_tree_node *parent, const char *name,
			const char *literal);
struct json_tree_node * ATTR_NOWARN_UNUSED_RESULT
json_tree_node_add_text_data(struct json_tree_node *parent, const char *name,
			     const unsigned char *data, size_t size);

struct json_tree_node * ATTR_NOWARN_UNUSED_RESULT
json_tree_node_add_subtree(struct json_tree_node *parent, const char *name,
			   struct json_tree *tree);

/*
 * Tree inspection
 */

enum json_type
json_tree_node_get_type(const struct json_tree_node *jtnode) ATTR_PURE;
const char *
json_tree_node_get_name(const struct json_tree_node *jtnode) ATTR_PURE;
struct json_tree *
json_tree_node_get_tree(struct json_tree_node *jtnode) ATTR_PURE;
const struct json_tree *
json_tree_node_get_tree_const(const struct json_tree_node *jtnode) ATTR_PURE;

bool json_tree_node_is_root(const struct json_tree_node *jtnode) ATTR_PURE;

bool json_tree_node_is_object(const struct json_tree_node *njtode) ATTR_PURE;
bool json_tree_node_is_array(const struct json_tree_node *jtnode) ATTR_PURE;
bool json_tree_node_is_string(const struct json_tree_node *jtnode) ATTR_PURE;
bool json_tree_node_is_number(const struct json_tree_node *jtnode) ATTR_PURE;
bool json_tree_node_is_true(const struct json_tree_node *jtnode) ATTR_PURE;
bool json_tree_node_is_false(const struct json_tree_node *jtnode) ATTR_PURE;
bool json_tree_node_is_boolean(const struct json_tree_node *jtnode) ATTR_PURE;
bool json_tree_node_is_null(const struct json_tree_node *jtnode) ATTR_PURE;

const struct json_node *
json_tree_node_get(const struct json_tree_node *jtnode) ATTR_PURE;

struct json_tree_node *
json_tree_node_get_next(const struct json_tree_node *jtnode) ATTR_PURE;
struct json_tree_node *
json_tree_node_get_parent(const struct json_tree_node *jtnode) ATTR_PURE;
struct json_tree_node *
json_tree_node_get_child(const struct json_tree_node *jtnode) ATTR_PURE;
/* O(n) per call (walks from the first child) - iterating all of a node's
   children by increasing index with this is accidentally quadratic; use
   json_tree_node_get_child()/get_next() instead for that. */
struct json_tree_node *
json_tree_node_get_nth_child(const struct json_tree_node *jtnode, unsigned int n);
unsigned int
json_tree_node_get_child_count(const struct json_tree_node *jtnode) ATTR_PURE;

struct json_tree_node *
json_tree_node_get_member(const struct json_tree_node *jtnode,
			  const char *name) ATTR_PURE;

struct json_tree_node *
json_tree_node_get_child_with(const struct json_tree_node *jtnode,
			      const char *key, const char *value);

/* Panics if the node's content type is STREAM rather than STRING - which a
   string node can be if it came from json_istream_read_tree_lazy_strings()
   and was at or above the lazy-string threshold. Use
   json_tree_node_get_str_istream() (or check the content type) for trees
   that may have been built that way. */
static inline const char *
json_tree_node_get_str(const struct json_tree_node *jtnode)
{
	return json_node_get_str(json_tree_node_get(jtnode));
}

/* Return a new istream yielding the decoded string bytes for this node via
   *stream_r.  Works for STRING, DATA and STREAM content types; the returned
   stream is independent of the source tree and safe to retain even after
   the tree is unreffed and across reads of any other node's stream (for
   STRING/DATA content the tree's pool is kept alive for as long as the
   stream is; for STREAM content the bytes are copied out up front).  The
   caller must unref the returned stream when done.  Returns 0 on success.
   Returns -1 if the node's content type is not STRING, DATA or STREAM (e.g.
   number/bool/null/object/array), or if it holds a STREAM-typed value whose
   underlying stream isn't seekable - its provenance can't be verified in
   advance (e.g. an arbitrary caller-supplied stream, as opposed to one this
   library built internally, which is always seekable). */
int
json_tree_node_get_str_istream(const struct json_tree_node *jtnode,
			       struct istream **stream_r);

/* Panics on STREAM content - see json_tree_node_get_str() above. */
static inline const unsigned char *
json_tree_node_get_data(const struct json_tree_node *jtnode, size_t *size_r)
{
	return json_node_get_data(json_tree_node_get(jtnode), size_r);
}

/* Panics on STREAM content - see json_tree_node_get_str() above. */
static inline const char *
json_tree_node_as_str(const struct json_tree_node *jtnode)
{
	return json_node_as_str(json_tree_node_get(jtnode));
}

static inline int
json_tree_node_get_intmax(const struct json_tree_node *jtnode, intmax_t *num_r)
{
	return json_node_get_intmax(json_tree_node_get(jtnode), num_r);
}

static inline int
json_tree_node_get_int(const struct json_tree_node *jtnode, int *num_r)
{
	return json_node_get_int(json_tree_node_get(jtnode), num_r);
}

static inline int
json_tree_node_get_long(const struct json_tree_node *jtnode, long *num_r)
{
	return json_node_get_long(json_tree_node_get(jtnode), num_r);
}

static inline int
json_tree_node_get_llong(const struct json_tree_node *jtnode, long long *num_r)
{
	return json_node_get_llong(json_tree_node_get(jtnode), num_r);
}

static inline int
json_tree_node_get_int32(const struct json_tree_node *jtnode, int32_t *num_r)
{
	return json_node_get_int32(json_tree_node_get(jtnode), num_r);
}

static inline int
json_tree_node_get_int64(const struct json_tree_node *jtnode, int64_t *num_r)
{
	return json_node_get_int64(json_tree_node_get(jtnode), num_r);
}

static inline int
json_tree_node_get_uintmax(const struct json_tree_node *jtnode,
			   uintmax_t *num_r)
{
	return json_node_get_uintmax(json_tree_node_get(jtnode), num_r);
}

static inline int
json_tree_node_get_uint(const struct json_tree_node *jtnode,
			unsigned int *num_r)
{
	return json_node_get_uint(json_tree_node_get(jtnode), num_r);
}

static inline int
json_tree_node_get_ulong(const struct json_tree_node *jtnode,
			 unsigned long *num_r)
{
	return json_node_get_ulong(json_tree_node_get(jtnode), num_r);
}

static inline int
json_tree_node_get_ullong(const struct json_tree_node *jtnode,
			  unsigned long long *num_r)
{
	return json_node_get_ullong(json_tree_node_get(jtnode), num_r);
}

static inline int
json_tree_node_get_uint32(const struct json_tree_node *jtnode, uint32_t *num_r)
{
	return json_node_get_uint32(json_tree_node_get(jtnode), num_r);
}

static inline int
json_tree_node_get_uint64(const struct json_tree_node *jtnode, uint64_t *num_r)
{
	return json_node_get_uint64(json_tree_node_get(jtnode), num_r);
}

/*
 * Tree object
 */

struct json_tree_node *json_tree_get_root(struct json_tree *jtree);
const struct json_tree_node *
json_tree_get_root_const(const struct json_tree *jtree);

struct json_tree *json_tree_create_pool(pool_t pool);
struct json_tree *json_tree_create(void);
void json_tree_ref(struct json_tree *jtree);
void json_tree_unref(struct json_tree **_jtree);

static inline struct json_tree *
json_tree_create_object(struct json_tree_node **root_r)
{
	struct json_tree *jtree;

	jtree = json_tree_create();
	*root_r = json_tree_node_add_object(json_tree_get_root(jtree), NULL);
	return jtree;
}
static inline struct json_tree *
json_tree_create_array(struct json_tree_node **root_r)
{
	struct json_tree *jtree;

	jtree = json_tree_create();
	*root_r = json_tree_node_add_array(json_tree_get_root(jtree), NULL);
	return jtree;
}

bool json_tree_is_object(const struct json_tree *jtree) ATTR_PURE;
bool json_tree_is_array(const struct json_tree *jtree) ATTR_PURE;
bool json_tree_is_string(const struct json_tree *jtree) ATTR_PURE;
bool json_tree_is_number(const struct json_tree *jtree) ATTR_PURE;
bool json_tree_is_true(const struct json_tree *jtree) ATTR_PURE;
bool json_tree_is_false(const struct json_tree *jtree) ATTR_PURE;
bool json_tree_is_boolean(const struct json_tree *jtree) ATTR_PURE;
bool json_tree_is_null(const struct json_tree *jtree) ATTR_PURE;

/*
 * Walker
 */

struct json_tree_walker;

struct json_tree_walker *
json_tree_walker_create_from_node(const struct json_tree_node *tree_node);
struct json_tree_walker *
json_tree_walker_create(const struct json_tree *tree);
void json_tree_walker_free(struct json_tree_walker **_twalker);

bool json_tree_walk(struct json_tree_walker *twalker, struct json_node *node_r);

#endif
