#ifndef JSON_POINTER_H
#define JSON_POINTER_H

/*
 * JSON Pointer (RFC 6901) lookup for json_tree.
 *
 * A json_pointer is a pre-parsed JSON Pointer.  Parse once with
 * json_pointer_create(), then apply repeatedly with
 * json_tree_node_pointer_query() / json_tree_resolve_pointer() - the same
 * object is safe to use against different trees or nodes.
 *
 * Syntax (RFC 6901 sect 3, JSON-string form):
 *   ""          - empty pointer, resolves to the starting node
 *   "/foo"      - object member "foo"
 *   "/foo/0"    - element 0 of the array at "foo"
 *   "/a~1b"     - object member "a/b"  (~1 -> '/')
 *   "/m~0n"     - object member "m~n"  (~0 -> '~')
 *
 * Member-vs-index is determined at evaluation time from the type of the
 * current node, not at parse time.  Array indices must be a single '0' or
 * a non-empty sequence of digits without leading zeros; the token "-"
 * refers to the (nonexistent) member past the end of an array and yields
 * NULL on read.
 *
 * RFC 6901 evaluates against the document root.  This API generalizes the
 * start node: json_tree_node_pointer_query(pointer, node) evaluates the
 * pointer relative to `node`.  When `node` is the tree root, this is exactly
 * the RFC 6901 semantics.
 */

struct json_pointer_step {
	struct json_pointer_step *next;
	/* Decoded reference token (~0/~1 already expanded).  NUL-terminated
	   for convenience, but the canonical length is token_len since RFC
	   6901 tokens are byte sequences and may contain embedded NULs. */
	const char *token;
	size_t token_len;
};

struct json_pointer {
	pool_t pool;
	/* NULL = empty pointer = whole document. */
	struct json_pointer_step *first;
};

/*
 * Parse a JSON Pointer string (RFC 6901 sect 3, JSON-string form).
 *
 * Returns  0 on success (*pointer_r is set; free with json_pointer_free()).
 * Returns -1 on syntax error (*error_r is set; *pointer_r is not set).
 *
 * Syntax errors: input is non-empty and does not begin with '/', or a
 * '~' is not followed by '0' or '1'.
 */
int json_pointer_create(const char *pointer, struct json_pointer **pointer_r,
			const char **error_r);

/*
 * Parse a JSON Pointer in URI fragment form (RFC 6901 sect 6).
 *
 * The input must begin with '#'; the remainder is percent-decoded per
 * RFC 3986 and then parsed as a JSON Pointer.  Note: percent-encoded NUL
 * bytes ("%00") are rejected as a decode error - JSON member names
 * containing embedded NULs cannot be represented in URI fragment form.
 *
 * Returns  0 on success (*pointer_r is set; free with json_pointer_free()).
 * Returns -1 on syntax error (*error_r is set; *pointer_r is not set).
 */
int json_pointer_create_uri_fragment(const char *fragment,
				     struct json_pointer **pointer_r,
				     const char **error_r);

/* Free a compiled pointer created by json_pointer_create() or
   json_pointer_create_uri_fragment(). */
void json_pointer_free(struct json_pointer **_pointer);

/* Test whether `token` matches the RFC 6901 sect 4 array-index production:
 *
 *    array-index = %x30 / ( %x31-39 *(%x30-39) )
 *
 *  i.e. exactly "0", or a non-empty digit sequence with no leading zero.
 *  Rejects empty input, leading zeros ("01"), embedded NULs, and any
 *  non-digit byte. */
bool
json_pointer_token_parse_array_index(const char *token, size_t token_len,
				     unsigned int *idx_r);

/*
 * Binary export / import.
 *
 * json_pointer_export() appends a self-contained binary representation of the
 * compiled pointer to `dest`.  json_pointer_import() reconstructs an equivalent
 * compiled pointer from such a byte sequence.
 *
 * The serialized form is intended to be persisted (e.g. on disk) and read
 * back later.  Import treats input as untrusted: it validates a magic and
 * version header, caps the step count and per-token length, and never
 * dereferences past the supplied buffer.  An empty pointer round-trips to
 * an empty pointer.
 *
 * json_pointer_export() enforces the same step-count and per-token-length
 * caps that json_pointer_import() does, so a successful export is always
 * importable: a pointer built via json_pointer_create() (which applies no
 * such caps) can in principle exceed them.  Returns 0 on success (nothing
 * appended to `dest` on failure).  Returns -1 if `pointer` exceeds a cap
 * (*error_r is set).
 *
 * json_pointer_import() returns 0 on success (*pointer_r is set; free with
 * json_pointer_free()).  Returns -1 on malformed input (*error_r is set;
 * *pointer_r is not set).
 */
int json_pointer_export(buffer_t *dest, const struct json_pointer *pointer,
			const char **error_r);
int json_pointer_import(const void *data, size_t size,
			struct json_pointer **pointer_r, const char **error_r);

#endif
