#ifndef JSON_ISTREAM_H
#define JSON_ISTREAM_H

#include "json-tree.h"
#include "json-parser.h"

// FIXME: don't bother recording values if we're only validating/skipping

struct json_istream;

enum json_istream_type {
	/* Normal JSON stream: there is one node at root; need to descend first
	   for reading the members of a top-level array or object. */
	JSON_ISTREAM_TYPE_NORMAL = 0,
	/* Stream starts inside a JSON array. If the top-level node is not an
	   array, the stream returns an error at first read. */
	JSON_ISTREAM_TYPE_ARRAY,
	/* Stream starts inside a JSON object. If the top-level node is not an
	   object, the stream returns an error at first read. */
	JSON_ISTREAM_TYPE_OBJECT,
};

struct json_istream *
json_istream_create(struct istream *input, enum json_istream_type type,
		    const struct json_limits *limits,
		    enum json_parser_flags parser_flags);
void json_istream_ref(struct json_istream *stream);
void json_istream_unref(struct json_istream **_stream);
void json_istream_destroy(struct json_istream **_stream);

void json_istream_close(struct json_istream *stream);
bool json_istream_is_closed(struct json_istream *stream) ATTR_PURE;

static inline struct json_istream *
json_istream_create_array(struct istream *input,
			  const struct json_limits *limits,
			  enum json_parser_flags parser_flags)
{
	return json_istream_create(input, JSON_ISTREAM_TYPE_ARRAY,
				   limits, parser_flags);
}

static inline struct json_istream *
json_istream_create_object(struct istream *input,
			   const struct json_limits *limits,
			   enum json_parser_flags parser_flags)
{
	return json_istream_create(input, JSON_ISTREAM_TYPE_OBJECT,
				   limits, parser_flags);
}

/* Get the current node's level in the JSON syntax hierarchy. */
unsigned int json_istream_get_node_level(struct json_istream *stream);

/* Returns TRUE if the JSON text is parsed to the end. Whether this means
   that the input stream is also at EOF depends on the parser flags. */
bool json_istream_is_at_end(struct json_istream *stream);

/* Returns true when the stream has reached an error condition. */
bool json_istream_failed(struct json_istream *stream);
/* Returns error string for the last error. It also returns "EOF" in case there
   is no error, but eof is set. Otherwise it returns "<no error>". */
const char *json_istream_get_error(struct json_istream *stream);
/* Get the current parse location */
void json_istream_get_location(struct json_istream *stream,
			       struct json_parser_location *loc_r);

/* Finish reading input from the JSON stream. If any unread data remains in the
   remainder of the JSON input, an error will occur. This function returns -1
   upon error, 0 when more input is needed to finish and 1 when finishing the
   input was successful. The error_r parameter will be set when the return value
   is -1 and will return any (preexisting or final) error in the stream. The
   provided stream is dereferenced implicitly when the return value is not 0. */
int json_istream_finish(struct json_istream **_stream,
			const char **error_r);

/* Read a JSON node from the stream. If one is already read, this function
   returns that node immediately. Returns 1 on success, 0 if more data is
   needed from the input stream, or -1 upon error or EOF. The last node in
   an object/array reads as JSON_TYPE_OBJECT/JSON_TYPE_ARRAY with
   JSON_CONTENT_TYPE_NONE. Use json_node_is_end() or the more specific
   json_node_is_object_end()/json_node_is_array_end() to check for these.
 */
int json_istream_read(struct json_istream *stream,
		      struct json_node *node_r);
/* Read the next JSON node from the stream. This is equivalent to calling
   json_istream_read() and subsequently json_istream_skip() upon success.
   Returns 1 on success, 0 if more data is needed from the input stream, or
   -1 upon error or EOF. Note that this doesn't descend into array/object nodes,
   these are skipped as a unit. */
int json_istream_read_next(struct json_istream *stream,
			   struct json_node *node_r);
/* Skip the JSON node that was (partially) parsed before. Calling
   json_istream_read() will then read the next JSON node from the input stream.
 */
void json_istream_skip(struct json_istream *stream);
/* Ignore a number of JSON nodes at the current node level. If a node was
   (partially) parsed before using json_istream_read() or
   json_istream_read_object_member() it is skipped and counted as one ignored
   node. The count may exceed the actual number of nodes left on this level
   without consequence. If count == UINT_MAX, the rest of the current node level
   is ignored no matter how many nodes are left.
 */
void json_istream_ignore(struct json_istream *stream, unsigned int count);

/* Read a JSON object member name from the stream. If an object member name
   or a complete node is already read, this function returns the name
   immediately. This function can be used to peek what the next object member
   is. Returns 1 on success, 0 if more data is needed from the input
   stream, or -1 upon error or EOF. The last member in an object has
   name_r=NULL. */
int json_istream_read_object_member(struct json_istream *stream,
				    const char **name_r);

/* Equivalent to json_istream_read_next(), but descends into array and object
   nodes. Subsequent calls to json_istream_read() will be performed on the
   child nodes of the array/object. This way, the hierarchy of the JSON document
   can be followed downwards.
 */
int json_istream_descend(struct json_istream *stream,
			 struct json_node *node_r);
/* Skips to the end of the current array/object and ascends to the parent
   JSON node. Any JSON nodes left at the end of the list will be skipped.
   The next node read will be the first one that follows the array/object
   the stream ascended from.
 */
void json_istream_ascend(struct json_istream *stream);

/* Skips to the end of the current array/object structure and thereby ascends to
   the indicated JSON node level. Any JSON nodes left at the end of the
   structure will be skipped. The next node read will be the first one that
   follows the JSON structure from which the stream ascended.
 */
void json_istream_ascend_to(struct json_istream *stream,
			    unsigned int node_level);

/* Equivalent to json_istream_descend(), but ascends implicitly after
   encountering the end of array/object. The end of each is reported once
   (json_node_is_end(node) == TRUE), after which it ascends implicitly.
   So, the subsequent call will return the next node after the array/object.
   This way, the hierarchy of the JSON document can be followed depth-first.
   Returns 1 on success, 0 if more data is needed from the input stream,
   or -1 upon error or EOF. */
int json_istream_walk(struct json_istream *stream,
		      struct json_node *node_r);

/* Equivalent to json_istream_read(), but reads strings bigger than
  `threshold' octets as an istream with `max_buffer_size'. When
  `temp_path_prefix' is not NULL, the returned stream is made seekable and
   can be read at a later time.
 */
int json_istream_read_stream(struct json_istream *stream,
			     size_t threshold, size_t max_buffer_size,
			     const char *temp_path_prefix,
			     struct json_node *node_r);
/* Equivalent to json_istream_read_next(), but reads strings bigger than
  `threshold' octets as an istream with `max_buffer_size'. When
  `temp_path_prefix' is not NULL, the returned stream is made seekable and
   can be read at a later time.
 */
int json_istream_read_next_stream(struct json_istream *stream,
				  size_t threshold, size_t max_buffer_size,
				  const char *temp_path_prefix,
				  struct json_node *node_r);

/* Equivalent to json_istream_walk(), but reads strings bigger than
  `threshold' octets as an istream with `max_buffer_size'. When
  `temp_path_prefix' is not NULL, the returned stream is made seekable and
   can be read at a later time.
 */
int json_istream_walk_stream(struct json_istream *stream,
			     size_t threshold, size_t max_buffer_size,
			     const char *temp_path_prefix,
			     struct json_node *node_r);

/* Read a full JSON tree starting at the current position. If a node was
   already read using json_istream_read(), is used as the tree root. Returns
   1 on success, 0 if more data is needed from the input stream, or -1 upon
   error or EOF. The last node in an array/object reads as *tree_r == NULL. The
   next json_istream_read*() will read the node right after the tree, so
   calling json_istream_skip() afterwards is not needed.
   */
int json_istream_read_tree(struct json_istream *stream,
			   struct json_tree **tree_r);

/* Same as json_istream_read_tree(), but read current node from stream and all
   its children into the provided existing tree node as a new child. */
int json_istream_read_into_tree_node(struct json_istream *stream,
				     struct json_tree_node *tree_node);
/* Same as json_istream_read_tree(), but read current node from stream and all
   children into the provided existing tree at the root. If there is no root,
   the read node becomes the tree root. Otherwise, it is added as a new child of
   the tree root. */
int json_istream_read_into_tree(struct json_istream *stream,
				struct json_tree *tree);

#endif
