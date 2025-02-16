#ifndef JSON_OSTREAM_H
#define JSON_OSTREAM_H

#include "lib.h"

#include "json-types.h"
#include "json-tree.h"
#include "json-generator.h"

struct json_ostream;

/*
 * JSON ostream
 */

struct json_ostream *
json_ostream_create(struct ostream *output,
		    enum json_generator_flags gen_flags);
struct json_ostream *
json_ostream_create_str(string_t *buf,
			enum json_generator_flags gen_flags);

void json_ostream_ref(struct json_ostream *stream);
void json_ostream_unref(struct json_ostream **_stream);
void json_ostream_destroy(struct json_ostream **_stream);

void json_ostream_close(struct json_ostream *stream);
bool json_ostream_is_closed(struct json_ostream *stream) ATTR_PURE;

void json_ostream_set_format(struct json_ostream *stream,
			     const struct json_format *format);

/*
 * Position
 */

unsigned int json_ostream_get_write_node_level(struct json_ostream *stream);

/*
 * Cork
 */

void json_ostream_cork(struct json_ostream *stream);
void json_ostream_uncork(struct json_ostream *stream);
bool json_ostream_is_corked(struct json_ostream *stream);

/*
 * Flush
 */

/* Try to flush the output stream. Returns 1 if all sent, 0 if not,
   -1 if error. */
int json_ostream_flush(struct json_ostream *stream);
void json_ostream_nflush(struct json_ostream *stream);

/*
 * Error handling
 */

/* Returns error string for the previous error. */
const char *json_ostream_get_error(struct json_ostream *stream);

/* Marks the stream's error handling as completed. Flushes the stream and
   returns -1 if any of the nwrite*(), ndescend*(), etc. calls didn't write
   all data. */
int json_ostream_nfinish(struct json_ostream *stream);
/* Same as json_ostream_nfinish() but expects guaranteed success and implicitly
   destroys the stream. This will assert fail if the internal
   json_ostream_nfinish() call fails, so this is mostly only suitable for
   buffer output. */
void json_ostream_nfinish_destroy(struct json_ostream **_stream);
/* Marks the stream's error handling as completed to avoid i_panic() on
   destroy. */
void json_ostream_ignore_last_errors(struct json_ostream *stream);
/* If error handling is disabled, the i_panic() on destroy is never called.
   This function can be called immediately after the stream is created. */
void json_ostream_set_no_error_handling(struct json_ostream *stream, bool set);

/*
 * Write functions
 */

/* The 'name' argument is the name of the object member if the value is
   written in the context of an object. If not, it MUST be NULL, or the
   underlying JSON generator will trigger an assertion panic. The object member
   name can also be written earlier using json_ostream_write_object_member(),
   in which case the name argument of the subsequent value write function must
   also be NULL.

   Just like an ostream, the 'n' functions send their data with delayed error
   handling. json_ostream_nfinish() or json_ostream_ignore_last_errors()
   must be called after these functions before the stream is destroyed. If
   any of the data can't be sent due to stream's buffer getting full, all
   further 'n' function calls are ignored and json_ostream_nfinish() will
   fail.
 */

/* value */

/* object member */

int json_ostream_write_object_member(struct json_ostream *stream,
				     const char *name);
void json_ostream_nwrite_object_member(struct json_ostream *stream,
                                       const char *name);

/* Try to write the value to the output stream. Returns 1 if buffered, 0
   if not, -1 if error. */
int json_ostream_write_value(struct json_ostream *stream,
			     const char *name, enum json_type type,
			     const struct json_value *value);
void json_ostream_nwrite_value(struct json_ostream *stream,
                               const char *name, enum json_type type,
                               const struct json_value *value);

/* node */

/* Try to write the JSON node to the output stream. Returns 1 if buffered,
   0 if not, -1 if error. Value is copied to stream upon partial write if
   copy is TRUE, otherwise caller is responsible for keeping it allocated until
   the potentially buffered node is flushed by the stream. */
int json_ostream_write_node(struct json_ostream *stream,
                            const struct json_node *node, bool copy);
void json_ostream_nwrite_node(struct json_ostream *stream,
                              const struct json_node *node);

/* number */

/* Try to write the number to the output stream. Returns 1 if buffered,
   0 if not, -1 if error. */
int json_ostream_write_number(struct json_ostream *stream,
                              const char *name, intmax_t number);
void json_ostream_nwrite_number(struct json_ostream *stream,
                                const char *name, intmax_t number);
/* Try to write the number (the string) to the output stream. Returns 1
   if buffered, 0 if not, -1 if error. */
int json_ostream_write_number_raw(struct json_ostream *stream,
                                  const char *name, const char *number);
void json_ostream_nwrite_number_raw(struct json_ostream *stream,
                                    const char *name, const char *number);

/* string */

/* Try to write the data to the output stream as a string. Returns 1 if
   buffered, 0 if not, -1 if error. */
int json_ostream_write_string_data(struct json_ostream *stream,
				   const char *name,
				   const void *data, size_t size);
void json_ostream_nwrite_string_data(struct json_ostream *stream,
				     const char *name,
				     const void *data, size_t size);
/* Try to write the buffer to the output stream as a string. Returns 1 if
   buffered, 0 if not, -1 if error. */
static inline int
json_ostream_write_string_buffer(struct json_ostream *stream,
                                 const char *name, const buffer_t *buf)
{
        return json_ostream_write_string_data(stream, name,
                                               buf->data, buf->used);
}
static inline void
json_ostream_nwrite_string_buffer(struct json_ostream *stream,
                                  const char *name, const buffer_t *buf)
{
        json_ostream_nwrite_string_data(stream, name, buf->data, buf->used);
}
/* Try to write the string to the output stream. Returns 1 if buffered,
   0 if not, -1 if error. */
int json_ostream_write_string(struct json_ostream *stream,
			      const char *name, const char *str);
void json_ostream_nwrite_string(struct json_ostream *stream,
				const char *name, const char *str);
void json_ostream_nwritef_string(struct json_ostream *stream,
				 const char *name,
				 const char *format, ...) ATTR_FORMAT(3, 4);
/* Try to write the stream to the output stream as a string. Returns 1
   if buffered, 0 if not, -1 if error. */
int json_ostream_write_string_stream(struct json_ostream *stream,
				     const char *name, struct istream *input);
void json_ostream_nwrite_string_stream(struct json_ostream *stream,
                                       const char *name, struct istream *input);

/* Open a string on the stream, which means that all subsequent string
   write functions are concatenated into a single JSON string value. Note that
   the individual string values need to be valid and complete UTF-8. Any invalid
   or incomplete UTF-8 code point will yield replacement characters in the
   output, so code points cannot span sequential string values and must always
   be fully contained within a single write. */
int json_ostream_open_string(struct json_ostream *stream, const char *name);
void json_ostream_nopen_string(struct json_ostream *stream, const char *name);
/* Close the earlier opened string value on the stream. All subsequent string
   write functions will create separate string values once more. */
int json_ostream_close_string(struct json_ostream *stream);
void json_ostream_nclose_string(struct json_ostream *stream);

/* null */

/* Try to write the `null' literal to the output stream. Returns 1 if
   buffered, 0 if not, -1 if error. */
int json_ostream_write_null(struct json_ostream *stream, const char *name);
void json_ostream_nwrite_null(struct json_ostream *stream, const char *name);

/* false, true */

/* Try to write the `false' literal to the output stream. Returns 1 if
   buffered, 0 if not, -1 if error. */
int json_ostream_write_false(struct json_ostream *stream, const char *name);
void json_ostream_nwrite_false(struct json_ostream *stream, const char *name);
/* Try to write the `true' literal to the output stream. Returns 1 if
   buffered, 0 if not, -1 if error. */
int json_ostream_write_true(struct json_ostream *stream, const char *name);
void json_ostream_nwrite_true(struct json_ostream *stream, const char *name);
/* Try to write the boolean value to the output stream. Returns 1 if
   buffered, 0 if not, -1 if error. */
int json_ostream_write_bool(struct json_ostream *stream,
			    const char *name, bool value);
void json_ostream_nwrite_bool(struct json_ostream *stream,
			      const char *name, bool value);

/* object */

/* Try to descend into a JSON object by writing '{' to the output stream.
   Returns 1 if buffered, 0 if not, -1 if error. */
int json_ostream_descend_object(struct json_ostream *stream,
                                const char *name);
void json_ostream_ndescend_object(struct json_ostream *stream,
				  const char *name);

/* Try to ascend from a JSON object by writing '}' to the output stream.
   Returns 1 if buffered, 0 if not, -1 if error. */
int json_ostream_ascend_object(struct json_ostream *stream);
void json_ostream_nascend_object(struct json_ostream *stream);

/* array */

/* Try to descend into a JSON array by writing '[' to the output stream.
   Returns 1 if buffered, 0 if not, -1 if error. */
int json_ostream_descend_array(struct json_ostream *stream,
                               const char *name);
void json_ostream_ndescend_array(struct json_ostream *stream,
				 const char *name);

/* Try to ascend from a JSON array by writing ']' to the output stream.
   Returns 1 if buffered, 0 if not, -1 if error. */
int json_ostream_ascend_array(struct json_ostream *stream);
void json_ostream_nascend_array(struct json_ostream *stream);

/* JSON-text */

/* Try to write the data to the output stream directly (JSON-text, not as
   a string). Returns 1 if buffered, 0 if not, -1 if error. */
int json_ostream_write_text_data(struct json_ostream *stream,
				 const char *name,
				 const void *data, size_t size);
void json_ostream_nwrite_text_data(struct json_ostream *stream,
				   const char *name,
				   const void *data, size_t size);

/* Try to write the string to the output stream directly (JSON-text, not as
   a string). Returns 1 if buffered, 0 if not, -1 if error. */
int json_ostream_write_text(struct json_ostream *stream,
			    const char *name, const char *str);
void json_ostream_nwrite_text(struct json_ostream *stream,
			      const char *name, const char *str);

/* Try to write the stream to the output stream directly (JSON-text, not as
   a string). Returns 1 if buffered, 0 if not, -1 if error. */
int json_ostream_write_text_stream(struct json_ostream *stream,
                                   const char *name, struct istream *input);
void json_ostream_nwrite_text_stream(struct json_ostream *stream,
                                     const char *name, struct istream *input);

/* Write a JSON-text tree object to the stream. Returns 1 on success,
   0 if the stream buffer is full, or -1 upon error. Success does not mean
   that the tree is already (fully) sent. It just means that the stream was
   able to accept/buffer the tree object immediately. While the tree is still
   being sent, the stream holds a reference to it. Sending an incompletely sent
   tree continues once one of the write(), descend(), acsend(), or flush()
   functions is called. */
int json_ostream_write_tree(struct json_ostream *stream, const char *name,
                            struct json_tree *jtree);
void json_ostream_nwrite_tree(struct json_ostream *stream, const char *name,
                              const struct json_tree *jtree);

/*
 * String output stream
 */

/* Try to open an output stream for a writing a big string value. Returns 1 if
   opened, 0 if the json output stream needs to be flushed more (tried
   implicitly) before the stream can be opened, -1 if error.
 */
int json_ostream_open_string_stream(struct json_ostream *stream,
                                    const char *name,
                                    struct ostream **ostream_r);
struct ostream *
json_ostream_nopen_string_stream(struct json_ostream *stream, const char *name);

/*
 * <space>
 */

/* Try to prepare the stream for writing raw JSON text to the underlying output
   stream directly. Returns 1 if ready, 0 if the json output stream needs to be
   flushed more (tried implicitly) before the stream can be opened, -1 if error.
 */
int json_ostream_open_space(struct json_ostream *stream, const char *name);
void json_ostream_nopen_space(struct json_ostream *stream, const char *name);
/* Continue after writing raw JSON to the underlying output stream directly. */
void json_ostream_close_space(struct json_ostream *stream);

#endif
