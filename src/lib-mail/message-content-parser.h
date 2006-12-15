#ifndef __MESSAGE_CONTENT_PARSER_H
#define __MESSAGE_CONTENT_PARSER_H

/* NOTE: name and value aren't \0-terminated. */
typedef void parse_content_callback_t(const unsigned char *value,
				      size_t value_len, void *context);
typedef void parse_content_param_callback_t(const unsigned char *name,
					    size_t name_len,
					    const unsigned char *value,
					    size_t value_len,
					    bool value_quoted, void *context);

extern parse_content_callback_t *null_parse_content_callback;
extern parse_content_param_callback_t *null_parse_content_param_callback;

void message_content_parse_header(const unsigned char *data, size_t size,
				  parse_content_callback_t *callback,
				  parse_content_param_callback_t *param_cb,
				  void *context);

#endif
