#ifndef __MESSAGE_CONTENT_PARSER_H
#define __MESSAGE_CONTENT_PARSER_H

/* NOTE: name and value aren't \0-terminated. */
typedef void (*ParseContentFunc)(const unsigned char *value, size_t value_len,
				 void *context);
typedef void (*ParseContentParamFunc)(const unsigned char *name,
				      size_t name_len,
				      const unsigned char *value,
				      size_t value_len,
				      int value_quoted, void *context);

void message_content_parse_header(const unsigned char *data, size_t size,
				  ParseContentFunc func,
				  ParseContentParamFunc param_func,
				  void *context);

#endif
