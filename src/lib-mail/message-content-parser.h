#ifndef __MESSAGE_CONTENT_PARSER_H
#define __MESSAGE_CONTENT_PARSER_H

/* functions can safely store data into data stack,
   ie. message_content_parse_header() is guaranteed not to call
   t_push()/t_pop() */

/* Note that count can be 0 */
typedef void (*ParseContentFunc)(const Rfc822Token *tokens, int count,
				 void *context);
/* name is always atom, value_count is always > 0 */
typedef void (*ParseContentParamFunc)(const Rfc822Token *name,
				      const Rfc822Token *value,
				      int value_count, void *context);

int message_content_parse_header(const char *value, ParseContentFunc func,
				 ParseContentParamFunc param_func,
				 void *context);

#endif
