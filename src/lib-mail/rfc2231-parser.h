#ifndef RFC2231_PARSER_H
#define RFC2231_PARSER_H

/* Parse all content parameters using rfc822_parse_content_param() and return
   them as a NULL-terminated [key, value] array. RFC 2231-style continuations
   are merged to a single key. Returns -1 if some of the input was invalid
   (but valid key/value pairs are still returned), 0 if everything looked ok. */
int rfc2231_parse(struct rfc822_parser_context *ctx,
		  const char *const **result_r);

#endif
