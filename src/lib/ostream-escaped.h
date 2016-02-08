#ifndef OSTREAM_ESCAPED_H
#define OSTREAM_ESCAPED_H

/**
  * Provides escape filter for ostream
  * This is intended to be used when certain (or all)
  * characters need to be escaped before sending.

  * Such usecases are f.ex.
  *  - JSON, ostream_escaped_json_format
  *  - hex,  ostream_escaped_hex_format

  * To implement your own filter, create function
  * that matches ostream_escaped_escape_formatter_t
  * and use it as parameter
  */

typedef void (*ostream_escaped_escape_formatter_t)
	(string_t *dest, unsigned char chr);

void ostream_escaped_hex_format(string_t *dest, unsigned char chr);

struct ostream *
o_stream_create_escaped(struct ostream *output,
			ostream_escaped_escape_formatter_t formatter);

#endif
