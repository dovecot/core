#ifndef ISTREAM_JSONSTR_H
#define ISTREAM_JSONSTR_H

/* Parse input until '"' is reached. Unescape JSON \x codes. */
struct istream *i_stream_create_jsonstr(struct istream *input);

#endif
