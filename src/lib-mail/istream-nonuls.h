#ifndef ISTREAM_DOT_H
#define ISTREAM_DOT_H

/* Translate all NUL characters to the specified replace_chr. */
struct istream *i_stream_create_nonuls(struct istream *input, char replace_chr);

#endif
