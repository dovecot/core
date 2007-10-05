#ifndef ISTREAM_CRLF_H
#define ISTREAM_CRLF_H

/* Read all linefeeds as CRLF */
struct istream *i_stream_create_crlf(struct istream *input);
/* Read all linefeeds as LF */
struct istream *i_stream_create_lf(struct istream *input);

#endif
