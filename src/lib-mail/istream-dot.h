#ifndef ISTREAM_DOT_H
#define ISTREAM_DOT_H

/* Create input stream for reading SMTP DATA style message: Drop initial "."
   from lines beginning with it. Return EOF on line that contains only ".".
   If send_last_lf=FALSE, the trailing [CR]LF before "." line isn't returned. */
struct istream *i_stream_create_dot(struct istream *input, bool send_last_lf);

#endif
