#ifndef ISTREAM_CONCAT_H
#define ISTREAM_CONCAT_H

/* Concatenate input streams into a single stream. */
struct istream *i_stream_create_concat(struct istream *input[]);

#endif
