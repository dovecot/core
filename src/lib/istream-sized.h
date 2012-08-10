#ifndef ISTREAM_SIZED_H
#define ISTREAM_SIZED_H

/* Assume that input is exactly the given size. If it's smaller, log an error
   and fail with EINVAL error. If it's larger, log an error but don't fail. */
struct istream *i_stream_create_sized(struct istream *input, uoff_t size);

#endif
