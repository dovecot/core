#ifndef __ISTREAM_RAW_MBOX_H
#define __ISTREAM_RAW_MBOX_H

/* Create a mbox stream for parsing mbox. Reading stops before From-line,
   you'll have to call istream_raw_mbox_next() to get to next message. */
struct istream *i_stream_create_raw_mbox(pool_t pool, struct istream *input);

/* Return number of bytes in this message after current offset.
   If body_size isn't (uoff_t)-1, we'll use it as potentially valid body size
   to avoid actually reading through the whole message. */
uoff_t istream_raw_mbox_get_size(struct istream *stream, uoff_t body_size);

/* Jump to next message. If body_size isn't (uoff_t)-1, we'll use it as
   potentially valid body size. */
void istream_raw_mbox_next(struct istream *stream, uoff_t body_size);

/* Flush all buffering. Call if you modify the mbox. */
void istream_raw_mbox_flush(struct istream *stream);

#endif
