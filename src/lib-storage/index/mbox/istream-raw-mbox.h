#ifndef __ISTREAM_RAW_MBOX_H
#define __ISTREAM_RAW_MBOX_H

/* Create a mbox stream for parsing mbox. Reading stops before From-line,
   you'll have to call istream_raw_mbox_next() to get to next message. */
struct istream *i_stream_create_raw_mbox(pool_t pool, struct istream *input);

/* Return offset to beginning of the "\nFrom"-line. */
uoff_t istream_raw_mbox_get_start_offset(struct istream *stream);
/* Return offset to beginning of the headers. */
uoff_t istream_raw_mbox_get_header_offset(struct istream *stream);

/* Return the number of bytes in the body of this message. If body_size isn't
   (uoff_t)-1, we'll use it as potentially valid body size to avoid actually
   reading through the whole message. */
uoff_t istream_raw_mbox_get_body_size(struct istream *stream, uoff_t body_size);

/* Return received time of current message, or (time_t)-1 if the timestamp is
   broken. */
time_t istream_raw_mbox_get_received_time(struct istream *stream);

/* Return sender of current message. */
const char *istream_raw_mbox_get_sender(struct istream *stream);

/* Jump to next message. If body_size isn't (uoff_t)-1, we'll use it as
   potentially valid body size. */
void istream_raw_mbox_next(struct istream *stream, uoff_t body_size);

/* Seek to message at given offset. offset must point to beginning of
   "\nFrom ", or 0 for beginning of file. */
void istream_raw_mbox_seek(struct istream *stream, uoff_t offset);

/* Flush all buffering. Call if you modify the mbox. */
void istream_raw_mbox_flush(struct istream *stream);

#endif
