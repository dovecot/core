#ifndef ISTREAM_TEE_H
#define ISTREAM_TEE_H

/* Tee can be used to create multiple child input streams which can access
   a single non-blocking input stream in a way that data isn't removed from
   memory until all child streams have consumed the input.

   If the stream's buffer gets full because some child isn't consuming the
   data, other streams get returned 0 by i_stream_read(). */
struct tee_istream *tee_i_stream_create(struct istream *input);
/* Returns TRUE if last read() operation returned 0, because it was waiting
   for another tee stream to read more of its data. */
bool tee_i_stream_child_is_waiting(struct istream *input);

struct istream *tee_i_stream_create_child(struct tee_istream *tee);

#endif
