#ifndef ISTREAM_TRY_H
#define ISTREAM_TRY_H

/* Read from the first input stream that doesn't fail with EINVAL. If any of
   the streams fail with non-EINVAL, it's treated as a fatal failure and the
   error is immediately returned. If a stream returns 0, more data is waited
   for before continuing to the next stream. This allows the last stream to
   be a fallback stream that always succeeds.

   Once the stream is detected, all the other streams are unreferenced.
   The streams should usually be children of the same parent tee-istream.

   Detecting whether istream-tee buffer is full or not is a bit tricky.
   There's no visible difference between non-blocking istream returning 0 and
   istream-tee buffer being full. To work around this, we treat used buffer
   sizes <= min_buffer_full_size as being non-blocking istreams, while
   buffer sizes > min_buffer_full_size are assumed to be due to istream-tee
   max buffer size being reached. Practically this means that
   min_buffer_full_size must be smaller than the smallest of the istreams'
   maximum buffer sizes, but large enough that all the istreams would have
   returned EINVAL on invalid input by that position. */
struct istream *istream_try_create(struct istream *const input[],
				   size_t min_buffer_full_size);

#endif
