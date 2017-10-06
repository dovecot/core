#ifndef ISTREAM_TRY_H
#define ISTREAM_TRY_H

/* Read from the first input stream that doesn't fail with EINVAL. If any of
   the streams fail with non-EINVAL, it's treated as a fatal failure and the
   error is immediately returned. If a stream returns 0, more data is waited
   for before continuing to the next stream. This allows the last stream to
   be a fallback stream that always succeeds.

   Once the stream is detected, all the other streams are unreferenced.
   The streams should usually be children of the same parent tee-istream. */
struct istream *istream_try_create(struct istream *const input[]);

#endif
