#ifndef ISTREAM_TIMEOUT_H
#define ISTREAM_TIMEOUT_H

/* Return ETIMEDOUT error if read() doesn't return anything for timeout_msecs.
   If timeout_msecs=0, there is no timeout. */
struct istream *
i_stream_create_timeout(struct istream *input, unsigned int timeout_msecs);

#endif
