#ifndef OSTREAM_FINAL_TRICKLE_H
#define OSTREAM_FINAL_TRICKLE_H

/* Creates a wrapper istream that delays sending the final byte until the next
   ioloop run. This can catch bugs where caller doesn't expect the final bytes
   to be delayed. */
struct ostream *o_stream_create_final_trickle(struct ostream *output);

#endif
