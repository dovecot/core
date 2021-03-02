#ifndef IOSTREAM_H
#define IOSTREAM_H

/* Returns human-readable reason for why iostream was disconnected.
   The output is either "Connection closed" for clean disconnections or
   "Connection closed: <error>" for unclean disconnections. */
const char *io_stream_get_disconnect_reason(struct istream *input,
					    struct ostream *output);

#endif
