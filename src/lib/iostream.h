#ifndef IOSTREAM_H
#define IOSTREAM_H

/* Returns human-readable reason for why iostream was disconnected. */
const char *io_stream_get_disconnect_reason(struct istream *input,
					    struct ostream *output);

#endif
