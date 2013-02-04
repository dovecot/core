#ifndef OSTREAM_METAWRAP_H
#define OSTREAM_METAWRAP_H

struct ostream *
o_stream_create_metawrap(struct ostream *output,
			 void (*write_callback)(void *), void *context);

#endif
