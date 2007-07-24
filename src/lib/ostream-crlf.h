#ifndef __OSTREAM_CRLF_H
#define __OSTREAM_CRLF_H

/* Replace all plain LFs with CRLF. */
struct ostream *o_stream_create_crlf(struct ostream *output);
/* Replace all CRLF pairs with plain LFs. */
struct ostream *o_stream_create_lf(struct ostream *output);

#endif
