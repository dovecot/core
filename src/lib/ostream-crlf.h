#ifndef __OSTREAM_CRLF_H
#define __OSTREAM_CRLF_H

/* Replace all plain LFs with CRLF. */
struct ostream *o_stream_create_crlf(pool_t pool, struct ostream *output);
/* Remove all CRs. */
struct ostream *o_stream_create_lf(pool_t pool, struct ostream *output);

#endif
