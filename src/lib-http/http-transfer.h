#ifndef HTTP_TRANSFER_H
#define HTTP_TRANSFER_H

// FIXME: we currently lack a means to get error strings from the input stream

struct istream *
	http_transfer_chunked_istream_create(struct istream *input);
struct ostream *
	http_transfer_chunked_ostream_create(struct ostream *output);

#endif

